<#
.SYNOPSIS
Audit Active Directory for signs of attack and for privilege-escalation paths. Run on the DC.

.DESCRIPTION
Report-only unless -Fix (asks before each change; -Yes to skip asking). Checks:
  Accounts    new / recently changed users and computers, privileged group members (nested) and
              when each was added, adminCount leftovers, SID history, passwords in descriptions,
              password-not-required / reversible / DES / no pre-auth (AS-REP roastable) accounts,
              Kerberoastable accounts (SPNs) - especially privileged ones, Guest, krbtgt age
  Delegation  unconstrained delegation on non-DCs, constrained delegation, resource-based
              constrained delegation (RBCD), machine account quota
  Permissions DCSync (replication) rights, dangerous rights on the domain root, AdminSDHolder and
              Domain Admins, DnsAdmins + the DNS ServerLevelPluginDll backdoor
  Group Policy recently changed GPOs, GPO scheduled tasks / scripts, GPP passwords (cpassword) in SYSVOL
  Other       trusts, domain controllers, Pre-Windows 2000 Compatible Access, password policy,
              recent account / group / password-reset events
-Fix offers: machine account quota -> 0, remove the DNS plugin DLL setting, remove DCSync rights from
unexpected accounts, clear RBCD, clear SID history, disable Guest. Old values go to the undo CSV.
Report: C:\ProgramData\CCDC\ad-audit-<time>.log. Critical findings go to the Application log
(source CCDC-ADAudit) for Splunk. Exit 2 = critical, 1 = warnings, 0 = clean.

.EXAMPLE
.\ad_audit.ps1
.\ad_audit.ps1 -Hours 4 -ExpectedAdmins backupadmin -Fix
#>
param(
    [int]$Hours = 24,                     # "recent" = created / changed in the last N hours
    [string[]]$ExpectedAdmins = @(),
    [switch]$Fix,
    [switch]$Yes
)
$ErrorActionPreference = 'Continue'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this from an elevated (Administrator) PowerShell.' -ForegroundColor Red; exit 1 }
try { Import-Module ActiveDirectory -ErrorAction Stop } catch { Write-Host 'ActiveDirectory module not found - run this on the domain controller.' -ForegroundColor Red; exit 1 }

$ExpectedAdmins = @($ExpectedAdmins -split ',' | Where-Object { $_ })
$OutDir = "$env:ProgramData\CCDC"; New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Log = Join-Path $OutDir "ad-audit-$Stamp.log"
$Undo = Join-Path $OutDir "ad-audit-$Stamp-undo.csv"
Start-Transcript -LiteralPath $Log | Out-Null

$script:Crit = 0; $script:Warn = 0
function Crit([string]$m) { $script:Crit++; Write-Host "[CRITICAL] $m" -ForegroundColor Red
    try { if (-not [Diagnostics.EventLog]::SourceExists('CCDC-ADAudit')) { New-EventLog -LogName Application -Source CCDC-ADAudit }
          Write-EventLog -LogName Application -Source CCDC-ADAudit -EventId 4700 -EntryType Warning -Message $m } catch { } }
function Warn([string]$m) { $script:Warn++; Write-Host "[WARN]     $m" -ForegroundColor Yellow }
function Ok([string]$m)   { Write-Host "[OK]       $m" -ForegroundColor Green }
function Info([string]$m) { Write-Host "           $m" }
function H1([string]$t)   { Write-Host "`n==================== $t ====================" -ForegroundColor Cyan }
function Ask([string]$q)  { if (-not $Fix) { return $false }; if ($Yes) { return $true }; (Read-Host "           $q [y/N]") -match '^[Yy]' }
function Record($What, $Old, $New) { [pscustomobject]@{ Time = (Get-Date -Format s); Item = $What; Old = $Old; New = $New } | Export-Csv -LiteralPath $Undo -Append -NoTypeInformation }

$domain = Get-ADDomain
$dn = $domain.DistinguishedName
$since = (Get-Date).AddHours(-$Hours)
$dcNames = @(Get-ADDomainController -Filter * | ForEach-Object { $_.Name })
Write-Host "AD audit of $($domain.DNSRoot) on $env:COMPUTERNAME - $(Get-Date) - 'recent' = last $Hours h"

# Resolve an ACE identity to a SID string (NTAccount -> SID); $null if it can't be resolved
function Get-Sid($identity) { try { $identity.Translate([Security.Principal.SecurityIdentifier]).Value } catch { $null } }
# Built-in principals that legitimately hold powerful rights
$domainSid = $domain.DomainSID.Value
$trustedSids = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-9', 'S-1-3-0', 'S-1-5-10',
                 "$domainSid-512", "$domainSid-516", "$domainSid-498", "$domainSid-519", "$domainSid-518", "$domainSid-521", "$domainSid-526", "$domainSid-527")

# ------------------------------------------------------------------ accounts
H1 'ACCOUNTS'
$uprops = 'whenCreated', 'whenChanged', 'adminCount', 'SIDHistory', 'Description', 'ServicePrincipalName', 'PasswordNotRequired',
          'AllowReversiblePasswordEncryption', 'DoesNotRequirePreAuth', 'UseDESKeyOnly', 'PasswordLastSet', 'MemberOf',
          'TrustedForDelegation', 'msDS-AllowedToDelegateTo', 'PasswordNeverExpires'
$users = @(Get-ADUser -Filter * -Properties $uprops)
$computers = @(Get-ADComputer -Filter * -Properties whenCreated, TrustedForDelegation, 'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity', OperatingSystem, PrimaryGroupID)

$newU = @($users | Where-Object { $_.whenCreated -gt $since })
if ($newU) { Warn "Users created in the last $Hours h: $(($newU | ForEach-Object { "$($_.SamAccountName) ($($_.whenCreated))" }) -join ', ')" } else { Ok "No users created in the last $Hours h" }
$newC = @($computers | Where-Object { $_.whenCreated -gt $since })
if ($newC) { Warn "Computer accounts created in the last $Hours h (often used for RBCD attacks): $(($newC | ForEach-Object Name) -join ', ')" }

# Privileged groups (nested membership) and when each direct member was added
$privGroups = 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators',
              'Server Operators', 'Print Operators', 'DnsAdmins', 'Group Policy Creator Owners', 'Key Admins', 'Enterprise Key Admins'
$privMembers = @{}
foreach ($g in $privGroups) {
    $grp = Get-ADGroup -Filter "Name -eq '$g'" -ErrorAction SilentlyContinue; if (-not $grp) { continue }
    $members = @(Get-ADGroupMember $grp -Recursive -ErrorAction SilentlyContinue)
    foreach ($m in $members) { $privMembers[$m.SamAccountName] = $true }
    if (-not $members) { continue }
    Info "$g : $(($members | ForEach-Object SamAccountName) -join ', ')"
    try {
        Get-ADReplicationAttributeMetadata -Object $grp.DistinguishedName -Server $env:COMPUTERNAME -ShowAllLinkedValues -Attribute member -ErrorAction Stop |
            Where-Object { $_.FirstOriginatingCreateTime -gt $since -and $_.IsLinkValue } | ForEach-Object {
                Crit "$($_.AttributeValue -replace ',.*' -replace 'CN=') was added to $g at $($_.FirstOriginatingCreateTime)" }
    } catch { }
    foreach ($m in $members) {
        if ($m.objectClass -ne 'user') { continue }
        $known = ($m.SID.Value -like '*-500') -or ($ExpectedAdmins -contains $m.SamAccountName) -or ($m.SamAccountName -eq $env:USERNAME)
        if (-not $known -and $g -in 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators') { Warn "$($m.SamAccountName) is (via nesting) in $g - expected? (-ExpectedAdmins)" }
    }
}
# adminCount=1 but no longer privileged: leftover rights / former admins worth checking
$stale = @($users | Where-Object { $_.adminCount -eq 1 -and -not $privMembers.ContainsKey($_.SamAccountName) -and $_.SamAccountName -ne 'krbtgt' })
if ($stale) { Warn "adminCount=1 but not in a privileged group now (was an admin, or still holds protected ACLs): $(($stale | ForEach-Object SamAccountName) -join ', ')" }

# SID history: an extra SID (e.g. Domain Admins) hidden on a normal account
foreach ($u in $users | Where-Object { $_.SIDHistory.Count -gt 0 }) {
    Crit "$($u.SamAccountName) has SID history: $($u.SIDHistory -join ', ') - grants the rights of those SIDs"
    if (Ask "Clear SID history of $($u.SamAccountName)?") {
        Record "SIDHistory $($u.SamAccountName)" ($u.SIDHistory -join ';') 'cleared'
        foreach ($s in $u.SIDHistory) { Set-ADUser $u -Remove @{ SIDHistory = $s.Value } }
    }
}
# Passwords left in descriptions
foreach ($u in $users | Where-Object { $_.Description -match '(?i)pass|pwd|pw\s*[:=]|cred' }) { Crit "$($u.SamAccountName) description may contain a password: '$($u.Description)'" }
# Attacker-friendly flags (ad_passwords.ps1 can fix these)
foreach ($u in $users | Where-Object { $_.SamAccountName -ne 'krbtgt' }) {
    if ($u.DoesNotRequirePreAuth) { Crit "$($u.SamAccountName): Kerberos pre-authentication disabled (AS-REP roastable)" }
    if ($u.PasswordNotRequired) { Warn "$($u.SamAccountName): password not required" }
    if ($u.AllowReversiblePasswordEncryption) { Warn "$($u.SamAccountName): reversible password encryption" }
    if ($u.UseDESKeyOnly) { Warn "$($u.SamAccountName): DES-only Kerberos keys" }
}
# Kerberoastable
foreach ($u in $users | Where-Object { $_.ServicePrincipalName -and $_.SamAccountName -ne 'krbtgt' }) {
    $age = if ($u.PasswordLastSet) { [int]((Get-Date) - $u.PasswordLastSet).TotalDays } else { 'never' }
    $msg = "$($u.SamAccountName) has SPNs (Kerberoastable; password age $age days): $($u.ServicePrincipalName -join ', ')"
    if ($privMembers.ContainsKey($u.SamAccountName)) { Crit "PRIVILEGED $msg" } else { Warn $msg }
}
$guest = $users | Where-Object { $_.SID.Value -like '*-501' }
if ($guest.Enabled) { Crit 'Guest account is enabled'; if (Ask 'Disable Guest?') { Disable-ADAccount $guest; Record 'Guest' 'enabled' 'disabled' } }
$krb = $users | Where-Object SamAccountName -eq 'krbtgt'
if ($krb.PasswordLastSet -lt (Get-Date).AddDays(-180)) { Warn "krbtgt password last set $($krb.PasswordLastSet) - reset it twice (ad_passwords.ps1 -ResetKrbtgt)" } else { Info "krbtgt password last set $($krb.PasswordLastSet)" }

# ------------------------------------------------------------------ delegation
H1 'DELEGATION'
foreach ($c in $computers | Where-Object { $_.TrustedForDelegation -and $dcNames -notcontains $_.Name }) {
    Crit "Computer $($c.Name) has UNCONSTRAINED delegation - any admin who logs on there leaves a reusable ticket"
}
foreach ($u in $users | Where-Object TrustedForDelegation) { Crit "User $($u.SamAccountName) has UNCONSTRAINED delegation" }
foreach ($o in @($users) + @($computers) | Where-Object { $_.'msDS-AllowedToDelegateTo' }) {
    Warn "$($o.Name) has constrained delegation to: $($o.'msDS-AllowedToDelegateTo' -join ', ')"
}
foreach ($c in $computers | Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' }) {
    $sd = $c.'msDS-AllowedToActOnBehalfOfOtherIdentity'
    $who = try { ($sd.Access | ForEach-Object { $_.IdentityReference.Value }) -join ', ' } catch { 'unknown' }
    Crit "Resource-based constrained delegation (RBCD) set on $($c.Name) - these can impersonate any user to it: $who"
    if (Ask "Clear RBCD on $($c.Name)?") { Set-ADComputer $c -Clear 'msDS-AllowedToActOnBehalfOfOtherIdentity'; Record "RBCD $($c.Name)" $who 'cleared' }
}
$maq = (Get-ADObject $dn -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
if ($maq -gt 0) {
    Warn "Machine account quota is $maq - any user can add computers to the domain (used in RBCD / relay attacks)"
    if (Ask 'Set the machine account quota to 0?') { Set-ADDomain -Identity $domain -Replace @{ 'ms-DS-MachineAccountQuota' = 0 }; Record 'ms-DS-MachineAccountQuota' $maq 0 }
} else { Ok 'Machine account quota is 0' }

# ------------------------------------------------------------------ permissions
H1 'PERMISSIONS'
$replGuids = @('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c')
$rootAcl = Get-Acl "AD:$dn"
$dcsync = @($rootAcl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and ($replGuids -contains $_.ObjectType.Guid -or $_.ActiveDirectoryRights -match 'GenericAll') })
$hit = $false
foreach ($ace in $dcsync) {
    $sid = Get-Sid $ace.IdentityReference
    if ($sid -and ($trustedSids -contains $sid)) { continue }
    $hit = $true
    Crit "DCSync / full-control right on the domain for $($ace.IdentityReference) ($($ace.ActiveDirectoryRights) $($ace.ObjectType)) - can dump every password hash"
    if (Ask "Remove this right from $($ace.IdentityReference)?") {
        Record "domain root ACE" "$($ace.IdentityReference) $($ace.ActiveDirectoryRights) $($ace.ObjectType)" 'removed'
        [void]$rootAcl.RemoveAccessRule($ace); Set-Acl "AD:$dn" $rootAcl
    }
}
if (-not $hit) { Ok 'Only domain controllers / admin groups hold replication (DCSync) rights' }

$dangerous = 'GenericAll|GenericWrite|WriteDacl|WriteOwner|WriteProperty'
foreach ($target in @("CN=AdminSDHolder,CN=System,$dn", (Get-ADGroup 'Domain Admins').DistinguishedName, $dn)) {
    foreach ($ace in (Get-Acl "AD:$target").Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.ActiveDirectoryRights -match $dangerous }) {
        $sid = Get-Sid $ace.IdentityReference
        # PowerShell -and / -or have equal precedence: keep the parentheses
        if (-not $sid -or ($trustedSids -contains $sid)) { continue }
        if (($sid -eq 'S-1-5-11') -and ($ace.ActiveDirectoryRights -notmatch 'GenericAll|WriteDacl|WriteOwner')) { continue }
        if ($ace.IdentityReference -match 'SELF$|CREATOR OWNER|Cert Publishers|Terminal Server License Servers|Key Admins|Exchange') { continue }
        Crit "$($ace.IdentityReference) has $($ace.ActiveDirectoryRights) on $(($target -split ',')[0]) - path to Domain Admin"
    }
}

$dnsAdmins = @(Get-ADGroupMember DnsAdmins -ErrorAction SilentlyContinue)
if ($dnsAdmins) { Warn "DnsAdmins members (can load a DLL into the DNS service = SYSTEM on the DC): $(($dnsAdmins | ForEach-Object SamAccountName) -join ', ')" }
$plugin = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters' -Name ServerLevelPluginDll -ErrorAction SilentlyContinue).ServerLevelPluginDll
if ($plugin) {
    Crit "DNS ServerLevelPluginDll is set to '$plugin' - a DLL loaded into the DNS service (DnsAdmins backdoor)"
    if (Ask 'Remove the ServerLevelPluginDll setting? (restart the DNS service afterwards)') {
        Record 'ServerLevelPluginDll' $plugin 'removed'
        Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters' -Name ServerLevelPluginDll
    }
} else { Ok 'No DNS plugin DLL configured' }

$pre2k = @(Get-ADGroupMember 'Pre-Windows 2000 Compatible Access' -ErrorAction SilentlyContinue | ForEach-Object Name)
if ($pre2k | Where-Object { $_ -match 'Anonymous|Everyone' }) { Warn "Pre-Windows 2000 Compatible Access contains $($pre2k -join ', ') - anonymous users can read AD" }

# ------------------------------------------------------------------ group policy
H1 'GROUP POLICY'
if (Get-Command Get-GPO -ErrorAction SilentlyContinue) {
    foreach ($g in Get-GPO -All | Where-Object { $_.ModificationTime -gt $since }) { Warn "GPO '$($g.DisplayName)' changed $($g.ModificationTime) - expected?" }
}
$sysvol = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies"
if (-not (Test-Path $sysvol)) { $sysvol = "$env:SystemRoot\SYSVOL\domain\Policies" }
if (Test-Path $sysvol) {
    foreach ($f in Get-ChildItem $sysvol -Recurse -Include *.xml -ErrorAction SilentlyContinue | Select-String -Pattern 'cpassword="[^"]+' -List) {
        Crit "Group Policy Preferences password (cpassword - decryptable by anyone) in $($f.Path)"
    }
    foreach ($f in Get-ChildItem $sysvol -Recurse -Include ScheduledTasks.xml, scripts.ini, psscripts.ini -ErrorAction SilentlyContinue) {
        $msg = "GPO runs tasks/scripts: $($f.FullName) (changed $($f.LastWriteTime))"
        if ($f.LastWriteTime -gt $since) { Crit "$msg - RECENT" } else { Info $msg }
    }
}

# ------------------------------------------------------------------ other
H1 'TRUSTS, DCs, POLICY'
$trusts = @(Get-ADTrust -Filter * -ErrorAction SilentlyContinue)
if ($trusts) { $trusts | ForEach-Object { Warn "Trust: $($_.Name) direction $($_.Direction) - expected?" } } else { Ok 'No domain trusts' }
Info "Domain controllers: $($dcNames -join ', ')"
$rogue = @($computers | Where-Object { $_.PrimaryGroupID -eq 516 -and $dcNames -notcontains $_.Name })
foreach ($r in $rogue) { Crit "$($r.Name) has the Domain Controllers primary group but is not a DC" }
$pol = Get-ADDefaultDomainPasswordPolicy
$msg = "Password policy: min $($pol.MinPasswordLength), complexity $($pol.ComplexityEnabled), history $($pol.PasswordHistoryCount), max age $($pol.MaxPasswordAge.Days) d, reversible $($pol.ReversibleEncryptionEnabled)"
if ($pol.MinPasswordLength -lt 14 -or -not $pol.ComplexityEnabled -or $pol.ReversibleEncryptionEnabled) { Warn "$msg - ad_passwords.ps1 sets the policy" } else { Ok $msg }

H1 "RECENT SECURITY EVENTS (last $Hours h)"
$ids = @{ 4720 = 'user created'; 4722 = 'user enabled'; 4724 = 'password reset by admin'; 4728 = 'added to global group'; 4732 = 'added to local group';
          4756 = 'added to universal group'; 4738 = 'user changed'; 5136 = 'directory object modified'; 4662 = 'directory object accessed'; 1102 = 'security log cleared' }
try {
    $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = [int[]]$ids.Keys; StartTime = $since } -ErrorAction Stop)
    $ev | Group-Object Id | Sort-Object Count -Descending | ForEach-Object { Info ("{0,5} x {1} ({2})" -f $_.Count, $_.Name, $ids[[int]$_.Name]) }
    if ($ev | Where-Object Id -eq 1102) { Crit 'The Security log was cleared' }
    $repl = @($ev | Where-Object { $_.Id -eq 4662 -and ($_.Message -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2|1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') })
    foreach ($e in $repl) {
        $acct = $e.Properties[1].Value
        if ($acct -notmatch '\$$') { Crit "Replication (DCSync) requested by $acct at $($e.TimeCreated) - not a DC account" }
    }
    Info 'Details: Get-WinEvent -FilterHashtable @{LogName=''Security'';Id=4720,4728,4732,4756,4724} -MaxEvents 30 | Format-List TimeCreated, Message'
} catch { Info 'No matching events (or auditing for these categories is off - see checklists/ad-dns/HARDENING.md)' }

H1 'SUMMARY'
Write-Host "Critical: $script:Crit   Warnings: $script:Warn   Log: $Log$(if (Test-Path $Undo) { "   Undo record: $Undo" })"
if ($script:Crit -and -not $Fix) { Write-Host 'Fix the fixable ones: .\ad_audit.ps1 -Fix (asks each time). Account passwords/flags: .\ad_passwords.ps1' }
Stop-Transcript | Out-Null
if ($script:Crit) { exit 2 } elseif ($script:Warn) { exit 1 } else { exit 0 }
