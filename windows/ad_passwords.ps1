<#
.SYNOPSIS
Domain controller: change every domain account password, apply the domain password policy,
fix attacker-friendly account settings and review privileged groups. Run on the AD/DNS server.

.DESCRIPTION
- You type a new password for your own account; every other user gets a random 16-character
  password (or -OnePassword). Disabled accounts get one too and stay disabled.
- Scored users (-ScoredUsers - e.g. the POP3 mailboxes, which use AD usernames) are changed and
  printed separately: report them to the White Team as their guidelines require. Admin accounts
  (administrator, admin, sysadmin, root) are never used for scoring and need no report.
  -SkipScored leaves scored users unchanged (decide with the captain).
- Accounts with a servicePrincipalName (service accounts used by services on other servers) are
  SKIPPED by default - changing them breaks those services until each one is updated too. They are
  listed; change them together with the service, or use -IncludeServiceAccounts.
- Never touched here: krbtgt (see -ResetKrbtgt), computer accounts, managed service accounts,
  DefaultAccount. Guest is disabled.
- Fixes (asks first): password not required, reversible encryption, Kerberos pre-authentication
  disabled (AS-REP roasting), DES-only keys.
- Domain password policy: 14+ characters, complexity, history 5, max age 90 days, min age 0,
  no reversible encryption, lockout OFF (the red team could lock out scored users).
- Privileged groups (Domain/Enterprise/Schema Admins, Administrators, operators, DnsAdmins...):
  members you don't expect are removed after asking (-ExpectedAdmins for legit ones).
- -ResetKrbtgt: resets the krbtgt password once (invalidates forged "golden" tickets after the
  second reset; run it again later - see the output).
New passwords: C:\ProgramData\CCDC\ad-passwords-<time>.csv (Administrators only).

.EXAMPLE
.\ad_passwords.ps1 -ScoredUsers jdoe,asmith
.\ad_passwords.ps1 -ScoredUsers jdoe,asmith -ExpectedAdmins backupadmin -ResetKrbtgt
#>
param(
    [string[]]$ScoredUsers = @(),
    [switch]$SkipScored,
    [switch]$OnePassword,
    [switch]$IncludeServiceAccounts,
    [string[]]$Skip = @(),
    [string[]]$ExpectedAdmins = @(),
    [switch]$ResetKrbtgt,
    [switch]$Yes
)
$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this from an elevated (Administrator) PowerShell.' -ForegroundColor Red; exit 1 }
try { Import-Module ActiveDirectory } catch { Write-Host 'ActiveDirectory module not found - run this on the domain controller.' -ForegroundColor Red; exit 1 }

$ScoredUsers = @($ScoredUsers -split ',' | Where-Object { $_ })
$OutDir = "$env:ProgramData\CCDC"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
icacls $OutDir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Csv = Join-Path $OutDir "ad-passwords-$Stamp.csv"
$Log = Join-Path $OutDir "ad-passwords-$Stamp.log"
$Undo = Join-Path $OutDir "ad-passwords-$Stamp-undo.csv"

function Write-Log([string]$m, [string]$Color = 'Gray') { Write-Host $m -ForegroundColor $Color; Add-Content -LiteralPath $Log -Value "[$(Get-Date -Format 'HH:mm:ss')] $m" }
function Ask([string]$q) { if ($Yes) { return $true }; (Read-Host "    $q [y/N]") -match '^[Yy]' }
function Record($What, $Old, $New) { [pscustomobject]@{ Time = (Get-Date -Format s); Item = $What; Old = $Old; New = $New } | Export-Csv -LiteralPath $Undo -Append -NoTypeInformation }

function New-RandomPassword([int]$Length = 16) {
    $chars = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); $b = New-Object byte[] 1
    do {
        $p = -join (1..$Length | ForEach-Object {
            do { $rng.GetBytes($b) } while ($b[0] -ge (256 - (256 % $chars.Length)))
            $chars[$b[0] % $chars.Length] })
    } until ($p -cmatch '[A-Z]' -and $p -cmatch '[a-z]' -and $p -match '[0-9]')
    $p
}
function Read-NewPassword([string]$Prompt) {
    while ($true) {
        $a = Read-Host -Prompt $Prompt -AsSecureString; $b = Read-Host -Prompt 'Again' -AsSecureString
        $pa = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($a))
        $pb = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($b))
        $classes = @('[A-Z]', '[a-z]', '[0-9]', '[^A-Za-z0-9]' | Where-Object { $pa -cmatch $_ }).Count
        if ($pa -ne $pb) { Write-Host 'Did not match.' -ForegroundColor Yellow }
        elseif ($pa.Length -lt 14 -or $classes -lt 3) { Write-Host 'Use 14+ characters with at least 3 of: upper, lower, digit, symbol.' -ForegroundColor Yellow }
        else { return $pa }
    }
}

$domain = Get-ADDomain
$me = $env:USERNAME
Write-Log "Domain $($domain.DNSRoot) - DC $env:COMPUTERNAME - $(Get-Date)" 'Cyan'

# ------------------------------------------------------------------ 1. passwords
$props = 'ServicePrincipalName', 'PasswordNotRequired', 'AllowReversiblePasswordEncryption', 'DoesNotRequirePreAuth',
         'UseDESKeyOnly', 'PasswordNeverExpires', 'whenCreated', 'PasswordLastSet'
$users = @(Get-ADUser -Filter * -Properties $props)
$one = $null; $mine = $null
if ($OnePassword) { $one = Read-NewPassword 'New password for ALL domain accounts' }
else { $mine = Read-NewPassword "New password for $me (you)" }

'user,password,scored,enabled,note' | Set-Content -LiteralPath $Csv
$skippedSvc = @(); $failed = @(); $changed = 0
foreach ($u in $users) {
    $sid = $u.SID.Value; $name = $u.SamAccountName
    if ($name -eq 'krbtgt' -or $sid -like '*-503') { continue }
    if ($sid -like '*-501') {   # Guest
        if ($u.Enabled) { Disable-ADAccount -Identity $u; Record "Guest" 'enabled' 'disabled'; Write-Log 'Disabled Guest' }
        continue
    }
    if ($Skip -contains $name) { Write-Log "Skipped $name (-Skip)"; continue }
    $scored = $ScoredUsers -contains $name
    if ($scored -and $SkipScored) { Write-Log "Skipped scored user $name (-SkipScored)" 'Yellow'; continue }
    if ($u.ServicePrincipalName -and -not $IncludeServiceAccounts -and $name -ne $me) { $skippedSvc += $u; continue }
    $pw = if ($one) { $one } elseif ($name -eq $me) { $mine } else { New-RandomPassword }
    try {
        Set-ADAccountPassword -Identity $u -Reset -NewPassword (ConvertTo-SecureString $pw -AsPlainText -Force)
        "$name,$pw,$(if ($scored) { 'yes' } else { 'no' }),$($u.Enabled)," | Add-Content -LiteralPath $Csv
        $changed++
    } catch { $failed += $name; Write-Log "FAILED $name : $($_.Exception.Message)" 'Red' }
}
icacls $Csv /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' | Out-Null
Write-Log "Changed $changed domain account password(s). New passwords: $Csv (Administrators only)" 'Green'
if ($failed) { Write-Log "Could not change: $($failed -join ', ')" 'Red' }
foreach ($s in $ScoredUsers) { if (-not ($users.SamAccountName -contains $s)) { Write-Log "Scored user '$s' not found in AD - check the name" 'Yellow' } }
$rows = @(Import-Csv -LiteralPath $Csv | Where-Object scored -eq 'yes')
if ($rows) {
    Write-Host "`nSubmit these password changes for scored users NOW (Quotient > PCR tab, paste as-is):" -ForegroundColor Cyan
    $rows | ForEach-Object { Write-Host "$($_.user),$($_.password)" }
}
if ($skippedSvc) {
    Write-Host "`nService accounts NOT changed (they have SPNs - the services using them would break):" -ForegroundColor Yellow
    $skippedSvc | ForEach-Object { Write-Host ("    {0,-22} last set {1}  SPN: {2}" -f $_.SamAccountName, $_.PasswordLastSet, ($_.ServicePrincipalName -join ', ')) }
    Write-Host '    These are Kerberoastable: change each one together with the service that uses it'
    Write-Host '    (Set-ADAccountPassword <name> -Reset, then update the service / app pool / task on its server).'
}

# ------------------------------------------------------------------ 2. risky account settings
Write-Host "`nAccount settings attackers abuse:" -ForegroundColor Cyan
$risky = @($users | Where-Object { $_.SamAccountName -ne 'krbtgt' -and ($_.PasswordNotRequired -or $_.AllowReversiblePasswordEncryption -or $_.DoesNotRequirePreAuth -or $_.UseDESKeyOnly) })
if (-not $risky) { Write-Log '  none found' 'Green' }
foreach ($u in $risky) {
    $what = @(); if ($u.PasswordNotRequired) { $what += 'password not required' }; if ($u.AllowReversiblePasswordEncryption) { $what += 'reversible encryption' }
    if ($u.DoesNotRequirePreAuth) { $what += 'no Kerberos pre-auth (AS-REP roastable)' }; if ($u.UseDESKeyOnly) { $what += 'DES only' }
    Write-Log "  $($u.SamAccountName): $($what -join ', ')" 'Yellow'
    if (Ask "Fix $($u.SamAccountName)?") {
        Set-ADAccountControl -Identity $u -PasswordNotRequired $false -AllowReversiblePasswordEncryption $false -DoesNotRequirePreAuth $false -UseDESKeyOnly $false
        Record "account flags $($u.SamAccountName)" ($what -join ';') 'fixed'
    }
}
$never = @($users | Where-Object { $_.PasswordNeverExpires -and $_.Enabled }).Count
if ($never) { Write-Log "  $never enabled account(s) have 'password never expires' (fine for scored/service accounts; review the rest)" }

# ------------------------------------------------------------------ 3. domain password policy
Write-Host "`nDomain password policy:" -ForegroundColor Cyan
try {
    $old = Get-ADDefaultDomainPasswordPolicy
    Record 'DefaultDomainPasswordPolicy' "min=$($old.MinPasswordLength) complex=$($old.ComplexityEnabled) hist=$($old.PasswordHistoryCount) max=$($old.MaxPasswordAge) lockout=$($old.LockoutThreshold)" 'min=14 complex hist=5 max=90d lockout=0'
    Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -MinPasswordLength 14 -ComplexityEnabled $true -PasswordHistoryCount 5 `
        -MaxPasswordAge (New-TimeSpan -Days 90) -MinPasswordAge (New-TimeSpan -Days 0) -ReversibleEncryptionEnabled $false -LockoutThreshold 0
    Write-Log '  Set: 14+ chars, complexity, history 5, max age 90 days, min age 0, no reversible encryption, no lockout' 'Green'
} catch { Write-Log "  Policy update failed: $($_.Exception.Message)" 'Red' }
$psos = @(Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction SilentlyContinue)
foreach ($p in $psos) { Write-Log "  Fine-grained policy '$($p.Name)' (applies to $(($p.AppliesTo | ForEach-Object { ($_ -split ',')[0] -replace 'CN=' }) -join ', ')): min $($p.MinPasswordLength), lockout $($p.LockoutThreshold) - check it isn't weaker" 'Yellow' }

# ------------------------------------------------------------------ 4. privileged groups
Write-Host "`nPrivileged groups:" -ForegroundColor Cyan
$groups = 'Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators', 'Account Operators', 'Backup Operators',
          'Server Operators', 'Print Operators', 'DnsAdmins', 'Group Policy Creator Owners'
$defaultNested = @{ 'Administrators' = @('Domain Admins', 'Enterprise Admins') }
foreach ($g in $groups) {
    $members = @(Get-ADGroupMember -Identity $g -ErrorAction SilentlyContinue)
    if (-not $members) { continue }
    Write-Host "  $g : $(($members | ForEach-Object SamAccountName) -join ', ')"
    foreach ($m in $members) {
        $ok = $m.SID.Value -like '*-500' -or $m.SamAccountName -eq $me -or $ExpectedAdmins -contains $m.SamAccountName -or
              ($defaultNested[$g] -contains $m.Name)
        if ($ok) { continue }
        Write-Log "    unexpected member of ${g}: $($m.SamAccountName) ($($m.objectClass))" 'Yellow'
        if (Ask "Remove $($m.SamAccountName) from $g?") {
            Remove-ADGroupMember -Identity $g -Members $m -Confirm:$false
            Record "group $g" "member $($m.SamAccountName)" 'removed'
            Write-Log "    removed (undo: Add-ADGroupMember '$g' $($m.SamAccountName))"
        }
    }
}

# ------------------------------------------------------------------ 5. newest accounts and krbtgt
Write-Host "`nNewest accounts (red team often adds users - check these):" -ForegroundColor Cyan
$users | Sort-Object whenCreated -Descending | Select-Object -First 8 SamAccountName, Enabled, whenCreated | Format-Table -AutoSize | Out-String | Write-Host

$krb = Get-ADUser krbtgt -Properties PasswordLastSet
Write-Host "krbtgt password last set: $($krb.PasswordLastSet)"
if ($ResetKrbtgt) {
    if (Ask 'Reset the krbtgt password now? (existing Kerberos tickets stay valid until the SECOND reset)') {
        Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString (New-RandomPassword 32) -AsPlainText -Force)
        Record 'krbtgt' $krb.PasswordLastSet 'reset'
        Write-Log 'krbtgt reset once. Run -ResetKrbtgt again later (e.g. 1-2 hours, at a quiet moment): the second reset' 'Green'
        Write-Log 'invalidates all old tickets, including forged golden tickets; users and services re-authenticate automatically.' 'Green'
    }
} else { Write-Host '(add -ResetKrbtgt to reset it - do it twice, some time apart, if the domain may be compromised)' }

Write-Host "`nLog: $Log   Undo record: $Undo"
Write-Host 'Also change: local Administrator on member servers (passwords.ps1 there), DSRM password (ntdsutil "set dsrm password").'
