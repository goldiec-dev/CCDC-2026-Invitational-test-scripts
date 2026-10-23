<#
.SYNOPSIS
Harden the scored Windows services without breaking their checks.

.DESCRIPTION
By -Role (deploy.ps1 passes it):
  dc     DNS: no zone transfers to anyone, secure dynamic updates, cache locking, response rate
         limiting, audit log; optional: recursion only for the LAN (asks).
         WinRM (AD-WinRM is scored): service on, HTTPS listener on 5986 added (HTTP 5985 kept);
         Basic auth / unencrypted traffic / CredSSP turned off only if you say so (the scorer may use them).
  mssql  SMB: no anonymous/null sessions, share-access auditing, backup + hash list of every share
         (the scored "SOPs"), optional read-only for Everyone-style write access (asks).
         RDP: NLA, TLS, high encryption; RDP turned on if it was off.
         SQL Server: xp_cmdshell / OLE Automation / ad hoc queries / CLR off (asks each), login
         auditing, blank or name-as-password SQL logins reported; nothing that needs a SQL restart now.
  ftp    (older topologies) IIS FTP: no anonymous logins, FTPS allowed (not required)
  workstation  RDP settings as above if RDP is on

Each section tests its service before and after; a failed test undoes that section.
Changes and previous values: C:\ProgramData\CCDC\secure-<time>-undo.csv; log secure-<time>.log.

.EXAMPLE
.\secure.ps1 -Role mssql
.\secure.ps1 -Role dc -Inside 172.20.240.0/24
#>
param(
    [ValidateSet('workstation', 'web', 'dc', 'ftp', 'mssql')]
    [string]$Role = 'workstation',
    [string[]]$Inside = @('172.20.240.0/24'),
    [switch]$Yes
)

$ErrorActionPreference = 'Continue'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this from an elevated (Administrator) PowerShell.' -ForegroundColor Red; exit 1 }

$OutDir = "$env:ProgramData\CCDC"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Log = Join-Path $OutDir "secure-$Stamp.log"
$UndoCsv = Join-Path $OutDir "secure-$Stamp-undo.csv"
Start-Transcript -LiteralPath $Log | Out-Null

$script:Failed = 0
function Ok([string]$m)   { Write-Host "[OK]     $m" -ForegroundColor Green }
function Warn([string]$m) { Write-Host "[WARN]   $m" -ForegroundColor Yellow }
function Bad([string]$m)  { $script:Failed++; Write-Host "[FAIL]   $m" -ForegroundColor Red }
function Info([string]$m) { Write-Host "         $m" }
function H1([string]$t)   { Write-Host "`n==================== $t ====================" -ForegroundColor Cyan }
function Ask([string]$q)  { if ($Yes) { return $true }; (Read-Host "    $q [y/N]") -match '^[Yy]' }
function Record($What, $Old, $New) {
    [pscustomobject]@{ Time = (Get-Date -Format s); Item = $What; Old = "$Old"; New = "$New" } |
        Export-Csv -LiteralPath $UndoCsv -Append -NoTypeInformation
}

# Undo list for the current section: scriptblocks run in reverse order if its test fails
$script:Undo = New-Object System.Collections.Generic.List[scriptblock]
function Begin-Section([string]$Title) { H1 $Title; $script:Undo.Clear() }
function Undo-Section {
    for ($i = $script:Undo.Count - 1; $i -ge 0; $i--) { try { & $script:Undo[$i] } catch { Warn "undo step failed: $($_.Exception.Message)" } }
    Warn 'section undone - previous settings restored'
}
function Set-Reg([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord') {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    $old = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    if ("$old" -eq "$Value") { return }
    Record "$Path\$Name" $old $Value
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
    $p = $Path; $n = $Name; $o = $old; $t = $Type
    $script:Undo.Add({ if ($null -eq $o) { Remove-ItemProperty -Path $p -Name $n -ErrorAction SilentlyContinue }
                       else { New-ItemProperty -Path $p -Name $n -Value $o -PropertyType $t -Force | Out-Null } }.GetNewClosure())
}
function Port-Open([int]$Port) {
    $c = New-Object Net.Sockets.TcpClient
    try { $c.ConnectAsync('127.0.0.1', $Port).Wait(3000) -and $c.Connected } catch { $false } finally { $c.Close() }
}

Write-Host "secure.ps1 on $env:COMPUTERNAME - role $Role - $(Get-Date)"

# ============================================================================ DNS (dc)
function Secure-Dns {
    Begin-Section 'DNS'
    if (-not (Get-Command Get-DnsServerZone -ErrorAction SilentlyContinue)) { Info 'no DNS server here - skipped'; return }
    $zones = @(Get-DnsServerZone | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' -and $_.ZoneName -ne 'TrustAnchors' })
    $answers = { param($z) [bool](Resolve-DnsName -Name $z -Type SOA -Server 127.0.0.1 -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue) }
    $before = @{}; foreach ($z in $zones) { $before[$z.ZoneName] = & $answers $z.ZoneName }
    Info "zones: $(($zones | ForEach-Object { "$($_.ZoneName)$(if (-not $before[$_.ZoneName]) { ' (no answer now!)' })" }) -join ', ')"

    foreach ($z in $zones) {
        $name = $z.ZoneName
        if ($z.SecureSecondaries -eq 'TransferAnyServer') {
            Record "zone $name SecureSecondaries" $z.SecureSecondaries 'NoTransfer'
            Set-DnsServerPrimaryZone -Name $name -SecureSecondaries NoTransfer
            $n = $name; $script:Undo.Add({ Set-DnsServerPrimaryZone -Name $n -SecureSecondaries TransferAnyServer }.GetNewClosure())
            Ok "$name : zone transfers to any server -> none (anyone could download every record)"
        }
        if ($z.IsDsIntegrated -and $z.DynamicUpdate -eq 'NonsecureAndSecure') {
            Record "zone $name DynamicUpdate" 'NonsecureAndSecure' 'Secure'
            Set-DnsServerPrimaryZone -Name $name -DynamicUpdate Secure
            $n = $name; $script:Undo.Add({ Set-DnsServerPrimaryZone -Name $n -DynamicUpdate NonsecureAndSecure }.GetNewClosure())
            Ok "$name : dynamic updates -> secure only (no unauthenticated record changes)"
        } elseif (-not $z.IsDsIntegrated -and $z.DynamicUpdate -ne 'None') {
            Warn "$name : file-backed zone accepts unauthenticated dynamic updates - consider Set-DnsServerPrimaryZone -Name $name -DynamicUpdate None"
        }
    }
    $cache = Get-DnsServerCache
    if ($cache.LockingPercent -lt 100) {
        Record 'DNS cache LockingPercent' $cache.LockingPercent 100
        Set-DnsServerCache -LockingPercent 100
        $o = $cache.LockingPercent; $script:Undo.Add({ Set-DnsServerCache -LockingPercent $o }.GetNewClosure())
        Ok 'cache locking 100% (cached answers can''t be overwritten - cache poisoning)'
    }
    try {
        $rrl = Get-DnsServerResponseRateLimiting
        if ($rrl.Mode -ne 'Enable') {
            Record 'DNS response rate limiting' $rrl.Mode 'Enable'
            Set-DnsServerResponseRateLimiting -Mode Enable -Confirm:$false | Out-Null
            $o = $rrl.Mode; $script:Undo.Add({ Set-DnsServerResponseRateLimiting -Mode $o -Confirm:$false | Out-Null }.GetNewClosure())
            Ok 'response rate limiting on (defaults: 5 identical answers/s per client subnet - amplification attacks)'
        }
    } catch { Warn "response rate limiting: $($_.Exception.Message)" }
    wevtutil sl 'Microsoft-Windows-DNSServer/Audit' /e:true 2>$null
    Ok 'DNS audit log on (Event Viewer > Applications and Services > Microsoft > Windows > DNS-Server > Audit)'

    # Open resolver: anyone on the internet can use us for recursion (amplification). The scorer
    # most likely asks for OUR records, which don't need recursion - but that's not certain.
    $scope = Get-DnsServerRecursionScope -Name '.' -ErrorAction SilentlyContinue
    if ($scope -and $scope.EnableRecursion -and -not (Get-DnsServerQueryResolutionPolicy -Name 'CCDC-RecursionInside' -ErrorAction SilentlyContinue)) {
        Warn 'recursion is open to everyone (outside clients can use this server to look up any name)'
        if (Ask "Allow recursion only for $($Inside -join ', ') and this server? Our own zones still answer everyone. Check Quotient's DNS check right after") {
            Add-DnsServerClientSubnet -Name 'CCDC-Inside' -IPv4Subnet (@($Inside) + '127.0.0.0/8')
            Add-DnsServerRecursionScope -Name 'CCDC-Internal' -EnableRecursion $true
            Add-DnsServerQueryResolutionPolicy -Name 'CCDC-RecursionInside' -Action ALLOW -ApplyOnRecursion -RecursionScope 'CCDC-Internal' -ClientSubnet 'EQ,CCDC-Inside'
            Set-DnsServerRecursionScope -Name '.' -EnableRecursion $false
            Record 'DNS recursion' 'everyone' "only $($Inside -join ',')"
            $script:Undo.Add({
                Set-DnsServerRecursionScope -Name '.' -EnableRecursion $true
                Remove-DnsServerQueryResolutionPolicy -Name 'CCDC-RecursionInside' -Force -ErrorAction SilentlyContinue
                Remove-DnsServerRecursionScope -Name 'CCDC-Internal' -Force -ErrorAction SilentlyContinue
                Remove-DnsServerClientSubnet -Name 'CCDC-Inside' -Force -ErrorAction SilentlyContinue })
            if (Resolve-DnsName -Name 'www.microsoft.com' -Server 127.0.0.1 -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue) { Ok 'recursion limited to the LAN; this server still resolves internet names' }
            else { Warn 'this server can''t resolve internet names now (was it able to before? forwarders / internet access)' }
            Info 'Undo: Set-DnsServerRecursionScope -Name . -EnableRecursion $true'
        }
    }
    foreach ($z in $zones) {
        if ($before[$z.ZoneName] -and -not (& $answers $z.ZoneName)) { Bad "$($z.ZoneName) stopped answering"; Undo-Section; return }
    }
    Ok 'every zone still answers'
}

# ============================================================================ WinRM (dc)
function Secure-WinRM {
    Begin-Section 'WinRM (AD-WinRM check)'
    $svc = Get-Service WinRM -ErrorAction SilentlyContinue
    if (-not $svc) { Bad 'no WinRM service'; return }
    if ($svc.Status -ne 'Running') {
        Bad 'WinRM is NOT running - the AD-WinRM check fails'
        if (Ask 'Start WinRM and set it to Automatic?') { Set-Service WinRM -StartupType Automatic; Start-Service WinRM; $script:Failed-- }
    }
    try { Test-WSMan -ComputerName localhost -ErrorAction Stop | Out-Null; Ok 'WinRM answers on HTTP 5985' }
    catch { Warn "WinRM doesn't answer locally: $($_.Exception.Message) (Enable-PSRemoting -Force sets it up)" }

    $item = { param($p) (Get-Item "WSMan:\localhost\Service\$p" -ErrorAction SilentlyContinue).Value }
    foreach ($s in @(@{ P = 'AllowUnencrypted'; Why = 'logins and commands cross the network unencrypted' },
                     @{ P = 'Auth\Basic'; Why = 'Basic auth sends the password itself (base64)' },
                     @{ P = 'Auth\CredSSP'; Why = 'CredSSP hands the user''s password to the server (credential theft)' })) {
        if ((& $item $s.P) -ne 'true') { Ok "$($s.P) = false"; continue }
        Warn "$($s.P) = true - $($s.Why)"
        if (Ask "Turn $($s.P) off? Only if the scorer doesn't need it - watch AD-WinRM in Quotient right after") {
            Set-Item "WSMan:\localhost\Service\$($s.P)" -Value $false
            Record "WSMan Service\$($s.P)" 'true' 'false'
            $p = $s.P; $script:Undo.Add({ Set-Item "WSMan:\localhost\Service\$p" -Value $true }.GetNewClosure())
            Info "undo: Set-Item WSMan:\localhost\Service\$($s.P) -Value `$true"
        }
    }
    # HTTPS listener (5986) next to HTTP: encrypted WinRM for anything that can use it
    $listeners = @(Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue)
    if (-not ($listeners | Where-Object { $_.Keys -contains 'Transport=HTTPS' })) {
        try {
            $fqdn = [Net.Dns]::GetHostEntry($env:COMPUTERNAME).HostName
            $cert = New-SelfSignedCertificate -DnsName $fqdn, $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(1)
            New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $cert.Thumbprint -Force | Out-Null
            Record 'WinRM HTTPS listener' 'none' "5986, cert $($cert.Thumbprint)"
            $script:Undo.Add({ Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTPS' } | Remove-Item -Recurse -Force }.GetNewClosure())
            Ok "HTTPS listener on 5986 (self-signed certificate for $fqdn); HTTP 5985 unchanged"
        } catch { Warn "could not add the HTTPS listener: $($_.Exception.Message)" }
    } else { Ok 'HTTPS listener already present' }

    try { Get-ADGroupMember 'Remote Management Users' -ErrorAction Stop | ForEach-Object { Info "Remote Management Users member: $($_.SamAccountName)" } } catch { }
    try {
        Test-WSMan -ComputerName localhost -ErrorAction Stop | Out-Null
        Invoke-Command -ComputerName localhost -ScriptBlock { 1 } -ErrorAction Stop | Out-Null
        Ok 'WinRM still runs a PowerShell command (what the scorer does)'
    } catch { Bad "WinRM test failed after the changes: $($_.Exception.Message)"; Undo-Section }
}

# ============================================================================ SMB (mssql)
function Secure-Smb {
    Begin-Section 'SMB (MSSQL SMB check - the SOP files)'
    $shares = @(Get-SmbShare | Where-Object { -not $_.Special -and $_.Name -notmatch '\$$' })
    $reach = { param($n) Test-Path -LiteralPath "\\localhost\$n" }
    $before = @{}; foreach ($s in $shares) { $before[$s.Name] = & $reach $s.Name }
    if (-not $shares) { Warn 'no file shares (besides admin shares) - the SMB check looks for SOP files in one' }

    # Backup + hash list of every share: proof and a way back if the red team deletes or plants files
    foreach ($s in $shares) {
        $dest = Join-Path $OutDir "share-backup-$Stamp\$($s.Name)"
        $size = (Get-ChildItem -LiteralPath $s.Path -Recurse -File -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
        if ($size -gt 500MB) { Warn "share $($s.Name) is $([int]($size / 1MB)) MB - not backed up"; continue }
        robocopy $s.Path $dest /E /COPY:DAT /R:0 /W:0 /NFL /NDL /NJH /NJS | Out-Null
        Get-ChildItem -LiteralPath $s.Path -Recurse -File -ErrorAction SilentlyContinue | Get-FileHash -Algorithm SHA256 |
            Select-Object Hash, Path | Export-Csv -LiteralPath (Join-Path $OutDir "share-$($s.Name)-hashes-$Stamp.csv") -NoTypeInformation
        Ok "share $($s.Name) ($($s.Path)): backed up to $dest, hashes saved"
    }

    # No anonymous / null sessions (the scorer logs in with a user)
    $lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $srv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'
    Set-Reg $lsa RestrictAnonymous 1
    Set-Reg $lsa RestrictAnonymousSAM 1
    Set-Reg $lsa EveryoneIncludesAnonymous 0
    Set-Reg $srv RestrictNullSessAccess 1
    $nss = (Get-ItemProperty $srv -Name NullSessionShares -ErrorAction SilentlyContinue).NullSessionShares
    if ($nss -and ($nss -join '')) { Set-Reg $srv NullSessionShares ([string[]]@()) 'MultiString'; Warn "null-session shares were: $($nss -join ', ') - cleared" }
    Ok 'anonymous / null-session access off'
    auditpol /set /subcategory:"File Share" /success:enable /failure:enable | Out-Null
    Ok 'share access auditing on (Security log 5140 / 5145)'
    $cfg = Get-SmbServerConfiguration
    if ($cfg.EnableSMB1Protocol) { Warn 'SMB1 is on (harden.ps1 turns it off)' }
    if (-not $cfg.RequireSecuritySignature) { Warn 'SMB signing not required (harden.ps1 requires it)' }

    foreach ($s in $shares) {
        foreach ($a in Get-SmbShareAccess -Name $s.Name) {
            if ($a.AccessControlType -ne 'Allow' -or "$($a.AccessRight)" -notin 'Full', 'Change') { continue }
            if ($a.AccountName -notmatch 'Everyone|Guest|Anonymous|Authenticated Users|Domain Users|\\Users$') { continue }
            Warn "share $($s.Name): $($a.AccountName) has $($a.AccessRight) - anyone with any login can change or delete the SOPs"
            if (Ask "Make $($a.AccountName) read-only on $($s.Name)? (the check only reads the files)") {
                $n = $s.Name; $acct = $a.AccountName; $right = $a.AccessRight
                Grant-SmbShareAccess -Name $n -AccountName $acct -AccessRight Read -Force | Out-Null
                Record "share $n access $acct" $right 'Read'
                $script:Undo.Add({ Grant-SmbShareAccess -Name $n -AccountName $acct -AccessRight $right -Force | Out-Null }.GetNewClosure())
            }
        }
        Info "share $($s.Name) access: $((Get-SmbShareAccess -Name $s.Name | ForEach-Object { "$($_.AccountName)=$($_.AccessRight)" }) -join '; ')"
    }
    foreach ($s in $shares) {
        if ($before[$s.Name] -and -not (& $reach $s.Name)) { Bad "share $($s.Name) no longer reachable"; Undo-Section; return }
    }
    if (Port-Open 445) { Ok 'SMB 445 answers, shares reachable' } else { Bad 'SMB 445 not answering'; Undo-Section }
    Info 'Re-check the SOPs any time: compare Get-FileHash of the share with the saved share-*-hashes CSV'
}

# ============================================================================ RDP
function Secure-Rdp {
    Begin-Section 'RDP'
    $ts = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $rdp = "$ts\WinStations\RDP-Tcp"
    if ((Get-ItemProperty $ts -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections -eq 1) {
        if ($Role -eq 'mssql') {
            Bad 'RDP is turned OFF - the MSSQL RDP check fails'
            if (Ask 'Turn RDP on?') { Set-Reg $ts fDenyTSConnections 0; $script:Failed-- } else { return }
        } else { Info 'RDP is off on this machine - leaving it off'; return }
    }
    Set-Reg $rdp UserAuthentication 1        # Network Level Authentication: log in before a session is created
    Set-Reg $rdp SecurityLayer 2             # TLS
    Set-Reg $rdp MinEncryptionLevel 3        # high
    Set-Reg $rdp fDisableEncryption 0
    Ok 'RDP: NLA required, TLS, high encryption'
    if ((Get-Service TermService).Status -ne 'Running') { Start-Service TermService -ErrorAction SilentlyContinue }
    try { Get-LocalGroupMember 'Remote Desktop Users' -ErrorAction Stop | ForEach-Object { Info "Remote Desktop Users member: $($_.Name)" } } catch { }
    Start-Sleep -Seconds 1
    if (Port-Open 3389) { Ok 'RDP 3389 answers' } else { Bad 'RDP 3389 not answering after the change'; Undo-Section }
}

# ============================================================================ SQL Server (mssql)
function Secure-Sql {
    Begin-Section 'SQL Server (MSSQL check)'
    $names = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL' -ErrorAction SilentlyContinue
    if (-not $names) { Bad 'no SQL Server instance found'; return }
    $instances = @($names.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { @{ Name = $_.Name; Id = $_.Value } })
    $sqlPids = @(Get-Process sqlservr -ErrorAction SilentlyContinue | ForEach-Object Id)
    $ports = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $sqlPids -contains $_.OwningProcess } | ForEach-Object LocalPort | Sort-Object -Unique)
    Info "instances: $(($instances | ForEach-Object Name) -join ', '); listening on TCP $($ports -join ', ')"
    if (-not $ports) { Bad 'SQL Server is not listening on TCP - the MSSQL check fails (SQL Server Configuration Manager > TCP/IP)' }
    $sqlcmd = Get-Command sqlcmd.exe -ErrorAction SilentlyContinue

    foreach ($inst in $instances) {
        $srv = if ($inst.Name -eq 'MSSQLSERVER') { 'localhost' } else { "localhost\$($inst.Name)" }
        # Login auditing (failed + successful) - takes effect at the next SQL Server restart
        Set-Reg "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$($inst.Id)\MSSQLServer" AuditLevel 3
        $force = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$($inst.Id)\MSSQLServer\SuperSocketNetLib" -Name ForceEncryption -ErrorAction SilentlyContinue).ForceEncryption
        Info "$srv : login auditing set to failed+successful (applies at the next SQL restart - not restarting a scored service now)"
        Info "$srv : ForceEncryption = $([int]$force) - left as it is (clients that don't trust a self-signed certificate would fail)"
        if (-not $sqlcmd) { Warn 'sqlcmd.exe not found - can''t check SQL settings and logins (install the SQL command line tools or use SSMS)'; continue }
        $sql = { param($q) & sqlcmd.exe -S $srv -E -b -h -1 -W -Q "SET NOCOUNT ON; $q" 2>&1 }
        $one = & $sql 'SELECT 1'
        if ("$one".Trim() -ne '1') { Warn "$srv : can't log in with Windows authentication as $env:USERNAME (not sysadmin?) - $one"; continue }

        & $sql "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;" | Out-Null
        # User CLR assemblies in any database (then CLR is in use and stays on)
        $assemblies = "$(& $sql "CREATE TABLE #a (n int); EXEC sp_MSforeachdb 'USE [?]; INSERT #a SELECT COUNT(*) FROM sys.assemblies WHERE is_user_defined = 1'; SELECT ISNULL(SUM(n), 0) FROM #a")".Trim()
        foreach ($o in @(@{ N = 'xp_cmdshell'; Why = 'runs Windows commands from SQL - the classic way in through a SQL login' },
                         @{ N = 'Ole Automation Procedures'; Why = 'COM objects from SQL - command execution' },
                         @{ N = 'Ad Hoc Distributed Queries'; Why = 'OPENROWSET to other servers - data exfiltration' },
                         @{ N = 'clr enabled'; Why = '.NET code inside SQL Server' })) {
            $v = "$(& $sql "SELECT CAST(value_in_use AS int) FROM sys.configurations WHERE name = '$($o.N)'")".Trim()
            if ($v -ne '1') { Ok "$($o.N) off"; continue }
            if ($o.N -eq 'clr enabled' -and $assemblies -ne '0') { Warn "clr enabled with user assemblies in use - leaving it on"; continue }
            Warn "$($o.N) is ON - $($o.Why)"
            if (Ask "Turn $($o.N) off?") {
                & $sql "EXEC sp_configure '$($o.N)', 0; RECONFIGURE;" | Out-Null
                Record "$srv sp_configure $($o.N)" 1 0
                $n = $o.N; $s2 = $srv
                $script:Undo.Add({ & sqlcmd.exe -S $s2 -E -b -Q "EXEC sp_configure '$n', 1; RECONFIGURE;" | Out-Null }.GetNewClosure())
            }
        }
        $weak = @(& $sql "SELECT name FROM sys.sql_logins WHERE PWDCOMPARE('', password_hash) = 1 OR PWDCOMPARE(name, password_hash) = 1 OR PWDCOMPARE('password', password_hash) = 1" | Where-Object { "$_".Trim() })
        foreach ($w in $weak) { Bad "$srv : SQL login '$("$w".Trim())' has a blank / own-name / 'password' password - change it now (checklists/mssql, PCR if scored)" }
        $nopol = @(& $sql "SELECT name FROM sys.sql_logins WHERE is_policy_checked = 0 AND is_disabled = 0" | Where-Object { "$_".Trim() })
        if ($nopol) { Warn "$srv : SQL logins without the Windows password policy: $(($nopol | ForEach-Object { "$_".Trim() }) -join ', ')" }
        Info "$srv : sysadmin members: $((& $sql "SELECT name FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1" | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) -join ', ')"
        $startup = @(& $sql "SELECT name FROM master.sys.procedures WHERE OBJECTPROPERTY(object_id, 'ExecIsStartup') = 1" | Where-Object { "$_".Trim() })
        if ($startup) { Warn "$srv : procedures that run at SQL startup (persistence?): $(($startup | ForEach-Object { "$_".Trim() }) -join ', ')" }
        $linked = @(& $sql "SELECT name FROM sys.servers WHERE is_linked = 1" | Where-Object { "$_".Trim() })
        if ($linked) { Warn "$srv : linked servers: $(($linked | ForEach-Object { "$_".Trim() }) -join ', ')" }
        if ("$(& $sql 'SELECT 1')".Trim() -ne '1') { Bad "$srv stopped answering queries"; Undo-Section; return }
        Ok "$srv : still answers queries"
    }
    $browser = Get-Service SQLBrowser -ErrorAction SilentlyContinue
    if ($browser -and $browser.Status -eq 'Running' -and -not ($instances | Where-Object { $_.Name -ne 'MSSQLSERVER' })) {
        Warn 'SQL Browser (UDP 1434) runs but there is only the default instance - it just advertises the server'
        if (Ask 'Stop and disable SQL Browser? (connections to port 1433 don''t need it)') {
            Stop-Service SQLBrowser; Set-Service SQLBrowser -StartupType Disabled; Record 'service SQLBrowser' 'Running' 'Disabled'
            $script:Undo.Add({ Set-Service SQLBrowser -StartupType Automatic; Start-Service SQLBrowser })
        }
    }
    foreach ($p in $ports) { if (-not (Port-Open $p)) { Bad "SQL port $p not answering"; Undo-Section; return } }
    if ($ports) { Ok "SQL Server answers on $($ports -join ', ')" }
}

# ============================================================================ IIS FTP (older topologies)
function Secure-Ftp {
    Begin-Section 'FTP (IIS)'
    if (-not (Get-Service ftpsvc -ErrorAction SilentlyContinue)) { Info 'no IIS FTP service - skipped'; return }
    Import-Module WebAdministration
    $sites = @(Get-ChildItem IIS:\Sites | Where-Object { $_.Bindings.Collection.protocol -contains 'ftp' })
    foreach ($s in $sites) {
        $p = "IIS:\Sites\$($s.Name)"
        if ((Get-ItemProperty $p -Name ftpServer.security.authentication.anonymousAuthentication.enabled).Value) {
            Set-ItemProperty $p -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $false
            Record "FTP $($s.Name) anonymous" 'True' 'False'
            $pp = $p; $script:Undo.Add({ Set-ItemProperty $pp -Name ftpServer.security.authentication.anonymousAuthentication.enabled -Value $true }.GetNewClosure())
            Ok "$($s.Name): anonymous FTP off (the check logs in with a user)"
        }
        if (-not (Get-ItemProperty $p -Name ftpServer.security.ssl.serverCertHash).Value) {
            $cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(1)
            Set-ItemProperty $p -Name ftpServer.security.ssl.serverCertHash -Value $cert.Thumbprint
        }
        Set-ItemProperty $p -Name ftpServer.security.ssl.controlChannelPolicy -Value 'SslAllow'
        Set-ItemProperty $p -Name ftpServer.security.ssl.dataChannelPolicy -Value 'SslAllow'
        Ok "$($s.Name): FTPS allowed (not required)"
    }
    if (Port-Open 21) { Ok 'FTP 21 answers' } else { Bad 'FTP 21 not answering'; Undo-Section }
}

# ------------------------------------------------------------------ run
switch ($Role) {
    'dc'          { Secure-Dns; Secure-WinRM }
    'mssql'       { Secure-Smb; Secure-Rdp; Secure-Sql }
    'ftp'         { Secure-Ftp; Secure-Rdp }
    'web'         { Secure-Rdp; Info 'IIS HTTP -> HTTPS redirect is not automated (needs the URL Rewrite module) - older topologies only' }
    'workstation' { Secure-Rdp }
}
H1 'SUMMARY'
Info "Changes and previous values: $UndoCsv"
if ($script:Failed -eq 0) { Ok 'done - now check Quotient: every service still up?' }
else { Bad "$($script:Failed) problem(s) - see above" }
Stop-Transcript | Out-Null
exit $(if ($script:Failed) { 1 } else { 0 })
