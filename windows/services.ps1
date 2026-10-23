<#
.SYNOPSIS
Service inventory, legacy-service removal and update check (Windows 11 / Server 2019 / 2022).

.DESCRIPTION
Report (default):
  - what listens on the network: port, process, Windows service, executable, file version, vendor
  - legacy / insecure features, services and protocols that should be removed right away
    (SMB1, PowerShell 2.0, Telnet/TFTP, SNMP, Simple TCP/IP, IIS FTP/WebDAV, Remote Registry,
    Print Spooler on servers, TLS 1.0/1.1 and SSL, NTLMv1/LM)
  - end-of-life Windows versions and software
  - pending Windows updates (security/critical first) and when the last update was installed

  -Fix            remove / disable each legacy item (asks per item; -Yes to skip asking)
  -ScoredPorts    ports the scoring engine uses on this machine; legacy items on these ports are
                  reported as SCORED? and never touched (default by -Role: web 80,443 / ftp 20,21,990 /
                  dc 53,88,135,389,445,464,636,3268,3269,5985,5986 / mssql 135,445,1433,3389 /
                  workstation 3389)
  -SkipUpdates    don't search Windows Update (the search can take a few minutes)
  -InstallUpdates install pending Security/Critical updates, asking per update. Never reboots;
                  says when a reboot is needed - plan it with the captain.

Changes are logged with their previous values to C:\ProgramData\CCDC\services-<time>-undo.csv.
Exit code: 2 legacy item found, 1 warnings / pending updates, 0 clean.

.EXAMPLE
.\services.ps1 -Role web
.\services.ps1 -Role web -Fix
#>
param(
    [ValidateSet('workstation', 'web', 'dc', 'ftp', 'mssql')]
    [string]$Role = 'workstation',
    [switch]$Fix,
    [switch]$Yes,
    [int[]]$ScoredPorts = @(),
    [switch]$SkipUpdates,
    [switch]$InstallUpdates
)

$ErrorActionPreference = 'Continue'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this from an elevated (Administrator) PowerShell.' -ForegroundColor Red; exit 1 }
if (-not $ScoredPorts) {
    $ScoredPorts = switch ($Role) {
        'web' { @(80, 443) }
        'ftp' { @(20, 21, 990) }                                       # FTP control/data, FTPS
        'dc'  { @(53, 88, 135, 389, 445, 464, 636, 3268, 3269, 5985, 5986) }   # DNS, WinRM (scored) + what AD needs
        'mssql' { @(135, 445, 1433, 3389) }                            # SMB, SQL, RDP (scored)
        default { @(3389) }
    }
}

$OutDir = "$env:ProgramData\CCDC"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Log = Join-Path $OutDir "services-$Stamp.log"
$Undo = Join-Path $OutDir "services-$Stamp-undo.csv"
Start-Transcript -LiteralPath $Log | Out-Null

$script:Crit = 0; $script:Warn = 0
function Legacy([string]$m) { $script:Crit++; Write-Host "[LEGACY] $m" -ForegroundColor Red
    try { if (-not [Diagnostics.EventLog]::SourceExists('CCDC-Services')) { New-EventLog -LogName Application -Source CCDC-Services }
          Write-EventLog -LogName Application -Source CCDC-Services -EventId 4500 -EntryType Warning -Message "LEGACY: $m" } catch { } }
function Warn([string]$m) { $script:Warn++; Write-Host "[WARN]   $m" -ForegroundColor Yellow }
function Ok([string]$m)   { Write-Host "[OK]     $m" -ForegroundColor Green }
function Info([string]$m) { Write-Host "         $m" }
function H1([string]$t)   { Write-Host "`n==================== $t ====================" -ForegroundColor Cyan }
function Ask([string]$q)  { if ($Yes) { return $true }; (Read-Host "    $q [y/N]") -match '^[Yy]' }
function Record($What, $Old, $New) { [pscustomobject]@{ Time = (Get-Date -Format s); Item = $What; Old = $Old; New = $New } | Export-Csv -LiteralPath $Undo -Append -NoTypeInformation }

$os = Get-CimInstance Win32_OperatingSystem
$isServer = $os.ProductType -ne 1
Write-Host "Service scan of $env:COMPUTERNAME - $($os.Caption) build $($os.BuildNumber) - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "Scored ports (never touched): $($ScoredPorts -join ', ')"

# ------------------------------------------------------------------ 1. inventory
H1 'LISTENING SERVICES'
$svcByPid = @{}
Get-CimInstance Win32_Service | Where-Object ProcessId | ForEach-Object { $svcByPid[[int]$_.ProcessId] += @($_.Name) }
$listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Proto = 'TCP'; Address = $_.LocalAddress; Port = $_.LocalPort; ProcId = $_.OwningProcess } }) +
          @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -notmatch '^(127\.|::1)' } | ForEach-Object { [pscustomobject]@{ Proto = 'UDP'; Address = $_.LocalAddress; Port = $_.LocalPort; ProcId = $_.OwningProcess } })
$listen | Sort-Object Proto, Port -Unique | ForEach-Object {
    $p = Get-Process -Id $_.ProcId -ErrorAction SilentlyContinue
    $path = if ($p) { $p.Path } else { $null }
    $vi = if ($path) { (Get-Item -LiteralPath $path -ErrorAction SilentlyContinue).VersionInfo } else { $null }
    [pscustomobject]@{
        Proto = $_.Proto; Port = $_.Port; Address = $_.Address
        Process = if ($p) { $p.ProcessName } else { "pid $($_.ProcId)" }
        Services = ($svcByPid[[int]$_.ProcId] -join ',')
        Version = if ($vi) { $vi.ProductVersion } else { '' }
        Vendor = if ($vi) { $vi.CompanyName } else { '' }
        Path = $path
    }
} | Format-Table -AutoSize | Out-String -Width 250 | Write-Host

H1 'AUTO-START SERVICES NOT FROM MICROSOFT'
Get-CimInstance Win32_Service -Filter "StartMode='Auto'" | ForEach-Object {
    $exe = if ($_.PathName -match '^"([^"]+)"') { $Matches[1] } else { ($_.PathName -split ' ')[0] }
    $vi = (Get-Item -LiteralPath $exe -ErrorAction SilentlyContinue).VersionInfo
    if (-not $vi -or $vi.CompanyName -notmatch 'Microsoft') {
        [pscustomobject]@{ Name = $_.Name; State = $_.State; RunAs = $_.StartName; Vendor = $vi.CompanyName; Version = $vi.ProductVersion; Path = $exe }
    }
} | Format-Table -AutoSize | Out-String -Width 250 | Write-Host

# ------------------------------------------------------------------ 2. legacy
H1 'LEGACY AND INSECURE FEATURES, SERVICES AND PROTOCOLS'

function Test-Scored([int[]]$Ports) { @($Ports | Where-Object { $ScoredPorts -contains $_ }).Count -gt 0 }

# Optional features: server feature name / client optional feature name
$features = @(
    @{ Id = 'SMB1';      Server = 'FS-SMB1';             Client = 'SMB1Protocol';                     Ports = @();          Why = 'SMB version 1 (WannaCry/EternalBlue)' }
    @{ Id = 'PSv2';      Server = 'PowerShell-V2';       Client = 'MicrosoftWindowsPowerShellV2Root'; Ports = @();          Why = 'PowerShell 2.0 - lets attackers bypass script logging and AMSI' }
    @{ Id = 'Telnet';    Server = 'Telnet-Client';       Client = 'TelnetClient';                     Ports = @();          Why = 'Telnet client - cleartext' }
    @{ Id = 'TFTP';      Server = 'TFTP-Client';         Client = 'TFTP';                             Ports = @();          Why = 'TFTP client - used to download attack tools' }
    @{ Id = 'SimpleTCP'; Server = 'Simple-TCPIP';        Client = 'SimpleTCP';                        Ports = @(7, 9, 13, 17, 19); Why = 'Simple TCP/IP services (echo, chargen...) - amplification/DoS' }
    @{ Id = 'SNMP';      Server = 'SNMP-Service';        Client = $null;                              Ports = @(161);       Why = 'SNMP service - v1/v2c community strings are cleartext passwords' }
    @{ Id = 'FTP';       Server = 'Web-Ftp-Server';      Client = 'IIS-FTPServer';                    Ports = @(21);        Why = 'IIS FTP server - cleartext passwords (keep only if scored, then require FTPS)' }
    @{ Id = 'WebDAV';    Server = 'Web-DAV-Publishing';  Client = 'IIS-WebDAV';                       Ports = @();          Why = 'IIS WebDAV publishing - file upload to the web root' }
    @{ Id = 'IIS6Mgmt';  Server = 'Web-Mgmt-Compat';     Client = 'IIS-IIS6ManagementCompatibility';  Ports = @();          Why = 'IIS 6 management compatibility (metabase) - legacy' }
    @{ Id = 'WINS';      Server = 'WINS';                Client = $null;                              Ports = @(42);        Why = 'WINS name service - legacy NetBIOS naming' }
)
$serverFeatures = $null
if ($isServer -and (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)) {
    $serverFeatures = @{}; Get-WindowsFeature | Where-Object Installed | ForEach-Object { $serverFeatures[$_.Name] = $true }
}
foreach ($f in $features) {
    $name = if ($isServer) { $f.Server } else { $f.Client }
    if (-not $name) { continue }
    $installed = if ($isServer -and $serverFeatures) { $serverFeatures.ContainsKey($name) }
                 else { (Get-WindowsOptionalFeature -Online -FeatureName $name -ErrorAction SilentlyContinue).State -eq 'Enabled' }
    if (-not $installed) { continue }
    if (Test-Scored $f.Ports) { Warn "SCORED? $($f.Why) - feature $name uses a scored port; not touching it, harden it instead"; continue }
    Legacy "$($f.Why) - feature $name is installed"
    if ($Fix -and (Ask "Remove feature $name?")) {
        try {
            if ($isServer -and $serverFeatures) { Uninstall-WindowsFeature -Name $name -ErrorAction Stop | Out-Null }
            else { Disable-WindowsOptionalFeature -Online -FeatureName $name -NoRestart -ErrorAction Stop | Out-Null }
            Record "feature $name" 'installed' 'removed'; Info "removed $name (a reboot may be needed to finish)"
        } catch { Warn "could not remove ${name}: $($_.Exception.Message)" }
    }
}
if (-not $isServer) {
    Get-WindowsCapability -Online -Name 'SNMP.Client*' -ErrorAction SilentlyContinue | Where-Object State -eq 'Installed' | ForEach-Object {
        if (Test-Scored @(161)) { Warn "SCORED? SNMP capability installed on a scored port"; return }
        Legacy 'SNMP capability installed - v1/v2c community strings are cleartext passwords'
        if ($Fix -and (Ask 'Remove the SNMP capability?')) { Remove-WindowsCapability -Online -Name $_.Name | Out-Null; Record 'capability SNMP' 'installed' 'removed' }
    }
}

# SMB1 as a protocol setting (feature may be absent but protocol enabled)
$smb = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
if ($smb -and $smb.EnableSMB1Protocol) {
    Legacy 'SMB1 protocol is enabled on the SMB server'
    if ($Fix -and (Ask 'Disable SMB1 on the SMB server?')) { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; Record 'SMB1 server' 'True' 'False' }
} elseif ($smb) { Ok 'SMB1 protocol disabled on the SMB server' }

# Services that should not run
$services = @(
    @{ Name = 'RemoteRegistry'; Why = 'Remote Registry - remote read/write of the registry'; Ports = @() }
    @{ Name = 'TlntSvr';        Why = 'Telnet server - cleartext logins'; Ports = @(23) }
    @{ Name = 'simptcp';        Why = 'Simple TCP/IP services'; Ports = @(7, 9, 13, 17, 19) }
    @{ Name = 'SNMP';           Why = 'SNMP service'; Ports = @(161) }
    @{ Name = 'SNMPTRAP';       Why = 'SNMP trap service'; Ports = @(162) }
    @{ Name = 'Fax';            Why = 'Fax service - not needed'; Ports = @() }
    @{ Name = 'upnphost';       Why = 'UPnP device host - not needed on servers'; Ports = @() }
    @{ Name = 'SSDPSRV';        Why = 'SSDP discovery - not needed on servers'; Ports = @(1900) }
    @{ Name = 'WebClient';      Why = 'WebClient (WebDAV client) - abused for NTLM relay'; Ports = @() }
    @{ Name = 'MSFTPSVC';       Why = 'Old IIS FTP service'; Ports = @(21) }
    @{ Name = 'ftpsvc';         Why = 'IIS FTP service - cleartext passwords'; Ports = @(21) }
)
if ($isServer) { $services += @{ Name = 'Spooler'; Why = 'Print Spooler on a server (PrintNightmare) - disable unless this is a print server'; Ports = @() } }
foreach ($s in $services) {
    $svc = Get-Service -Name $s.Name -ErrorAction SilentlyContinue
    if (-not $svc -or ($svc.StartType -eq 'Disabled' -and $svc.Status -ne 'Running')) { continue }
    if ($s.Name -in 'upnphost', 'SSDPSRV' -and -not $isServer) { continue }
    if (Test-Scored $s.Ports) { Warn "SCORED? $($s.Why) - service $($s.Name) uses a scored port; not touching it"; continue }
    $msg = "$($s.Why) - service $($s.Name) is $($svc.Status), start type $($svc.StartType)"
    if ($svc.Status -eq 'Running' -or $svc.StartType -eq 'Automatic') { Legacy $msg } else { Warn "$msg (starts on demand)" }
    if ($Fix -and (Ask "Stop and disable service $($s.Name)?")) {
        try {
            Stop-Service -Name $s.Name -Force -ErrorAction Stop
            Set-Service -Name $s.Name -StartupType Disabled -ErrorAction Stop
            Record "service $($s.Name)" "$($svc.StartType)/$($svc.Status)" 'Disabled/Stopped'
            Info "disabled $($s.Name) (undo: Set-Service $($s.Name) -StartupType $($svc.StartType); Start-Service $($s.Name))"
        } catch { Warn "could not disable $($s.Name): $($_.Exception.Message)" }
    }
}

# Old TLS / SSL versions
$sch = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
$weak = @()
foreach ($p in 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1') {
    $k = Join-Path $sch "$p\Server"
    $en = (Get-ItemProperty -Path $k -Name Enabled -ErrorAction SilentlyContinue).Enabled
    if ($en -ne 0) { $weak += $p }
}
if ($weak) {
    $msg = "Old protocols not explicitly disabled: $($weak -join ', ') (not set = Windows default; Server 2019 still allows TLS 1.0/1.1)"
    if ($isServer) { Legacy $msg } else { Warn $msg }
    Info 'Disabling them needs a reboot; test every scored HTTPS / RDP service afterwards.'
    if ($Fix -and (Ask "Disable $($weak -join ', ') (server and client side)?")) {
        foreach ($p in $weak) {
            foreach ($side in 'Server', 'Client') {
                $k = Join-Path $sch "$p\$side"
                if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
                Record "SCHANNEL $p $side Enabled" ((Get-ItemProperty $k -Name Enabled -ErrorAction SilentlyContinue).Enabled) 0
                New-ItemProperty -Path $k -Name Enabled -Value 0 -PropertyType DWord -Force | Out-Null
                New-ItemProperty -Path $k -Name DisabledByDefault -Value 1 -PropertyType DWord -Force | Out-Null
            }
        }
        Info 'Done - reboot when convenient, then test HTTPS and RDP.'
    }
} else { Ok 'SSL 2.0/3.0 and TLS 1.0/1.1 disabled' }

# LM / NTLMv1
$lm = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel
if ($null -eq $lm) { Ok 'LmCompatibilityLevel not set (Windows default: send NTLMv2 only); 5 also refuses LM/NTLMv1 from clients' }
elseif ($lm -lt 3) {
    Legacy "LmCompatibilityLevel is $lm - LM / NTLMv1 responses may be sent (cracked in minutes)"
    if ($Fix -and (Ask 'Set LmCompatibilityLevel to 5 (NTLMv2 only, refuse LM and NTLMv1)?')) {
        Record 'LmCompatibilityLevel' $lm 5
        New-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 -PropertyType DWord -Force | Out-Null
    }
} else { Ok "LmCompatibilityLevel $lm (NTLMv2)" }

# Settings harden.ps1 handles - report only
$llmnr = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name EnableMulticast -ErrorAction SilentlyContinue).EnableMulticast
if ($llmnr -ne 0) { Warn 'LLMNR is enabled - run harden.ps1' }
$nla = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -ErrorAction SilentlyContinue).UserAuthentication
if ($nla -ne 1) { Warn 'RDP does not require Network Level Authentication - run harden.ps1' }

# ------------------------------------------------------------------ 3. end of life
H1 'END-OF-LIFE SOFTWARE (no more security fixes; as of October 2026)'
$build = [int]$os.BuildNumber
$eol = $null
if ($isServer) {
    if ($build -lt 14393) { $eol = "$($os.Caption) (Server 2012 R2 and older ended October 2023)" }
    elseif ($build -lt 17763) { Info "Windows Server 2016: extended support ends January 2027" }
} else {
    if ($build -lt 22000) { $eol = "Windows 10 (ended October 2025 without paid Extended Security Updates)" }
    elseif ($build -lt 22631) { $eol = "Windows 11 build $build (21H2 / 22H2)" }
    elseif ($build -lt 26100 -and $os.Caption -notmatch 'Enterprise|Education') { $eol = "Windows 11 23H2 Home/Pro (ended November 2025)" }
    elseif ($build -lt 26200 -and $os.Caption -notmatch 'Enterprise|Education') { $eol = "Windows 11 24H2 Home/Pro (ended October 13, 2026)" }
}
if ($eol) { Warn "Operating system is end-of-life: $eol - note it in reports; can't be upgraded mid-competition" }
else { Ok "Operating system: $($os.Caption) build $build" }

$eolSoftware = @(
    @{ Re = '^Adobe Flash';                        Why = 'Adobe Flash Player (ended 2020)' }
    @{ Re = '^Microsoft Silverlight';              Why = 'Silverlight (ended 2021)' }
    @{ Re = '^Python 2\.';                         Why = 'Python 2 (ended 2020)' }
    @{ Re = '^PHP [5-7]\.|^PHP 8\.[01]\b';         Why = 'PHP older than 8.2 (8.1 ended December 2025)' }
    @{ Re = '^MySQL Server [5-8]\.[0-7]?\b|^MySQL Server 8\.0'; Why = 'MySQL 5.x / 8.0 (8.0 ended April 2026)' }
    @{ Re = '^Apache Tomcat [5-8]\.';              Why = 'Apache Tomcat 8.x or older' }
    @{ Re = '^QuickTime';                          Why = 'QuickTime for Windows (ended 2016)' }
    @{ Re = '^Microsoft SQL Server 20(0[0-9]|1[0-4])\b'; Why = 'SQL Server 2014 or older' }
)
$apps = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue |
    Where-Object DisplayName
$hit = $false
foreach ($a in $apps) {
    foreach ($e in $eolSoftware) {
        if ($a.DisplayName -match $e.Re) { Warn "$($e.Why): $($a.DisplayName) $($a.DisplayVersion)"; $hit = $true }
    }
}
if (-not $hit) { Ok 'No known end-of-life applications in the installed programs list' }
$iis = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\InetStp' -ErrorAction SilentlyContinue
if ($iis) { Info "IIS $($iis.MajorVersion).$($iis.MinorVersion) (updated through Windows Update)" }
Get-ChildItem 'C:\Program Files\PHP', 'C:\PHP', 'C:\tools\php*' -Filter php.exe -Recurse -Depth 2 -ErrorAction SilentlyContinue | ForEach-Object {
    $v = $_.VersionInfo.ProductVersion
    if ($v -and [version]($v -replace '[^0-9.].*$') -lt [version]'8.2') { Warn "PHP $v at $($_.FullName) is end-of-life" } else { Info "PHP $v at $($_.FullName)" }
}

# ------------------------------------------------------------------ 4. updates
H1 'UPDATES'
$last = Get-HotFix -ErrorAction SilentlyContinue | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($last) {
    $days = [int]((Get-Date) - $last.InstalledOn).TotalDays
    $msg = "Last update installed: $($last.HotFixID) on $($last.InstalledOn.ToString('yyyy-MM-dd')) ($days days ago)"
    if ($days -gt 45) { Warn $msg } else { Ok $msg }
}
$wuQuery = "IsInstalled=0 and IsHidden=0 and Type='Software'"
if (-not $SkipUpdates -and -not $InstallUpdates) {
    Write-Host 'Searching Windows Update (up to 3 minutes; -SkipUpdates to skip)...'
    $job = Start-Job -ArgumentList $wuQuery -ScriptBlock {
        param($q)
        $r = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search($q)
        foreach ($u in $r.Updates) {
            [pscustomobject]@{ Severity = $u.MsrcSeverity; KB = ($u.KBArticleIDs -join ',')
                               Categories = (@($u.Categories) | ForEach-Object { $_.Name }) -join ', '; Title = $u.Title
                               Reboot = $u.InstallationBehavior.RebootBehavior -ne 0 }
        }
    }
    if (Wait-Job $job -Timeout 180) {
        $pending = @(Receive-Job $job -ErrorAction SilentlyContinue)
        if ($job.State -eq 'Failed' -or $job.ChildJobs[0].Error.Count) { Warn "Windows Update search failed (no internet / WSUS?): $($job.ChildJobs[0].Error | Select-Object -First 1)" }
        elseif (-not $pending) { Ok 'No pending Windows updates' }
        else {
            $important = @($pending | Where-Object { $_.Severity -in 'Critical', 'Important' -or $_.Categories -match 'Security|Critical' })
            $pending | Sort-Object @{ e = { $_.Severity -in 'Critical', 'Important' }; Descending = $true } |
                Format-Table Severity, KB, Reboot, Title -AutoSize -Wrap | Out-String -Width 220 | Write-Host
            Warn "$($pending.Count) pending update(s), $($important.Count) security/critical. Install: .\services.ps1 -InstallUpdates"
        }
    } else { Stop-Job $job; Warn 'Windows Update search timed out - try again later or check connectivity' }
    Remove-Job $job -Force -ErrorAction SilentlyContinue
}
if ($InstallUpdates) {
    Write-Host 'Searching for Security / Critical updates (can take several minutes)...'
    Write-Host 'Installing updates can restart services. Nothing reboots automatically.' -ForegroundColor Yellow
    try {
        $session = New-Object -ComObject Microsoft.Update.Session
        $res = $session.CreateUpdateSearcher().Search($wuQuery)
        $coll = New-Object -ComObject Microsoft.Update.UpdateColl
        foreach ($u in $res.Updates) {
            $cats = (@($u.Categories) | ForEach-Object { $_.Name }) -join ', '
            if ($u.MsrcSeverity -notin 'Critical', 'Important' -and $cats -notmatch 'Security|Critical') { continue }
            if (Ask "Install $($u.Title)?") { if (-not $u.EulaAccepted) { $u.AcceptEula() }; [void]$coll.Add($u) }
        }
        if ($coll.Count -gt 0) {
            $dl = $session.CreateUpdateDownloader(); $dl.Updates = $coll; [void]$dl.Download()
            $inst = $session.CreateUpdateInstaller(); $inst.Updates = $coll
            $r = $inst.Install()
            for ($i = 0; $i -lt $coll.Count; $i++) {
                $code = $r.GetUpdateResult($i).ResultCode   # 2 = succeeded, 3 = succeeded with errors
                Info ("{0}  {1}" -f $(if ($code -in 2, 3) { 'OK    ' } else { 'FAILED' }), $coll.Item($i).Title)
                Record "update $($coll.Item($i).Title)" 'pending' "result $code"
            }
            if ($r.RebootRequired) { Warn 'A reboot is required to finish - plan it with the captain, then check every scored service.' }
            Write-Host 'If the file integrity monitor alerts on updated System32 files: .\fim.ps1 accept -Path <file>'
        } else { Info 'Nothing selected.' }
    } catch { Warn "Windows Update failed: $($_.Exception.Message)" }
}

# ------------------------------------------------------------------ summary
H1 'SUMMARY'
Write-Host "Legacy/insecure: $script:Crit   Warnings: $script:Warn   Log: $Log$(if (Test-Path $Undo) { "   Undo record: $Undo" })"
if ($script:Crit -and -not $Fix) { Write-Host 'Remove them: .\services.ps1 -Fix (asks per item)' }
Stop-Transcript | Out-Null
if ($script:Crit) { exit 2 } elseif ($script:Warn) { exit 1 } else { exit 0 }
