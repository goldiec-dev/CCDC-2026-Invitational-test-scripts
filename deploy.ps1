<#
.SYNOPSIS
Lock down one Windows machine, in order, from ccdc.conf. The Windows twin of deploy.sh.

.DESCRIPTION
Steps, in order (each one asks before it runs; a failed step doesn't stop the rest):
  passwords  change every local password + password policy      windows\passwords.ps1
             (role dc: every DOMAIN password + domain policy       windows\ad_passwords.ps1)
Roles (2026): dc (Server 2022 AD/DNS), mssql (Server 2019 SQL Server), workstation (Windows 11)
       older topologies: web (IIS server), ftp (FTP server)
  harden     baseline hardening, keeps RDP on with NLA, allows the  windows\harden.ps1
             role's scored ports before turning the firewall on
  secure     harden the scored services, testing each and undoing   windows\secure.ps1
  cis        CIS Level 1 controls not covered above, asks per section windows\cis.ps1
             a section whose test fails (dc: DNS, WinRM; mssql: SMB, RDP, SQL Server)
  forwarder  install the Splunk forwarder, send Windows event logs to SPLUNK:9997
  audit      backdoor/persistence hunt, asks before each fix     windows\audit.ps1 -Fix
  services   legacy features/services/protocols (SMB1, PSv2, Telnet, SNMP, TLS 1.0...), asks
             before removing each; lists pending Windows updates  windows\services.ps1 -Fix
  webguard   (web role) baseline the IIS site after the audit cleaned it, then watch
             it from a SYSTEM scheduled task (CCDC-WebGuard)    windows\webguard.ps1
  beacon     watch outbound TCP for anything calling home on a timer (task CCDC-Beacon)
  fim        baseline hosts file, tasks, startup folders, profiles, System32 programs
             (IIS config on web), then watch them from task CCDC-FIM   windows\fim.ps1

Reads from ccdc.conf: CONFIG_REVIEWED, SCORED_USERS, SPLUNK, WEBGUARD_AUTO_RESTORE,
WIN_WEBROOT, WIN_EXPECTED_ADMINS, WIN_FIM_EXTRA_PATHS, FIM_INTERVAL, INSIDE, BEACON_ALLOW.
Log: C:\ProgramData\CCDC\deploy-<time>.log (Administrators only; it includes scored
users' new passwords).

.EXAMPLE
powershell -ExecutionPolicy Bypass -File .\deploy.ps1 -Role mssql
.\deploy.ps1 -Role workstation -Only audit
.\deploy.ps1 -Role dc -Skip forwarder
#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('workstation', 'web', 'dc', 'ftp', 'mssql')]
    [string]$Role,
    [string[]]$Only = @(),
    [string[]]$Skip = @()
)

$ErrorActionPreference = 'Continue'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this from an elevated (Administrator) PowerShell.' -ForegroundColor Red; exit 1 }

$Here      = $PSScriptRoot
$Conf      = Join-Path $Here 'ccdc.conf'
$Passwords = Join-Path $Here 'windows\passwords.ps1'
$Harden    = Join-Path $Here 'windows\harden.ps1'
$Audit     = Join-Path $Here 'windows\audit.ps1'
$WebGuard  = Join-Path $Here 'windows\webguard.ps1'
$Fim       = Join-Path $Here 'windows\fim.ps1'
$Beacon    = Join-Path $Here 'windows\beacon.ps1'
$Services  = Join-Path $Here 'windows\services.ps1'
$Secure    = Join-Path $Here 'windows\secure.ps1'
$Cis       = Join-Path $Here 'windows\cis.ps1'
$AllSteps  = 'passwords', 'harden', 'secure', 'cis', 'forwarder', 'audit', 'services', 'webguard', 'beacon', 'fim'

foreach ($f in $Conf, $Passwords, $Harden, $Audit, $WebGuard, $Fim, $Beacon, $Services, $Secure, $Cis) {
    if (-not (Test-Path -LiteralPath $f)) { Write-Host "Missing $f - copy the whole scripts folder" -ForegroundColor Red; exit 1 }
}
foreach ($s in @($Only) + @($Skip)) {
    if ($s -and $AllSteps -notcontains $s) { Write-Host "Unknown step '$s'. Steps: $($AllSteps -join ', ')" -ForegroundColor Red; exit 1 }
}
# Files copied from the internet are "blocked"; this script runs them with Bypass anyway
Get-ChildItem -LiteralPath (Join-Path $Here 'windows') -Recurse -Filter *.ps1 |
    Unblock-File -ErrorAction SilentlyContinue

# ------------------------------------------------------------------ ccdc.conf
# ccdc.conf is a bash file: NAME=value and NAME=( ... ) arrays, which may span lines and carry # comments
function Read-Conf([string]$Path) {
    $conf = @{}
    $lines = @(Get-Content -LiteralPath $Path)
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -notmatch '^\s*([A-Za-z_][A-Za-z0-9_]*)=(.*)$') { continue }
        $name = $Matches[1]; $v = $Matches[2].Trim()
        if ($v.StartsWith('(')) {
            # words: "quoted", 'quoted' or bare; # outside quotes = comment to the end of the line; ) ends it
            $items = @(); $done = $false; $text = $v.Substring(1)
            while ($true) {
                foreach ($m in [regex]::Matches($text, '"([^"]*)"|''([^'']*)''|(#.*$)|(\))|([^\s"''#)]+)')) {
                    if ($m.Groups[3].Success) { break }
                    if ($m.Groups[4].Success) { $done = $true; break }
                    $items += $m.Groups[1].Value + $m.Groups[2].Value + $m.Groups[5].Value
                }
                if ($done -or $i + 1 -ge $lines.Count) { break }
                $i++; $text = $lines[$i]
            }
            $conf[$name] = $items
        } elseif ($v -match '^"([^"]*)"') { $conf[$name] = $Matches[1] }
        elseif ($v -match "^'([^']*)'") { $conf[$name] = $Matches[1] }
        else { $conf[$name] = ($v -split '\s+|#')[0] }
    }
    $conf
}
$C = Read-Conf $Conf
if ($C['CONFIG_REVIEWED'] -ne 'yes') {
    Write-Host "Check every value in $Conf for this year's topology, then set CONFIG_REVIEWED=yes." -ForegroundColor Yellow
    exit 1
}
if ($Role -eq 'dc') {
    # On the DC the scored users are domain accounts (e.g. POP3 mailboxes use AD usernames)
    $ScoredUsers = @($C['SCORED_USERS'] | Where-Object { $_ })
} else {
    $localNames  = @(Get-LocalUser | ForEach-Object Name)
    $ScoredUsers = @($C['SCORED_USERS'] | Where-Object { $_ -and $localNames -contains $_ })   # the list also has Linux users
}
$AdPasswords    = Join-Path $Here 'windows\ad_passwords.ps1'
$ExpectedAdmins = @($C['WIN_EXPECTED_ADMINS'] | Where-Object { $_ })
$WebRoot        = if ($C['WIN_WEBROOT']) { $C['WIN_WEBROOT'] } else { 'C:\inetpub\wwwroot' }
$Splunk         = $C['SPLUNK']
$FimExtra       = @($C['WIN_FIM_EXTRA_PATHS'] | Where-Object { $_ })
$BeaconAllow    = @($C['BEACON_ALLOW'] | Where-Object { $_ })
if ($Splunk) { $BeaconAllow += "${Splunk}:9997", "${Splunk}:8089" }
if ($C['WAZUH']) { $BeaconAllow += "$($C['WAZUH']):1514", "$($C['WAZUH']):1515" }
$Inside         = @("$($C['INSIDE'])" -split '\s+' | Where-Object { $_ })
$FimInterval    = if ($C['FIM_INTERVAL'] -match '^\d+$') { $C['FIM_INTERVAL'] } else { '60' }

# ------------------------------------------------------------------ log
$OutDir = "$env:ProgramData\CCDC"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
icacls $OutDir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
$Log = Join-Path $OutDir "deploy-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
Start-Transcript -LiteralPath $Log | Out-Null

function Ask([string]$Question, [bool]$Default) {
    $hint = if ($Default) { '[Y/n]' } else { '[y/N]' }
    $a = Read-Host "$Question $hint"
    if (-not $a) { return $Default }
    return $a -match '^[Yy]'
}

function Wanted([string]$Step) {
    if ($Only.Count -gt 0 -and $Only -notcontains $Step) { return $false }
    return $Skip -notcontains $Step
}

# How many lines match a failure pattern in the log a child script wrote during this step
function Count-Failures([string]$Prefix, [string]$Pattern, [datetime]$Since) {
    $f = Get-ChildItem -LiteralPath $OutDir -Filter "$Prefix-*.log" -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -ge $Since } | Sort-Object LastWriteTime | Select-Object -Last 1
    if (-not $f) { return 0 }
    @(Select-String -LiteralPath $f.FullName -Pattern $Pattern).Count
}

# Run a watcher script from a SYSTEM scheduled task so it survives logoff and reboot.
# No hidden-window flags: audit.ps1 rightly treats those as suspicious.
# SYSTEM tasks must not run scripts that ordinary users can edit (folders created under C:\
# are user-writable by default). Copy the watchers into the admin-only C:\ProgramData\CCDC\bin,
# record their hashes, and point the tasks there. fim.ps1 watches this folder.
$Bin = Join-Path $OutDir 'bin'
function Install-Watcher([string]$Source) {
    New-Item -ItemType Directory -Force -Path $Bin | Out-Null
    $dest = Join-Path $Bin (Split-Path $Source -Leaf)
    Copy-Item -LiteralPath $Source -Destination $dest -Force
    Get-ChildItem -LiteralPath $Bin -Filter *.ps1 | Get-FileHash -Algorithm SHA256 |
        ForEach-Object { "$($_.Hash)  $(Split-Path $_.Path -Leaf)" } | Set-Content -LiteralPath (Join-Path $Bin 'SHA256SUMS.txt')
    $dest
}

function Register-WatchTask([string]$Name, [string]$Arguments) {
    Unregister-ScheduledTask -TaskName $Name -Confirm:$false -ErrorAction SilentlyContinue
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 `
        -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $Name -Settings $settings `
        -Action (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass $Arguments") `
        -Trigger (New-ScheduledTaskTrigger -AtStartup) `
        -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) | Out-Null
}
function Start-WatchTask([string]$Name) {
    Start-ScheduledTask -TaskName $Name
    Start-Sleep -Seconds 3
    (Get-ScheduledTask -TaskName $Name).State
}

# ------------------------------------------------------------------ steps
# Each returns a status string for the summary. Child scripts are piped to Out-Host
# so their output is shown instead of being captured as the step's return value.

function Step-Passwords {
    if ($ScoredUsers) { Write-Host "Scored users on this machine: $($ScoredUsers -join ', ')" -ForegroundColor Cyan }
    else { Write-Host 'No SCORED_USERS from ccdc.conf exist on this machine.' -ForegroundColor Yellow }
    $start = Get-Date
    if ($Role -eq 'dc') {
        $p = @{ ScoredUsers = $ScoredUsers }
        if ($ExpectedAdmins) { $p.ExpectedAdmins = $ExpectedAdmins }
        & $AdPasswords @p | Out-Host
        $n = Count-Failures 'ad-passwords' 'FAILED' $start
        if ($n) { return "done, $n FAILURE(S) - see the ad-passwords log" }
        return 'done - submit scored users'' new passwords (Quotient PCR); run passwords.ps1 on member servers too'
    }
    & $Passwords -ScoredUsers $ScoredUsers | Out-Host
    $n = Count-Failures 'passwords' 'FAILED' $start
    if ($n) { return "done, $n FAILURE(S) - see the passwords log" }
    'done - submit scored users'' new passwords (Quotient PCR)'
}

function Step-Harden {
    $start = Get-Date
    & $Harden -Role $Role | Out-Host
    $n = Count-Failures 'harden' '\] FAIL ' $start
    if ($n) { return "done, $n setting(s) FAILED - see the harden log" }
    'done (reboot later for LSA protection)'
}

function Step-Secure {
    $global:LASTEXITCODE = 0
    & $Secure -Role $Role -Inside $Inside | Out-Host
    if ($LASTEXITCODE) { return 'done with PROBLEMS - see the secure log (failed sections were undone)' }
    'done - check Quotient: every service still up?'
}

function Step-Cis {
    $global:LASTEXITCODE = 0
    & $Cis -Role $Role -Fix | Out-Host
    if ($LASTEXITCODE) { return 'done - some CIS controls still not passing (see the cis log; deviations in checklists\CIS.md)' }
    'done - every CIS control passes'
}

function Step-Forwarder {
    if (Get-Service -Name SplunkForwarder -ErrorAction SilentlyContinue) {
        Write-Host 'The Splunk forwarder is already installed. Check its outputs.conf points at the right server.'
        return 'already installed'
    }
    if (-not $Splunk) { Write-Host 'SPLUNK is not set in ccdc.conf'; return 'FAILED - SPLUNK not set' }
    # Splunk 10.0.2 forwarder (2026 Splunk server is 10.0.2 - forwarders must be the same or older)
    $ufName = 'splunkforwarder-10.0.2-e2d18b4767e9-windows-x64.msi'
    $ufUrl  = "https://download.splunk.com/products/universalforwarder/releases/10.0.2/windows/$ufName"
    $msi = Get-ChildItem -LiteralPath (Join-Path $Here 'installers\splunk') -Filter 'splunkforwarder-*x64*.msi' -ErrorAction SilentlyContinue |
        Sort-Object { [version](($_.Name -split '-')[1]) } -Descending | Select-Object -First 1
    if (-not $msi) {
        Write-Host "No forwarder .msi in installers\splunk - downloading $ufName ..."
        $dest = Join-Path $OutDir $ufName
        try {
            [Net.ServicePointManager]::SecurityProtocol = 'Tls12'
            Invoke-WebRequest $ufUrl -OutFile $dest -UseBasicParsing
            $expected = ([regex]::Match((Invoke-WebRequest "$ufUrl.sha512" -UseBasicParsing).Content, '[0-9a-fA-F]{128}')).Value
            if ((Get-FileHash $dest -Algorithm SHA512).Hash -ne $expected) { Remove-Item $dest; return 'FAILED - downloaded installer failed the SHA-512 check' }
            $msi = Get-Item $dest
        } catch { Write-Host "Download failed (proxy?): $($_.Exception.Message)"; return 'FAILED - installer missing' }
    }
    if (-not (Test-NetConnection -ComputerName $Splunk -Port 9997 -InformationLevel Quiet -WarningAction SilentlyContinue)) {
        Write-Host "Can't reach $Splunk on port 9997 right now (Splunk receiving off, or a firewall). Installing anyway; it will retry." -ForegroundColor Yellow
    }
    Write-Host "Installing $($msi.Name), sending to ${Splunk}:9997 ..."
    # GENRANDOMPASSWORD: the forwarder's local admin gets a random password, never a default one
    $msiArgs = "/i `"$($msi.FullName)`" RECEIVING_INDEXER=`"${Splunk}:9997`" AGREETOLICENSE=yes GENRANDOMPASSWORD=1 " +
            'WINEVENTLOG_APP_ENABLE=1 WINEVENTLOG_SEC_ENABLE=1 WINEVENTLOG_SYS_ENABLE=1 /quiet /norestart ' +
            "/l*v `"$OutDir\splunkforwarder-install.log`""
    $p = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
    if ($p.ExitCode -in 0, 3010) { return 'done' }
    "FAILED - msiexec exit $($p.ExitCode), see $OutDir\splunkforwarder-install.log"
}

function Step-Audit {
    $params = @{ Fix = $true }
    if ($ExpectedAdmins) { $params.ExpectedAdmins = $ExpectedAdmins }
    $global:LASTEXITCODE = 0
    & $Audit @params | Out-Host
    switch ($LASTEXITCODE) {
        0 { 'done - nothing found' }
        1 { 'done - warnings to review' }
        2 { 'done - CRITICAL findings (check what you didn''t fix)' }
        default { "FAILED - exit $LASTEXITCODE" }
    }
}

function Step-Services {
    $global:LASTEXITCODE = 0
    & $Services -Role $Role -Fix | Out-Host
    switch ($LASTEXITCODE) {
        0 { 'done - nothing legacy found' }
        1 { 'done - warnings / pending updates to review' }
        2 { 'done - legacy items found (check what you kept)' }
        default { "FAILED - exit $LASTEXITCODE" }
    }
}

function Step-WebGuard {
    if ($Role -ne 'web') { Write-Host 'Not a web server'; return 'not needed' }
    if (Get-Module -ListAvailable -Name WebAdministration) {
        Import-Module WebAdministration
        $sites = @(Get-Website)
        Write-Host 'IIS sites:'
        $sites | ForEach-Object { Write-Host "    $($_.Name)  ->  $([Environment]::ExpandEnvironmentVariables($_.PhysicalPath))" }
        if ($sites.Count -gt 1) {
            Write-Host "Only $WebRoot is baselined. For another site: webguard.ps1 init/watch -WebRoot <its path>" -ForegroundColor Yellow
        }
    }
    if (-not (Test-Path -LiteralPath $WebRoot)) { Write-Host "No web root at $WebRoot - set WIN_WEBROOT in ccdc.conf"; return 'FAILED - web root not found' }
    Write-Host 'Open the site in a browser NOW. The baseline is what webguard restores, so it must be clean.'
    if (-not (Ask 'Does the site look right?' $false)) { Write-Host 'Fix the site first, then: -Only webguard'; return 'postponed' }

    $global:LASTEXITCODE = 0
    & $WebGuard init -WebRoot $WebRoot | Out-Host
    if ($LASTEXITCODE) { return "FAILED - webguard init exit $LASTEXITCODE" }

    $taskArgs = "-File `"$(Install-Watcher $WebGuard)`" watch -WebRoot `"$WebRoot`""
    if ($C['WEBGUARD_AUTO_RESTORE'] -eq 'yes') { $taskArgs += ' -AutoRestore' }
    Register-WatchTask 'CCDC-WebGuard' $taskArgs
    $state = Start-WatchTask 'CCDC-WebGuard'
    Write-Host "webguard task state: $state. Alerts: Event Viewer > Application, source WebGuard. Stop it: Stop-ScheduledTask CCDC-WebGuard"
    if ($state -ne 'Running') { return "FAILED - task is $state" }
    'done - watching'
}

function Step-Beacon {
    # Runs before the fim step: registering the task adds a file to System32\Tasks
    $taskArgs = "-File `"$(Install-Watcher $Beacon)`" watch"
    if ($BeaconAllow) { $taskArgs += " -Allow $($BeaconAllow -join ',')" }
    if ($Inside) { $taskArgs += " -Inside $($Inside -join ',')" }
    Register-WatchTask 'CCDC-Beacon' $taskArgs
    $state = Start-WatchTask 'CCDC-Beacon'
    Write-Host "beacon task state: $state. Alerts: Event Viewer > Application, source CCDC-Beacon. Table: .\windows\beacon.ps1 report"
    if ($state -ne 'Running') { return "FAILED - task is $state" }
    'done - watching'
}

function Step-Fim {
    $params = @{ Role = $(if ($Role -in 'web', 'ftp') { 'web' } else { 'workstation' }) }   # web: also watch IIS config
    if ($FimExtra) { $params.ExtraPaths = $FimExtra }
    # Register the task before the baseline: its file lands in System32\Tasks, a watched folder.
    # The baseline remembers role and extra paths, so watch needs only the interval.
    Stop-ScheduledTask -TaskName 'CCDC-FIM' -ErrorAction SilentlyContinue
    Register-WatchTask 'CCDC-FIM' "-File `"$(Install-Watcher $Fim)`" watch -Interval $FimInterval"
    $global:LASTEXITCODE = 0
    & $Fim init @params | Out-Host
    if ($LASTEXITCODE) { return "FAILED - fim init exit $LASTEXITCODE" }
    $state = Start-WatchTask 'CCDC-FIM'
    Write-Host "fim task state: $state. Alerts: Event Viewer > Application, source CCDC-FIM. Stop it: Stop-ScheduledTask CCDC-FIM"
    if ($state -ne 'Running') { return "FAILED - task is $state" }
    'done - watching'
}

# ------------------------------------------------------------------ run
Write-Host "=== CCDC deploy: $env:COMPUTERNAME, role $Role, $(Get-Date) ===" -ForegroundColor Cyan
$Result = [ordered]@{}
foreach ($step in $AllSteps) {
    if (-not (Wanted $step)) { $Result[$step] = 'skipped'; continue }
    Write-Host "`n################ $step ################" -ForegroundColor Cyan
    if (-not (Ask "Run $step now?" $true)) { $Result[$step] = 'skipped by you'; continue }
    try {
        $out = & "Step-$step"
        $Result[$step] = @($out)[-1]   # the status is the last thing a step returns
    } catch {
        Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
        $Result[$step] = 'FAILED - see log'
    }
}

Write-Host "`n################ summary ################" -ForegroundColor Cyan
foreach ($k in $Result.Keys) { Write-Host ('  {0,-10} {1}' -f $k, $Result[$k]) }
Write-Host @"

Log:       $Log
Passwords: $OutDir\passwords-*.csv (submit scored users' changes)
Next:
  - Web app / database / CMS admin passwords and SQL Server logins (sa...): no script changes
    these (see the checklist)
  - Re-run the hunt every so often:  .\windows\audit.ps1
  - Beacons (anything calling home on a timer):  .\windows\beacon.ps1 report
  - Our watchers unchanged? compare  Get-FileHash C:\ProgramData\CCDC\bin\*.ps1  with bin\SHA256SUMS.txt
  - Evidence for injects:  .\windows\evidence.ps1
  - After changing a watched file on purpose, stop the alerts:  .\windows\fim.ps1 accept -Path <file>
"@
Stop-Transcript | Out-Null
