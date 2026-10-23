<#
.SYNOPSIS
Collect evidence for the initial injects in one report (Windows 11 / Server 2019).

.DESCRIPTION
Read-only, except the two optional tests. Screenshot the output or paste it into the inject memo.
Report: C:\ProgramData\CCDC\evidence-<host>-<time>.txt

  -Section   any of: system, time, network, firewall, startup, fim, logging, traffic (default: all)
  -FimTest   prove file integrity monitoring works: create a test file in the hosts-file folder,
             show fim.ps1 detecting it, delete it, show it clears
  -LogTest   write a uniquely tagged test event to the Application log, to find in Splunk/Wazuh
  -Splunk / -Wazuh / -Dns   IPs to test connectivity to (deploy.ps1 users: same as ccdc.conf)

.EXAMPLE
.\evidence.ps1 -FimTest -LogTest -Splunk 172.20.240.20
#>
param(
    [string[]]$Section = @('system', 'time', 'network', 'firewall', 'startup', 'fim', 'logging', 'traffic'),
    [switch]$FimTest,
    [switch]$LogTest,
    [string]$Splunk = '',
    [string]$Wazuh = '',
    [string]$Dns = ''
)

$ErrorActionPreference = 'Continue'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this from an elevated (Administrator) PowerShell.' -ForegroundColor Red; exit 1 }

$Section = @($Section -split ',' | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ })
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$OutDir = "$env:ProgramData\CCDC"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Out = Join-Path $OutDir "evidence-$env:COMPUTERNAME-$Stamp.txt"
Start-Transcript -LiteralPath $Out | Out-Null

function H1([string]$t) { Write-Host "`n==================== $t ====================" -ForegroundColor Cyan }
function Run([string]$Label, [scriptblock]$Block) {
    Write-Host "`nPS> $Label" -ForegroundColor DarkGray
    try { & $Block | Out-String -Width 220 | Write-Host } catch { Write-Host "  (failed: $($_.Exception.Message))" }
}
function Test-Port([string]$Ip, [int]$Port) {
    if (-not $Ip) { return }
    $ok = Test-NetConnection -ComputerName $Ip -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue
    Write-Host ("{0}  {1}:{2}" -f $(if ($ok) { 'OK  ' } else { 'FAIL' }), $Ip, $Port)
}
function Want([string]$s) { $Section -contains $s }

Write-Host "CCDC evidence report - $env:COMPUTERNAME - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')"

# ------------------------------------------------------------------ system
if (Want 'system') {
    H1 'SYSTEM'
    Run 'OS' { Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, LastBootUpTime }
    Run 'Get-NetIPAddress (IPv4)' { Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -ne '127.0.0.1' | Select-Object InterfaceAlias, IPAddress, PrefixLength }
    Run 'Domain' { Get-CimInstance Win32_ComputerSystem | Select-Object Name, Domain, PartOfDomain }
}

# ------------------------------------------------------------------ time
if (Want 'time') {
    H1 'TIME SYNCHRONIZATION (NTP / PTP)'
    Run 'w32tm /query /status' { w32tm /query /status }
    Run 'w32tm /query /source' { w32tm /query /source }
    Run 'w32tm /query /configuration (providers)' { w32tm /query /configuration | Select-String -Pattern 'NtpClient|NtpServer|PtpClient|Enabled|Type:' }
}

# ------------------------------------------------------------------ network
if (Want 'network') {
    H1 'NETWORK CONNECTIVITY'
    Run 'Get-NetRoute (default)' { Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Select-Object InterfaceAlias, NextHop, RouteMetric }
    $gw = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -First 1).NextHop
    if ($gw) { Run "ping gateway $gw" { Test-Connection -ComputerName $gw -Count 2 | Select-Object Address, ResponseTime, StatusCode } }
    Run 'DNS servers' { Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object ServerAddresses | Select-Object InterfaceAlias, ServerAddresses }
    Run 'Resolve-DnsName www.google.com' { Resolve-DnsName www.google.com -ErrorAction Stop | Select-Object -First 2 Name, IPAddress }
    Write-Host "`nRequired services:"
    Test-Port $Dns 53; Test-Port $Splunk 9997; Test-Port $Wazuh 1514; Test-Port '1.1.1.1' 443
}

# ------------------------------------------------------------------ firewall
if (Want 'firewall') {
    H1 'HOST FIREWALL POLICY'
    Run 'Get-NetFirewallProfile' { Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogBlocked, LogFileName }
    Write-Host "`nInbound ALLOW rules that are enabled (name, program, protocol, local ports, remote addresses):"
    Run 'enabled inbound allow rules' {
        Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | ForEach-Object {
            $pf = $_ | Get-NetFirewallPortFilter; $af = $_ | Get-NetFirewallAddressFilter; $ap = $_ | Get-NetFirewallApplicationFilter
            [pscustomobject]@{ Rule = $_.DisplayName; Profile = $_.Profile; Program = $ap.Program; Proto = $pf.Protocol; LocalPort = ($pf.LocalPort -join ','); Remote = ($af.RemoteAddress -join ',') }
        } | Sort-Object LocalPort | Format-Table -AutoSize
    }
    Write-Host "Deny-by-default with logging (threat hunting): default inbound action Block + LogBlocked True on every profile."
    $log = "$env:SystemRoot\System32\LogFiles\Firewall\pfirewall.log"
    if (Test-Path $log) {
        $drops = @(Get-Content $log -Tail 5000 | Select-String ' DROP ')
        Write-Host "Dropped packets in the last 5000 log lines: $($drops.Count)"
        $drops | Select-Object -Last 5 | ForEach-Object { Write-Host "  $_" }
    } else { Write-Host "No firewall log at $log - run harden.ps1 (it enables drop logging)" }
}

# ------------------------------------------------------------------ startup
if (Want 'startup') {
    H1 'STARTUP SCRIPTS AND THEIR INTEGRITY'
    Run 'Our watcher tasks (start at boot as SYSTEM)' {
        Get-ScheduledTask -TaskName 'CCDC-*' -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{ Task = $_.TaskName; State = $_.State; Trigger = ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName -replace 'MSFT_Task|Trigger', '' }) -join ','
                               RunAs = $_.Principal.UserId; Command = "$($_.Actions[0].Execute) $($_.Actions[0].Arguments)" }
        } | Format-List
    }
    $bin = Join-Path $OutDir 'bin'
    $sums = Join-Path $bin 'SHA256SUMS.txt'
    if (Test-Path $sums) {
        Write-Host "`nIntegrity of the installed watcher scripts ($bin):"
        foreach ($line in Get-Content $sums) {
            $hash, $name = $line -split '\s+', 2
            $now = (Get-FileHash -LiteralPath (Join-Path $bin $name) -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
            Write-Host ("  {0,-14} {1}" -f $name, $(if ($now -eq $hash) { 'OK' } else { 'CHANGED OR MISSING' }))
        }
        Run 'Who can modify the watcher folder (should be Administrators and SYSTEM only)' { icacls $bin }
    } else { Write-Host "  $bin not installed - run deploy.ps1 (webguard / beacon / fim steps)" }
    Run 'Other startup commands (review for persistence)' { Get-CimInstance Win32_StartupCommand | Select-Object Name, Command, Location, User | Format-Table -AutoSize }
    Run 'Auto-start services not in C:\Windows (review)' {
        Get-CimInstance Win32_Service -Filter "StartMode='Auto'" | Where-Object { $_.PathName -notmatch '(?i)\\Windows\\' } | Select-Object Name, State, StartName, PathName | Format-Table -AutoSize
    }
}

# ------------------------------------------------------------------ fim
if (Want 'fim') {
    H1 'FILE INTEGRITY MONITORING'
    $fim = Join-Path $OutDir 'bin\fim.ps1'; if (-not (Test-Path $fim)) { $fim = Join-Path $PSScriptRoot 'fim.ps1' }
    Run 'Task CCDC-FIM' { Get-ScheduledTask -TaskName 'CCDC-FIM' -ErrorAction SilentlyContinue | Select-Object TaskName, State }
    $base = "$OutDir\fim\baseline.csv"
    if (Test-Path $base) { Write-Host "Baseline: $(@(Import-Csv $base).Count) files, taken $((Get-Item $base).LastWriteTime)" }
    if ($FimTest) {
        $t = "$env:SystemRoot\System32\drivers\etc\ccdc-fim-proof-$Stamp.txt"
        Write-Host "`n--- FIM proof: create $t, detect it, remove it"
        Set-Content -LiteralPath $t -Value "CCDC file integrity test $Stamp"
        Run 'fim.ps1 check' { & $fim check }
        Remove-Item -LiteralPath $t -Force
        Write-Host "--- test file removed; check again (expect 'No changes.' unless something else changed):"
        Run 'fim.ps1 check' { & $fim check }
    } else { Write-Host '(add -FimTest for a live detection demo)' }
    Run 'Recent CCDC-FIM events' { Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'CCDC-FIM' } -MaxEvents 10 -ErrorAction Stop | Select-Object TimeCreated, Message | Format-Table -Wrap }
}

# ------------------------------------------------------------------ logging
if (Want 'logging') {
    H1 'CENTRALIZED LOGGING'
    Run 'Log shipping services' { Get-Service -Name WazuhSvc, SplunkForwarder, EventLog -ErrorAction SilentlyContinue | Select-Object Name, Status, StartType }
    Run 'Live connections to log collectors (1514 Wazuh, 9997 Splunk)' {
        Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemotePort -in 1514, 9997 } |
            Select-Object LocalAddress, RemoteAddress, RemotePort, @{ n = 'Process'; e = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } }
    }
    if ($LogTest) {
        $id = "ccdc-logtest-$env:COMPUTERNAME-$Stamp"
        if (-not [Diagnostics.EventLog]::SourceExists('CCDC-Evidence')) { New-EventLog -LogName Application -Source CCDC-Evidence }
        Write-EventLog -LogName Application -Source CCDC-Evidence -EventId 4900 -EntryType Information -Message "CCDC centralized logging test id=$id"
        Write-Host "`nWrote test event id=$id (Application log, source CCDC-Evidence). Find it and screenshot it:"
        Write-Host "  Splunk: index=* `"$id`""
        Write-Host "  Wazuh:  Discover / Threat Hunting, search `"$id`""
    } else { Write-Host '(add -LogTest to write a tagged test event to find in Splunk/Wazuh)' }
}

# ------------------------------------------------------------------ traffic
if (Want 'traffic') {
    H1 'TRAFFIC PROFILE'
    $procs = @{}; Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
    Run 'Listening ports' {
        Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, @{ n = 'Process'; e = { $procs[[int]$_.OwningProcess] } } | Sort-Object LocalPort -Unique | Format-Table -AutoSize
    }
    Run 'Established connections by remote address and program' {
        Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1)' } |
            Group-Object RemoteAddress, @{ e = { $procs[[int]$_.OwningProcess] } } | Sort-Object Count -Descending |
            Select-Object -First 25 Count, @{ n = 'Remote, Program'; e = { $_.Name } } | Format-Table -AutoSize
    }
    Run 'Outbound SSH (remote port 22 or an ssh client)' {
        $hits = Get-NetTCPConnection -State Established | Where-Object {
            $_.RemotePort -eq 22 -or $procs[[int]$_.OwningProcess] -match '^(ssh|plink|putty)$' }
        if ($hits) { $hits | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, @{ n = 'Process'; e = { $procs[[int]$_.OwningProcess] } } }
        else { 'No outbound SSH connections.' }
    }
    $beacon = Join-Path $OutDir 'bin\beacon.ps1'; if (-not (Test-Path $beacon)) { $beacon = Join-Path $PSScriptRoot 'beacon.ps1' }
    if (Test-Path "$OutDir\beacon\events.csv") { Run 'beacon.ps1 report' { & $beacon report } }
}

Write-Host "`nReport saved: $Out"
Stop-Transcript | Out-Null
