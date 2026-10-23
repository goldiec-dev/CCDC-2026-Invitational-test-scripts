<#
.SYNOPSIS
Beacon detector: find outbound connections that repeat on a timer (malware calling home
every N seconds), and the program making them. Windows 11 / Server 2019.

.DESCRIPTION
  watch    Record every new outbound TCP connection (polled every -Interval seconds) and
           check for beacons every minute. Runs until stopped (deploy.ps1 runs it as the
           SYSTEM task CCDC-Beacon).
  report   Show every repeating destination recorded so far, beacons first. Works while
           watch is running.

A destination (IP, port) is a BEACON when at least 80% of the gaps between connections to
it are within 25% of the typical gap, the gap is -MinGap seconds or more, and there are at
least -MinHits connections. "maybe" (50-80% regular) is worth a look too.

Polls Get-NetTCPConnection, which also lists recently closed connections (TIME_WAIT), so
most short connections are still seen. TCP only. Windows itself has some regular traffic
(Defender, Windows Update, OneDrive, time sync): the report shows each program's path and
signer so those are quick to rule out. Report-only: nothing is blocked. Alerts go to the
Application event log (source CCDC-Beacon, event 4400) so Splunk sees them.

.EXAMPLE
.\beacon.ps1 watch -Allow '172.20.240.20:9997'
.\beacon.ps1 report
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('watch', 'report')]
    [string]$Command,
    [int]$Interval = 2,
    [int]$Window = 7200,
    [int]$MinHits = 8,
    [int]$MinGap = 10,
    [string[]]$Allow = @(),      # 'IP', 'IP:PORT' or ':PORT' - expected regular traffic
    [string[]]$Inside = @(),     # team subnets (CIDR), shown as scope "team"
    [string]$Store = "$env:ProgramData\CCDC\beacon"
)

$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this from an elevated (Administrator) PowerShell.' -ForegroundColor Red; exit 1 }

# Values may arrive comma-joined when run from a scheduled task (-File passes plain strings)
$Allow  = @($Allow  -split ',' | Where-Object { $_ })
$Inside = @($Inside -split ',' | Where-Object { $_ })

$Tolerance = 0.25
$Regular   = 0.8
$Events    = Join-Path $Store 'events.csv'
$LogFile   = Join-Path $Store 'beacon.log'
if (-not (Test-Path -LiteralPath $Store)) {
    New-Item -ItemType Directory -Force -Path $Store | Out-Null
    icacls $Store /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
}
if (-not (Test-Path -LiteralPath $Events)) { Set-Content -LiteralPath $Events -Value 'Ts,Proto,Dst,Port,Proc' }

# Expected regular traffic: NTP and DNS to our own resolvers
$AllowList = @(':123') + $Allow
try {
    Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop |
        ForEach-Object { $_.ServerAddresses } | Sort-Object -Unique | ForEach-Object { $AllowList += "${_}:53" }
} catch { }

function Write-Log([string]$Message) {
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Write-Host $line
    Add-Content -LiteralPath $LogFile -Value $line -ErrorAction SilentlyContinue
    try {
        if (-not [Diagnostics.EventLog]::SourceExists('CCDC-Beacon')) { New-EventLog -LogName Application -Source CCDC-Beacon }
        Write-EventLog -LogName Application -Source CCDC-Beacon -EventId 4400 -EntryType Warning -Message $Message
    } catch { }
}

function Get-Now { [int64]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) }

function Test-Allowed([string]$Ip, [string]$Port) {
    foreach ($a in $AllowList) { if ($a -eq ":$Port" -or $a -eq $Ip -or $a -eq "${Ip}:$Port") { return $true } }
    $false
}

function Get-Scope([string]$Ip) {
    $addr = $null
    if (-not [Net.IPAddress]::TryParse($Ip, [ref]$addr) -or $addr.AddressFamily -ne 'InterNetwork') { return 'ipv6' }
    $b = $addr.GetAddressBytes(); [array]::Reverse($b); $n = [BitConverter]::ToUInt32($b, 0)
    foreach ($c in $Inside) {
        $parts = $c -split '/'; $bits = if ($parts.Count -gt 1) { [int]$parts[1] } else { 32 }
        $nb = ([Net.IPAddress]::Parse($parts[0])).GetAddressBytes(); [array]::Reverse($nb); $net = [BitConverter]::ToUInt32($nb, 0)
        # 4294967295 = 0xFFFFFFFF (the hex literal would be a negative Int32 in PowerShell)
        $mask = [uint32](([uint64]4294967295 -shl (32 - $bits)) -band [uint64]4294967295)
        if (($n -band $mask) -eq ($net -band $mask)) { return 'team' }
    }
    if ($Ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)') { return 'private' }
    'EXTERNAL'
}

# ------------------------------------------------------------------ recording
$script:Seen = @{}        # connection key -> last seen
$script:ProcNames = @{}   # pid -> name

function Get-ProcName([int]$ProcId) {
    if ($ProcId -le 4) { return '-' }
    if (-not $script:ProcNames.ContainsKey($ProcId)) {
        $p = Get-Process -Id $ProcId -ErrorAction SilentlyContinue
        $script:ProcNames[$ProcId] = if ($p) { "$($p.ProcessName)[$ProcId]" } else { '-' }
    }
    $script:ProcNames[$ProcId]
}

function Invoke-Record {
    $now = Get-Now
    $all = @(Get-NetTCPConnection -ErrorAction SilentlyContinue)
    $listening = @{}
    $all | Where-Object { $_.State -eq 'Listen' } | ForEach-Object { $listening[[string]$_.LocalPort] = $true }
    $lines = foreach ($c in $all) {
        if ($c.State -in 'Listen', 'Bound') { continue }
        $r = $c.RemoteAddress
        if ($r -match '^(127\.|0\.0\.0\.0$|::$|::1$)' -or $listening.ContainsKey([string]$c.LocalPort)) { continue }
        $key = "$($c.LocalAddress):$($c.LocalPort)>${r}:$($c.RemotePort)"
        if (-not $script:Seen.ContainsKey($key)) {
            $proc = Get-ProcName ([int]$c.OwningProcess)
            "$now,tcp,$r,$($c.RemotePort),$proc"
        }
        $script:Seen[$key] = $now
    }
    if ($lines) { Add-Content -LiteralPath $Events -Value $lines }
    foreach ($k in @($script:Seen.Keys)) { if ($now - $script:Seen[$k] -ge 300) { $script:Seen.Remove($k) } }
}

# ------------------------------------------------------------------ analysis
function Get-Beacons {
    $now = Get-Now
    $groups = @{}
    foreach ($e in Import-Csv -LiteralPath $Events) {
        $ts = [int64]$e.Ts
        if ($ts -lt $now - $Window -or (Test-Allowed $e.Dst $e.Port)) { continue }
        $key = "$($e.Proto)|$($e.Dst)|$($e.Port)"
        if (-not $groups.ContainsKey($key)) {
            $groups[$key] = [pscustomobject]@{ Times = New-Object Collections.Generic.List[int64]; Last = [int64]-1; Names = @(); LastProc = '-' }
        }
        $g = $groups[$key]
        if ($e.Proc -ne '-') {
            $name = $e.Proc -replace '\[\d+\]$', ''
            if ($g.Names -notcontains $name) { $g.Names += $name }
            $g.LastProc = $e.Proc
        }
        # connections within 2 polls of the previous one are one burst
        if ($g.Last -ge 0 -and $ts - $g.Last -le 2 * $Interval) { continue }
        $g.Times.Add($ts); $g.Last = $ts
    }
    foreach ($key in $groups.Keys) {
        $g = $groups[$key]
        if ($g.Times.Count -lt $MinHits) { continue }
        $gaps = @(@(for ($i = 1; $i -lt $g.Times.Count; $i++) { $g.Times[$i] - $g.Times[$i - 1] }) | Sort-Object)
        $m = $gaps.Count
        $mid = [int][Math]::Floor($m / 2)
        $med = if ($m % 2) { $gaps[$mid] } else { ($gaps[$mid - 1] + $gaps[$mid]) / 2 }
        if ($med -lt $MinGap) { continue }
        $tol = [Math]::Max($med * $Tolerance, 2 * $Interval)
        $ok = @($gaps | Where-Object { $_ -ge $med - $tol -and $_ -le $med + $tol }).Count
        $reg = $ok / $m
        if ($reg -lt 0.5) { continue }
        $proto, $dst, $port = $key -split '\|'
        [pscustomobject]@{
            Verdict = if ($reg -ge $Regular) { 'BEACON' } else { 'maybe' }
            Regular = [int]($reg * 100); Every = [int]$med; Hits = $g.Times.Count
            Proto = $proto; Destination = $dst; Port = $port; Scope = Get-Scope $dst
            Programs = if ($g.Names) { $g.Names -join ',' } else { 'unknown' }; Last = $g.LastProc
        }
    }
}

# "name[pid]" -> path and signer, while the process is still running
function Get-ProcDetail([string]$Proc) {
    if ($Proc -notmatch '\[(\d+)\]$') { return $Proc }
    $p = Get-Process -Id ([int]$Matches[1]) -ErrorAction SilentlyContinue
    if (-not $p -or -not $p.Path) { return $Proc }
    $sig = Get-AuthenticodeSignature -LiteralPath $p.Path -ErrorAction SilentlyContinue
    $who = if ($sig -and $sig.Status -eq 'Valid') { 'signed by ' + ($sig.SignerCertificate.Subject -replace '^CN=([^,]+).*', '$1') } else { 'NOT SIGNED' }
    "$Proc $($p.Path) ($who)"
}

# ------------------------------------------------------------------ commands
switch ($Command) {
    'report' {
        $rows = @(Get-Beacons | Sort-Object @{ e = { $_.Verdict -ne 'BEACON' } }, @{ e = 'Regular'; Descending = $true })
        if ($rows) { $rows | Format-Table -AutoSize | Out-String -Width 250 | Write-Host }
        else { Write-Host 'Nothing repeating yet.' }
        $count = @(Import-Csv -LiteralPath $Events).Count
        Write-Host "$count connections recorded. Allowed (ignored): $($AllowList -join ' ')"
    }
    'watch' {
        Write-Log "Watching outbound TCP every ${Interval}s; beacon = $MinHits+ connections, gap ${MinGap}s+, 80% within 25% of the typical gap"
        $alerted = @{}
        $lastAnalyze = Get-Now; $lastPrune = $lastAnalyze
        while ($true) {
            try {
                Invoke-Record
                $now = Get-Now
                if ($now - $lastAnalyze -ge 60) {
                    $lastAnalyze = $now
                    $script:ProcNames = @{}   # pids get reused
                    foreach ($b in Get-Beacons | Where-Object Verdict -eq 'BEACON') {
                        $key = "$($b.Proto)|$($b.Destination)|$($b.Port)"
                        if ($alerted.ContainsKey($key)) { continue }
                        $alerted[$key] = $true
                        Write-Log ("BEACON: $($b.Destination):$($b.Port)/$($b.Proto) ($($b.Scope)) every ~$($b.Every)s, " +
                                   "$($b.Hits) connections, $($b.Regular)% regular - program: $($b.Programs) (last: $(Get-ProcDetail $b.Last))")
                    }
                }
                if ($now - $lastPrune -ge 600) {
                    $lastPrune = $now
                    $keep = @(Import-Csv -LiteralPath $Events | Where-Object { [int64]$_.Ts -ge $now - $Window })
                    if ($keep) { $keep | Export-Csv -LiteralPath $Events -NoTypeInformation } else { Set-Content -LiteralPath $Events -Value 'Ts,Proto,Dst,Port,Proc' }
                }
            } catch {
                Write-Log "ERROR: $_"
            }
            Start-Sleep -Seconds $Interval
        }
    }
}
