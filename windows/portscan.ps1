<#
.SYNOPSIS
Network port scan of the team's own hosts: which ports are actually reachable (Windows).

.DESCRIPTION
Same checks as linux/portscan.sh. Targets default to every host in ccdc.conf
(ECOM, WEBMAIL, SPLUNK, PA_MGMT, AD, MSSQL, WEB, FTP, WIN11, FTD_MGMT, MYSQL, WAZUH, SCAN_TARGETS, SCAN_EXPECT hosts).
Targets outside INSIDE / EXTERNAL / SCAN_SCOPE are refused - CCDC rules forbid scanning other
teams and competition infrastructure (-AllowAny for practice labs only).

Each open port is labeled expected (SCAN_EXPECT), UNEXPECTED, RISKY (legacy/admin/database
service reachable from the network) or SUSPICIOUS (common backdoor / C2 port). Compared with the
previous scan: NEW and GONE ports are reported and written to the Application log (CCDC-Portscan).
Uses nmap if installed, otherwise parallel TCP connects (TCP only).
Results: C:\ProgramData\CCDC\portscan\. Exit: 2 suspicious/new, 1 unexpected/risky/gone, 0 clean.

.EXAMPLE
.\portscan.ps1
.\portscan.ps1 172.20.240.120 -Ports 1-1024 -Banner
#>
param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Targets = @(),
    [string]$Ports = 'common',
    [switch]$Banner,
    [int]$TimeoutMs = 1000,
    [ValidateSet('auto', 'nmap', 'tcp')]
    [string]$Engine = 'auto',
    [switch]$AllowAny,
    [string]$Config = (Join-Path $PSScriptRoot '..\ccdc.conf')
)
$ErrorActionPreference = 'Continue'

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
$C = if (Test-Path -LiteralPath $Config) { Read-Conf $Config } else { @{} }
$Named = 'ECOM', 'WEBMAIL', 'SPLUNK', 'PA_MGMT', 'AD', 'MSSQL', 'WEB', 'FTP', 'WIN11', 'FTD_MGMT', 'MYSQL', 'WAZUH'
$Expect = @{}
foreach ($e in @($C['SCAN_EXPECT'])) { if ($e -match '^([^:]+):(.+)$') { $Expect[$Matches[1]] = @($Matches[2] -split ',' | ForEach-Object { [int]$_ }) } }

$Dir = "$env:ProgramData\CCDC\portscan"
New-Item -ItemType Directory -Force -Path $Dir | Out-Null

# ------------------------------------------------------------------ ports
$CommonTcp = '21,22,23,25,53,69,79,80,81,88,110,111,113,119,135,139,143,161,179,389,427,443,444,445,464,465,500,512,513,514,515,548,554,587,593,623,631,636,646,873,902,990,993,995,1025,1080,1099,1194,1337,1433,1434,1514,1515,1521,1723,1883,2000,2049,2082,2083,2121,2181,2222,2323,2375,2376,2483,3000,3128,3260,3268,3269,3306,3389,3632,3690,4243,4369,4433,4444,4445,4505,4506,4786,4848,5000,5001,5060,5061,5432,5555,5601,5672,5800,5900,5901,5902,5985,5986,6000,6001,6379,6443,6666,6667,6697,7001,7070,7443,7474,7777,8000,8001,8008,8009,8080,8081,8088,8089,8090,8161,8180,8191,8443,8500,8834,8880,8888,9000,9001,9042,9090,9092,9100,9200,9300,9443,9997,9999,10000,10250,11211,12345,15672,20000,27017,31337,47001,50000,50050,54321,55000,61616'
$Names = @{ 21 = 'ftp'; 22 = 'ssh'; 23 = 'telnet'; 25 = 'smtp'; 53 = 'dns'; 69 = 'tftp'; 80 = 'http'; 88 = 'kerberos'; 110 = 'pop3'; 111 = 'rpcbind'
    135 = 'msrpc'; 139 = 'netbios-ssn'; 143 = 'imap'; 389 = 'ldap'; 443 = 'https'; 445 = 'smb'; 464 = 'kpasswd'; 465 = 'smtps'; 587 = 'submission'
    636 = 'ldaps'; 873 = 'rsync'; 993 = 'imaps'; 995 = 'pop3s'; 1433 = 'mssql'; 1514 = 'wazuh'; 1515 = 'wazuh-enroll'; 2049 = 'nfs'; 2375 = 'docker-api'
    3268 = 'ldap-gc'; 3306 = 'mysql'; 3389 = 'rdp'; 5432 = 'postgres'; 5900 = 'vnc'; 5985 = 'winrm'; 5986 = 'winrm-https'; 6379 = 'redis'
    8000 = 'splunk-web/http'; 8080 = 'http-alt'; 8089 = 'splunk-mgmt'; 8443 = 'https-alt'; 9200 = 'elasticsearch'; 9997 = 'splunk-fwd'
    10000 = 'webmin'; 11211 = 'memcached'; 27017 = 'mongodb'; 47001 = 'winrm-alt'; 55000 = 'wazuh-api' }
$Risky = @(21, 23, 69, 79, 111, 135, 137, 139, 161, 445, 512, 513, 514, 515, 593, 873, 1099, 1433, 1521, 2049, 2375, 3306, 3389, 4505, 4506, 5432, 5800, 5900, 5901, 5902, 5985, 5986, 6000, 6001, 6379, 9200, 9300, 10000, 11211, 27017)
$Suspicious = @(1337, 4444, 4445, 5555, 6666, 6667, 6697, 7777, 9001, 12345, 31337, 50050, 54321)

$portSpec = switch ($Ports) { 'common' { $CommonTcp } 'all' { '1-65535' } default { $Ports } }
$PortList = @(foreach ($part in $portSpec -split ',') {
    if ($part -match '^(\d+)-(\d+)$') { [int]$Matches[1]..[int]$Matches[2] } elseif ($part -match '^\d+$') { [int]$part } }) | Sort-Object -Unique

# ------------------------------------------------------------------ targets and scope
function ConvertTo-N([string]$ip) { $a = $null; if (-not [Net.IPAddress]::TryParse($ip, [ref]$a) -or $a.AddressFamily -ne 'InterNetwork') { return $null }
    $b = $a.GetAddressBytes(); [array]::Reverse($b); [BitConverter]::ToUInt32($b, 0) }
function Test-InCidr([string]$ip, [string]$cidr) {
    $parts = $cidr -split '/'; $bits = if ($parts.Count -gt 1) { [int]$parts[1] } else { 32 }
    $n = ConvertTo-N $ip; $b = ConvertTo-N $parts[0]; if ($null -eq $n -or $null -eq $b) { return $false }
    $size = [math]::Pow(2, 32 - $bits); [math]::Floor($n / $size) -eq [math]::Floor($b / $size) }
$namedIps = @($Named | ForEach-Object { $C[$_] } | Where-Object { $_ })
function Test-Scope([string]$ip) {
    if ($AllowAny) { return $true }
    foreach ($c in @($C['INSIDE'] -split '\s+') + @($C['EXTERNAL'] -split '\s+') + @($C['SCAN_SCOPE'])) { if ($c -and (Test-InCidr $ip $c)) { return $true } }
    $namedIps -contains $ip }
function Get-Label([string]$ip) { foreach ($v in $Named) { if ($C[$v] -eq $ip) { return $v } }; '-' }

if (-not $Targets) { $Targets = @($C['SCAN_TARGETS']) + $namedIps + @($Expect.Keys) | Where-Object { $_ } }
$hosts = foreach ($t in $Targets) {
    if ($t -match '^([\d.]+)/(\d+)$') {
        $bits = [int]$Matches[2]; if ($bits -lt 22) { Write-Host "Refusing ${t}: larger than /22"; continue }
        $size = [uint32][math]::Pow(2, 32 - $bits); $start = [uint32]([math]::Floor((ConvertTo-N $Matches[1]) / $size) * $size)
        for ($i = 1; $i -lt $size - 1; $i++) { $b = [BitConverter]::GetBytes([uint32]($start + $i)); [array]::Reverse($b); ([Net.IPAddress]$b).ToString() }
    } elseif (ConvertTo-N $t) { $t }
    else { try { ([Net.Dns]::GetHostAddresses($t) | Where-Object AddressFamily -eq 'InterNetwork' | Select-Object -First 1).IPAddressToString } catch { Write-Host "Can't resolve $t" } }
}
$Scoped = @($hosts | Where-Object { $_ } | Select-Object -Unique | Where-Object {
    if (Test-Scope $_) { $true } else { Write-Host "Skipping ${_}: outside the team ranges. CCDC rules forbid scanning other teams." -ForegroundColor Yellow; $false } })
if (-not $Scoped) { Write-Host 'Nothing to scan. Give targets, or fill in the host IPs in ccdc.conf.'; exit 3 }

$nmap = (Get-Command nmap.exe -ErrorAction SilentlyContinue).Source
if (-not $nmap -and (Test-Path "${env:ProgramFiles(x86)}\Nmap\nmap.exe")) { $nmap = "${env:ProgramFiles(x86)}\Nmap\nmap.exe" }
if ($Engine -eq 'auto') { $Engine = if ($nmap) { 'nmap' } else { 'tcp' } }
if ($Engine -eq 'nmap' -and -not $nmap) { Write-Host 'nmap not installed - using TCP connects'; $Engine = 'tcp' }

# ------------------------------------------------------------------ scanning -> objects Host, Port
function Invoke-TcpScan([string[]]$HostList) {
    # objects, not nested arrays: PowerShell unrolls single-element arrays
    $jobs = New-Object Collections.Generic.List[object]
    foreach ($h in $HostList) { foreach ($p in $PortList) { $jobs.Add([pscustomobject]@{ H = $h; P = [int]$p }) } }
    for ($i = 0; $i -lt $jobs.Count; $i += 256) {
        $end = [math]::Min($i + 255, $jobs.Count - 1)
        $pending = @(foreach ($j in $jobs.GetRange($i, $end - $i + 1)) {
            $c = New-Object Net.Sockets.TcpClient
            [pscustomobject]@{ Host = $j.H; Port = $j.P; Client = $c; Task = $c.ConnectAsync($j.H, $j.P) }
        })
        try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($pending.Task), $TimeoutMs) } catch { }
        foreach ($x in $pending) {
            if ($x.Task.Status -eq 'RanToCompletion' -and $x.Client.Connected) { [pscustomobject]@{ Host = $x.Host; Port = $x.Port } }
            $x.Client.Dispose()
        }
    }
}
function Invoke-NmapScan([string[]]$HostList) {
    $nmapArgs = @('-n', '-T4', '--open', '-sT', '-oG', '-', '-p', ($PortList -join ','))
    if ($HostList.Count -le 50) { $nmapArgs += '-Pn' }
    & $nmap @($nmapArgs + $HostList) 2>$null | Where-Object { $_ -match 'Ports: ' } | ForEach-Object {
        $h = ($_ -split '\s+')[1]
        foreach ($p in (($_ -split 'Ports: ')[1] -split ', ')) { $f = $p -split '/'; if ($f[1] -eq 'open') { [pscustomobject]@{ Host = $h; Port = [int]$f[0] } } }
    }
}
function Get-Banner([string]$h, [int]$p) {
    try {
        $c = New-Object Net.Sockets.TcpClient; if (-not $c.ConnectAsync($h, $p).Wait(2000)) { return '' }
        $s = $c.GetStream(); $s.ReadTimeout = 2000
        if ($p -in 80, 81, 8000, 8008, 8080, 8888, 9000) { $req = [Text.Encoding]::ASCII.GetBytes("HEAD / HTTP/1.0`r`nHost: $h`r`n`r`n"); $s.Write($req, 0, $req.Length) }
        $buf = New-Object byte[] 1024; $n = $s.Read($buf, 0, 1024); $c.Dispose()
        $txt = [Text.Encoding]::ASCII.GetString($buf, 0, $n)
        if ($txt -match '(?im)^Server:\s*(.+)$') { return "Server: $($Matches[1].Trim())" }
        ($txt -split "`n")[0].Trim() -replace '[^\x20-\x7E]', ''
    } catch { '' }
}

# ------------------------------------------------------------------ report
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$out = Join-Path $Dir "scan-$stamp.csv"
$prev = Get-ChildItem -LiteralPath $Dir -Filter 'scan-*.csv' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Write-Host "Port scan $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $($Scoped.Count) host(s) - engine $Engine - $($PortList.Count) TCP ports" -ForegroundColor Cyan
$found = @(if ($Engine -eq 'nmap') { Invoke-NmapScan $Scoped } else { Invoke-TcpScan $Scoped }) | Sort-Object Host, Port -Unique
$found | Export-Csv -LiteralPath $out -NoTypeInformation
$rc = 0
foreach ($h in $Scoped) {
    $open = @($found | Where-Object Host -eq $h)
    Write-Host "`nHOST $h ($(Get-Label $h)) - $($open.Count) open" -ForegroundColor Cyan
    if (-not $open) { Write-Host '  no open ports found (host down, all filtered, or not reachable from here)' }
    $exp = $Expect[$h]
    foreach ($o in $open) {
        $name = if ($Names.ContainsKey($o.Port)) { $Names[$o.Port] } else { '-' }
        $color = 'Gray'
        if ($Suspicious -contains $o.Port -and -not ($exp -contains $o.Port)) { $status = 'SUSPICIOUS - port commonly used by backdoors / C2; find the process on that host'; $color = 'Red'; $rc = 2 }
        elseif ($exp -and $exp -contains $o.Port) { $status = 'expected'; $color = 'Green' }
        elseif ($Risky -contains $o.Port) { $status = "RISKY - $name reachable from the network; needed?"; $color = 'Yellow'; $rc = [math]::Max($rc, 1) }
        elseif ($exp) { $status = 'UNEXPECTED - not in SCAN_EXPECT for this host'; $color = 'Yellow'; $rc = [math]::Max($rc, 1) }
        else { $status = 'open' }
        $line = '  tcp   {0,-6} {1,-20} {2}' -f $o.Port, $name, $status
        if ($Banner) { $b = Get-Banner $h $o.Port; if ($b) { $line += "  [$b]" } }
        Write-Host $line -ForegroundColor $color
    }
    foreach ($p in @($exp)) { if ($p -and -not ($open.Port -contains $p)) { Write-Host "  MISSING expected port $p - is a scored service down or blocked?" -ForegroundColor Red; $rc = [math]::Max($rc, 1) } }
}

function Write-Alert([string]$m) {
    try { if (-not [Diagnostics.EventLog]::SourceExists('CCDC-Portscan')) { New-EventLog -LogName Application -Source CCDC-Portscan }
          Write-EventLog -LogName Application -Source CCDC-Portscan -EventId 4600 -EntryType Warning -Message $m } catch { }
}
if ($prev) {
    $old = @(Import-Csv -LiteralPath $prev.FullName | Where-Object { $Scoped -contains $_.Host } | ForEach-Object { "$($_.Host) $($_.Port)" })
    $now = @($found | ForEach-Object { "$($_.Host) $($_.Port)" })
    Write-Host "`nChanges since $($prev.BaseName -replace 'scan-', ''):" -ForegroundColor Cyan
    $new = @($now | Where-Object { $old -notcontains $_ }); $gone = @($old | Where-Object { $now -notcontains $_ })
    if (-not $new -and -not $gone) { Write-Host '  none' }
    foreach ($x in $new)  { Write-Host "  NEW  $x" -ForegroundColor Red; Write-Alert "NEW open port $x"; $rc = 2 }
    foreach ($x in $gone) { Write-Host "  GONE $x (closed or blocked since last scan)" -ForegroundColor Yellow; Write-Alert "port no longer open $x"; $rc = [math]::Max($rc, 1) }
} else { Write-Host "`nFirst scan - saved as the reference for the next one." }
Write-Host "`nSaved: $out"
exit $rc
