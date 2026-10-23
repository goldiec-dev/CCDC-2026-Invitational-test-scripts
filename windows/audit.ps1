<#
.SYNOPSIS
Persistence and backdoor audit for the Windows 11 workstation and Server 2019 IIS server.

.DESCRIPTION
Report-only by default. -Fix asks before each fix; -Fix -Yes applies fixes for
CRITICAL findings only (warnings always need a person). Nothing is deleted:
files are moved to C:\ProgramData\CCDC\quarantine-<time>, registry keys are
exported to backup-<time> before they change, and tasks/services are disabled,
not removed. Critical findings also go to the Application event log (source
CCDC-Audit) so Splunk sees them.

Checks: administrators, Run keys (all loaded user hives), Winlogon, image file
execution options, AppInit DLLs, accessibility binaries, services, scheduled
tasks, WMI event subscriptions, startup folders, Defender exclusions, firewall,
processes, listeners and connections, IIS webshells, shares, hosts file,
PowerShell profiles.

.EXAMPLE
.\audit.ps1
.\audit.ps1 -Fix
.\audit.ps1 -Fix -Yes -ExpectedAdmins webadmin
#>
param(
    [switch]$Fix,
    [switch]$Yes,
    [string[]]$ExpectedAdmins = @()
)

$ErrorActionPreference = 'Continue'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Error 'Run this from an elevated (Administrator) PowerShell.'; exit 1 }

$OutDir = "$env:ProgramData\CCDC"
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
icacls $OutDir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Report = Join-Path $OutDir "audit-$Stamp.txt"
$QDir = Join-Path $OutDir "quarantine-$Stamp"
$BDir = Join-Path $OutDir "backup-$Stamp"

$script:CritCount = 0
$script:WarnCount = 0
$script:Last = ''

function Out-Line([string]$Text, [string]$Color = 'Gray') {
    Write-Host $Text -ForegroundColor $Color
    Add-Content -LiteralPath $Report -Value $Text
}
function Section([string]$Title) { Out-Line "`n== $Title ==" 'White' }
function Info([string]$Text) { Out-Line "    $Text" }
function Ok([string]$Text) { Out-Line "[OK] $Text" 'Green' }
function Warn([string]$Text) { $script:WarnCount++; $script:Last = 'warn'; Out-Line "[WARN] $Text" 'Yellow' }
function Crit([string]$Text) {
    $script:CritCount++; $script:Last = 'crit'
    Out-Line "[CRITICAL] $Text" 'Red'
    try {
        if (-not [Diagnostics.EventLog]::SourceExists('CCDC-Audit')) { New-EventLog -LogName Application -Source CCDC-Audit }
        Write-EventLog -LogName Application -Source CCDC-Audit -EventId 4200 -EntryType Warning -Message $Text
    } catch { }
}

function Ask-Fix([string]$Description) {
    if (-not $Fix) { return $false }
    if ($Yes) {
        if ($script:Last -eq 'crit') { Info "fixing: $Description"; return $true }
        Info 'not auto-fixed (warning - review by hand)'; return $false
    }
    return ((Read-Host "    Fix - $Description? [y/N]") -match '^[Yy]')
}

function Move-ToQuarantine([string]$Path) {
    $dest = Join-Path $QDir ($Path -replace ':', '')
    New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
    Move-Item -LiteralPath $Path -Destination $dest -Force
    Info "moved to $dest"
}

# Export a registry key (HKLM:\... or Registry::HKEY_USERS\...) before changing it
function Backup-RegKey([string]$PsPath) {
    New-Item -ItemType Directory -Force -Path $BDir | Out-Null
    $native = $PsPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', '' -replace '^Registry::', '' `
                      -replace '^HKLM:', 'HKLM' -replace '^HKCU:', 'HKCU'
    $file = Join-Path $BDir (($native -replace '[\\/:*?"<>| ]', '_') + '.reg')
    reg export $native $file /y | Out-Null
}

# Built-in Windows tools used in suspicious ways. These are signed by Microsoft,
# so a match is CRITICAL regardless of signature.
$SusTrick = '(?i)(powershell(\.exe)?\s.*(\s-e(nc|ncodedcommand)?\s|\s-w(indowstyle)?\s+h|downloadstring|frombase64string|iex[\s(])|mshta|regsvr32.*/i:|rundll32.*(javascript:|http)|certutil.*(urlcache|decode)|bitsadmin.*/transfer|(wscript|cscript)(\.exe)?\s|cmd(\.exe)?\s+/c.*(powershell|http|\\temp\\))'
# User-writable folders. A program here is CRITICAL only if it isn't validly signed
# (OneDrive, Teams etc. legitimately run from AppData).
$SusPath = '(?i)\\(temp|tmp|appdata|users\\public|perflogs)\\'

# Returns 'crit', 'warn' or '' for a command line
function Get-CmdVerdict([string]$CommandLine) {
    if ($CommandLine -match $SusTrick) { return 'crit' }
    $exe = Get-ExePath $CommandLine
    if ($CommandLine -match $SusPath -and -not (Test-Signed $exe)) { return 'crit' }
    if ($exe -and -not (Test-Signed $exe)) { return 'warn' }
    return ''
}

# First executable path in a command line
function Get-ExePath([string]$CommandLine) {
    if (-not $CommandLine) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($c -match '^"([^"]+)"') { return $Matches[1] }
    if ($c -match '^(.+?\.(exe|com|bat|cmd|dll|ps1|vbs|js))(\s|$)') { return $Matches[1] }
    return ($c -split '\s+')[0]
}

function Test-MicrosoftSigned([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $false }
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    return ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'O=Microsoft Corporation')
}
function Test-Signed([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $false }
    return ((Get-AuthenticodeSignature -LiteralPath $Path).Status -eq 'Valid')
}

function Run-Check([string]$Name, [scriptblock]$Body) {
    Section $Name
    try { & $Body } catch { Warn "check failed: $($_.Exception.Message)" }
}

# ============================================================== checks

function Check-Admins {
    $builtinAdmin = (Get-LocalUser | Where-Object { $_.SID.Value -like '*-500' }).Name
    $allowed = @($builtinAdmin, $env:USERNAME) + $ExpectedAdmins
    $members = @()
    try {
        $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { $_.Name })
    } catch {
        # Get-LocalGroupMember fails on orphaned SIDs; fall back to net.exe
        $members = @(net localgroup Administrators | Select-Object -Skip 6 | Where-Object { $_ -and $_ -notmatch 'command completed' })
    }
    foreach ($m in $members) {
        $short = ($m -split '\\')[-1]
        if ($allowed -contains $short) { Info "admin: $m (expected)"; continue }
        if ($m -match '\\' -and $m -notmatch "^$([regex]::Escape($env:COMPUTERNAME))\\") {
            Warn "Administrators member from outside this machine: $m"
            continue
        }
        Crit "Unexpected member of Administrators: $m (add -ExpectedAdmins if it is legitimate)"
        if (Ask-Fix "remove $m from Administrators") { net localgroup Administrators "$short" /delete | Out-Null }
    }
    Info 'Enabled local accounts:'
    Get-LocalUser | Where-Object Enabled | ForEach-Object {
        Out-Line ("      {0,-20} last logon {1}  password set {2}" -f $_.Name, $_.LastLogon, $_.PasswordLastSet)
    }
}

function Check-RunKeys {
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    )
    foreach ($hive in Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -notmatch '_Classes$' }) {
        $keys += "Registry::HKEY_USERS\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Run"
        $keys += "Registry::HKEY_USERS\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    }
    foreach ($k in $keys) {
        if (-not (Test-Path $k)) { continue }
        $item = Get-ItemProperty -Path $k
        foreach ($p in $item.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }) {
            $cmd = [string]$p.Value
            $verdict = Get-CmdVerdict $cmd
            if ($verdict -eq 'crit') { Crit "Run key $k : $($p.Name) = $cmd" }
            elseif ($verdict -eq 'warn') { Warn "Run key entry with unsigned or missing program: $k : $($p.Name) = $cmd" }
            else { Info "$($p.Name) = $cmd"; continue }
            if (Ask-Fix "remove this Run entry (key exported first)") {
                Backup-RegKey $k; Remove-ItemProperty -Path $k -Name $p.Name
            }
        }
    }
    Info 'Only loaded user hives are checked (users who are logged in or have run something).'
}

function Check-Winlogon {
    $k = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $w = Get-ItemProperty $k
    if ($w.Shell -and $w.Shell -notmatch '^\s*explorer\.exe\s*$') {
        Crit "Winlogon Shell is '$($w.Shell)' (should be explorer.exe)"
        if (Ask-Fix 'reset Shell to explorer.exe') { Backup-RegKey $k; Set-ItemProperty $k -Name Shell -Value 'explorer.exe' }
    } else { Ok 'Winlogon Shell is default' }
    if ($w.Userinit -notmatch '^\s*C:\\Windows\\system32\\userinit\.exe,?\s*$') {
        Crit "Winlogon Userinit is '$($w.Userinit)' (should be C:\Windows\system32\userinit.exe,)"
        if (Ask-Fix 'reset Userinit to default') { Backup-RegKey $k; Set-ItemProperty $k -Name Userinit -Value 'C:\Windows\system32\userinit.exe,' }
    } else { Ok 'Winlogon Userinit is default' }

    foreach ($base in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
                      'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
        $a = Get-ItemProperty $base -ErrorAction SilentlyContinue
        if ($a -and $a.AppInit_DLLs -and $a.LoadAppInit_DLLs -eq 1) {
            Crit "AppInit_DLLs loads into every GUI process: $($a.AppInit_DLLs) ($base)"
            if (Ask-Fix 'turn off LoadAppInit_DLLs') { Backup-RegKey $base; Set-ItemProperty $base -Name LoadAppInit_DLLs -Value 0 }
        }
    }
}

function Check-IFEO {
    $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    $found = $false
    foreach ($k in Get-ChildItem $base) {
        $d = (Get-ItemProperty $k.PSPath -Name Debugger -ErrorAction SilentlyContinue).Debugger
        if ($d) {
            $found = $true
            Crit "Debugger hijack: running $($k.PSChildName) starts '$d'"
            if (Ask-Fix "remove the Debugger value for $($k.PSChildName)") { Backup-RegKey $k.PSPath; Remove-ItemProperty $k.PSPath -Name Debugger }
        }
    }
    $spe = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
    if (Test-Path $spe) {
        foreach ($k in Get-ChildItem $spe) {
            $m = (Get-ItemProperty $k.PSPath -Name MonitorProcess -ErrorAction SilentlyContinue).MonitorProcess
            if ($m) { $found = $true; Crit "SilentProcessExit: when $($k.PSChildName) exits, '$m' runs" }
        }
    }
    if (-not $found) { Ok 'No debugger or exit-monitor hijacks' }

    foreach ($f in 'sethc.exe', 'utilman.exe', 'osk.exe', 'Magnify.exe', 'Narrator.exe', 'DisplaySwitch.exe', 'AtBroker.exe') {
        $p = Join-Path "$env:SystemRoot\System32" $f
        if ((Test-Path $p) -and -not (Test-MicrosoftSigned $p)) {
            Crit "Accessibility binary replaced (login-screen backdoor): $p - restore with: sfc /scanfile=$p"
        }
    }
}

function Check-Services {
    foreach ($s in Get-CimInstance Win32_Service) {
        $exe = Get-ExePath $s.PathName
        $standard = $exe -match '(?i)^(C:\\Windows\\|C:\\Program Files( \(x86\))?\\)'
        $verdict = Get-CmdVerdict $s.PathName
        # Unsigned services in Program Files are common (and may be scored) - only flag them elsewhere
        if ($verdict -eq 'warn' -and $standard) { $verdict = '' }
        if ($verdict) {
            $msg = "Service '$($s.Name)' ($($s.State), $($s.StartMode)) runs: $($s.PathName)"
            if ($verdict -eq 'crit') { Crit $msg } else { Warn "$msg (unsigned, outside Program Files - make sure it isn't a scored service before disabling)" }
            if (Ask-Fix "stop and disable service $($s.Name)") {
                Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
                Set-Service -Name $s.Name -StartupType Disabled
            }
        } elseif ($exe -and -not (Test-Path -LiteralPath $exe) -and $s.StartMode -ne 'Disabled') {
            Warn "Service '$($s.Name)' points at a missing file: $($s.PathName)"
        }
    }
}

function Check-Tasks {
    foreach ($t in Get-ScheduledTask) {
        $actions = @($t.Actions | Where-Object { $_.Execute } | ForEach-Object { "$($_.Execute) $($_.Arguments)".Trim() })
        if (-not $actions) { continue }
        $line = $actions -join ' ; '
        $name = "$($t.TaskPath)$($t.TaskName)"
        if ((Get-CmdVerdict $actions[0]) -eq 'crit' -or ($line -match $SusTrick)) {
            Crit "Scheduled task $name ($($t.State), runs as $($t.Principal.UserId)): $line"
            if (Ask-Fix "export and disable task $name") {
                New-Item -ItemType Directory -Force -Path $QDir | Out-Null
                Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath |
                    Set-Content -LiteralPath (Join-Path $QDir (($name -replace '[\\/:*?"<>|]', '_') + '.xml'))
                Disable-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath | Out-Null
            }
        } elseif ($t.TaskPath -notmatch '^\\Microsoft\\') {
            Info "task $name ($($t.State)): $line"
        }
    }
}

function Check-Wmi {
    $consumers = @(Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue)
    $bindings = @(Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue)
    $bad = $consumers | Where-Object { $_.CimClass.CimClassName -in 'CommandLineEventConsumer', 'ActiveScriptEventConsumer' }
    if (-not $bad) { Ok 'No WMI consumers that run commands or scripts'; return }
    foreach ($c in $bad) {
        $what = if ($c.CommandLineTemplate) { $c.CommandLineTemplate } else { "script: $($c.ScriptFileName)$($c.ScriptText)" }
        Crit "WMI event subscription '$($c.Name)' ($($c.CimClass.CimClassName)) runs: $what"
        if (Ask-Fix "save and remove WMI subscription $($c.Name)") {
            New-Item -ItemType Directory -Force -Path $QDir | Out-Null
            $c | Format-List * | Out-File -LiteralPath (Join-Path $QDir "wmi-$($c.Name).txt")
            foreach ($b in $bindings | Where-Object { $_.Consumer.Name -eq $c.Name }) {
                $filterName = $b.Filter.Name
                $b | Remove-CimInstance
                Get-CimInstance -Namespace root\subscription -ClassName __EventFilter |
                    Where-Object { $_.Name -eq $filterName } | Remove-CimInstance
            }
            $c | Remove-CimInstance
        }
    }
}

function Check-Startup {
    $dirs = @("$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp")
    $dirs += Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue |
        ForEach-Object { Join-Path $_.FullName 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup' }
    $any = $false
    foreach ($d in $dirs | Where-Object { Test-Path $_ }) {
        foreach ($f in Get-ChildItem -LiteralPath $d -File -Force | Where-Object { $_.Name -ne 'desktop.ini' }) {
            $any = $true
            if ($f.Extension -match '(?i)^\.(bat|cmd|vbs|vbe|js|jse|wsf|hta|ps1|scr)$') {
                Crit "Script in a startup folder: $($f.FullName)"
                if (Ask-Fix "quarantine $($f.FullName)") { Move-ToQuarantine $f.FullName }
            } else {
                Warn "Startup folder item: $($f.FullName)"
                if (Ask-Fix "quarantine $($f.FullName)") { Move-ToQuarantine $f.FullName }
            }
        }
    }
    if (-not $any) { Ok 'Startup folders are empty' }
}

function Check-Defender {
    $pref = Get-MpPreference
    $status = Get-MpComputerStatus
    if (-not $status.RealTimeProtectionEnabled) {
        Crit 'Defender real-time protection is OFF'
        if (Ask-Fix 'turn real-time protection on') { Set-MpPreference -DisableRealtimeMonitoring $false }
    } else { Ok 'Defender real-time protection is on' }
    foreach ($kind in 'ExclusionPath', 'ExclusionProcess', 'ExclusionExtension') {
        foreach ($e in @($pref.$kind | Where-Object { $_ })) {
            Crit "Defender $kind exclusion: $e"
            if (Ask-Fix "remove the $kind exclusion '$e'") {
                $arg = @{ $kind = $e }
                Remove-MpPreference @arg
            }
        }
    }
}

function Check-Firewall {
    foreach ($p in Get-NetFirewallProfile) {
        if (-not $p.Enabled) {
            Crit "Firewall profile $($p.Name) is OFF"
            if (Ask-Fix "turn on the $($p.Name) firewall profile") { Set-NetFirewallProfile -Name $p.Name -Enabled True }
        }
    }
    foreach ($r in Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True) {
        $prog = ($r | Get-NetFirewallApplicationFilter).Program
        if ($prog -and $prog -match $SusPath -and -not (Test-Signed ([Environment]::ExpandEnvironmentVariables($prog)))) {
            Crit "Inbound allow rule '$($r.DisplayName)' for a program in a user-writable folder: $prog"
            if (Ask-Fix "disable rule $($r.DisplayName)") { Disable-NetFirewallRule -Name $r.Name }
        }
    }
}

function Check-Processes {
    foreach ($p in Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath }) {
        if ($p.ExecutablePath -match '(?i)\\(temp|tmp|appdata\\local\\temp|users\\public|perflogs)\\' -and
            -not (Test-Signed $p.ExecutablePath)) {
            Crit "Unsigned process running from a temp/public folder: pid $($p.ProcessId) $($p.ExecutablePath)"
            if (Ask-Fix "copy the binary to quarantine and stop pid $($p.ProcessId)") {
                New-Item -ItemType Directory -Force -Path $QDir | Out-Null
                Copy-Item -LiteralPath $p.ExecutablePath -Destination (Join-Path $QDir "$($p.ProcessId)-$(Split-Path $p.ExecutablePath -Leaf)") -ErrorAction SilentlyContinue
                Stop-Process -Id $p.ProcessId -Force
            }
        }
    }
    $procs = @{}
    Get-CimInstance Win32_Process | ForEach-Object { $procs[[int]$_.ProcessId] = $_ }
    Info 'Listening TCP ports:'
    Get-NetTCPConnection -State Listen | Sort-Object LocalPort -Unique | ForEach-Object {
        $pr = $procs[[int]$_.OwningProcess]
        Out-Line ("      {0,-6} {1,-16} {2}" -f $_.LocalPort, $pr.Name, $pr.ExecutablePath)
    }
    Info 'Established connections to other hosts (check anything you do not recognise):'
    Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1$)' } | ForEach-Object {
        $pr = $procs[[int]$_.OwningProcess]
        Out-Line ("      {0}:{1} -> {2}:{3}  {4}" -f $_.LocalAddress, $_.LocalPort, $_.RemoteAddress, $_.RemotePort, $pr.ExecutablePath)
    }
}

function Check-Web {
    $roots = @('C:\inetpub\wwwroot')
    if (Get-Module -ListAvailable -Name WebAdministration) {
        Import-Module WebAdministration
        $roots += Get-Website | ForEach-Object { [Environment]::ExpandEnvironmentVariables($_.PhysicalPath) }
    }
    $roots = $roots | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique
    if (-not $roots) { Info 'No web roots on this machine'; return }
    $pattern = '(?i)(Process\.Start|ProcessStartInfo|cmd\.exe\s*/c|WScript\.Shell|eval\s*\(\s*Request|Execute\s*\(\s*Request|Assembly\.Load\s*\(|FromBase64String\s*\(\s*Request|eval\s*\(\s*base64_decode|(system|shell_exec|passthru)\s*\(\s*\$_(GET|POST|REQUEST))'
    $files = Get-ChildItem -LiteralPath $roots -Recurse -File -Force -Include *.aspx, *.ashx, *.asmx, *.asp, *.cshtml, *.php, *.jsp -ErrorAction SilentlyContinue
    $hits = 0
    foreach ($f in $files) {
        $m = Select-String -LiteralPath $f.FullName -Pattern $pattern -List -ErrorAction SilentlyContinue
        if ($m) {
            $hits++
            Crit "Possible webshell: $($f.FullName) (line $($m.LineNumber): $($m.Line.Trim().Substring(0, [Math]::Min(120, $m.Line.Trim().Length))))"
            if (Ask-Fix "quarantine $($f.FullName) (check the site still works after)") { Move-ToQuarantine $f.FullName }
        }
    }
    if ($hits -eq 0) { Ok "No webshell patterns in $($files.Count) script files under $($roots -join ', ')" }
}

function Check-Misc {
    foreach ($s in Get-SmbShare | Where-Object { $_.Name -notmatch '\$$' }) {
        $everyone = Get-SmbShareAccess -Name $s.Name | Where-Object { $_.AccountName -match 'Everyone' -and $_.AccessRight -eq 'Full' }
        if ($everyone) { Warn "Share '$($s.Name)' ($($s.Path)) gives Everyone full access" }
        else { Info "share: $($s.Name) -> $($s.Path)" }
    }
    $hosts = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_ -match '^\s*[^#\s]' }
    foreach ($h in $hosts) { Warn "hosts file entry: $h" }
    $profiles = @("$PSHOME\profile.ps1", "$PSHOME\Microsoft.PowerShell_profile.ps1")
    $profiles += Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        Join-Path $_.FullName 'Documents\WindowsPowerShell\profile.ps1'
        Join-Path $_.FullName 'Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1'
    }
    foreach ($p in $profiles | Where-Object { Test-Path $_ }) {
        Warn "PowerShell profile runs on every PowerShell start - review it: $p"
    }
}

# ============================================================== run

Out-Line "CCDC Windows audit of $env:COMPUTERNAME at $(Get-Date)" 'White'
if ($Fix) { Out-Line $(if ($Yes) { 'Fix mode: auto-fixing CRITICAL findings' } else { 'Fix mode: asking per finding' }) 'White' }

Run-Check 'Administrators and accounts' { Check-Admins }
Run-Check 'Run keys' { Check-RunKeys }
Run-Check 'Winlogon and AppInit' { Check-Winlogon }
Run-Check 'Debugger hijacks and accessibility binaries' { Check-IFEO }
Run-Check 'Services' { Check-Services }
Run-Check 'Scheduled tasks' { Check-Tasks }
Run-Check 'WMI event subscriptions' { Check-Wmi }
Run-Check 'Startup folders' { Check-Startup }
Run-Check 'Defender' { Check-Defender }
Run-Check 'Firewall' { Check-Firewall }
Run-Check 'Processes and network' { Check-Processes }
Run-Check 'IIS webshells' { Check-Web }
Run-Check 'Shares, hosts file, PowerShell profiles' { Check-Misc }

Section 'Summary'
Out-Line "Critical: $script:CritCount   Warnings: $script:WarnCount" 'White'
Out-Line "Report: $Report"
if (Test-Path $QDir) { Out-Line "Quarantined: $QDir" }
if (Test-Path $BDir) { Out-Line "Registry backups: $BDir" }
if ($script:CritCount -gt 0) { exit 2 } elseif ($script:WarnCount -gt 0) { exit 1 } else { exit 0 }
