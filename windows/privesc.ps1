<#
.SYNOPSIS
Find privilege-escalation paths and living-off-the-land (LOLBin) abuse on a Windows machine.

.DESCRIPTION
Report-only unless -Fix (asks before each change; -Yes to skip asking). Checks:
  Services       unquoted paths with spaces, service programs / folders / registry keys that
                 non-admins can modify
  Tasks          SYSTEM / elevated scheduled tasks whose program non-admins can modify
  Installer      AlwaysInstallElevated (any user installs an MSI as SYSTEM)
  PATH           system PATH folders non-admins can write (DLL / program hijack)
  Credentials    autologon password, unattend/sysprep files, PowerShell history, VNC passwords,
                 SAM/SYSTEM hives readable by users (HiveNightmare), web.config passwords
  Privileges     non-default holders of SeDebug, SeImpersonate, SeBackup, SeRestore, SeLoadDriver,
                 SeTakeOwnership, SeTcb...; members of Backup Operators and similar groups
  Settings       UAC off, LocalAccountTokenFilterPolicy (pass-the-hash), WDigest, LSA protection,
                 PrintNightmare Point-and-Print, WSUS over HTTP, no AppLocker/WDAC
  LOLBins        built-in tools used for attacks (certutil download, mshta, regsvr32 /i:http,
                 rundll32 comsvcs MiniDump, encoded PowerShell, wmic process create, vssadmin
                 delete shadows, reg save hklm\sam...) in running processes and in the last -Hours
                 of process (4688), Sysmon (1) and PowerShell (4104) events
  -BlockLolbinEgress  add outbound firewall rules so certutil, mshta, regsvr32, rundll32, msbuild,
                 installutil, regasm, regsvcs, cmstp, wscript, cscript, hh and certreq can't reach the
                 network (none of them are needed by the scored services)
Log: C:\ProgramData\CCDC\privesc-<time>.log; old values in the undo CSV. Critical findings go to the
Application log (source CCDC-Privesc). Exit 2 = critical, 1 = warnings, 0 = clean.

.EXAMPLE
.\privesc.ps1
.\privesc.ps1 -Fix -BlockLolbinEgress
#>
param(
    [switch]$Fix,
    [switch]$Yes,
    [switch]$BlockLolbinEgress,
    [int]$Hours = 24
)
$ErrorActionPreference = 'Continue'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this from an elevated (Administrator) PowerShell.' -ForegroundColor Red; exit 1 }

$OutDir = "$env:ProgramData\CCDC"; New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Log = Join-Path $OutDir "privesc-$Stamp.log"
$Undo = Join-Path $OutDir "privesc-$Stamp-undo.csv"
Start-Transcript -LiteralPath $Log | Out-Null

$script:Crit = 0; $script:Warn = 0
function Crit([string]$m) { $script:Crit++; Write-Host "[CRITICAL] $m" -ForegroundColor Red
    try { if (-not [Diagnostics.EventLog]::SourceExists('CCDC-Privesc')) { New-EventLog -LogName Application -Source CCDC-Privesc }
          Write-EventLog -LogName Application -Source CCDC-Privesc -EventId 4800 -EntryType Warning -Message $m } catch { } }
function Warn([string]$m) { $script:Warn++; Write-Host "[WARN]     $m" -ForegroundColor Yellow }
function Ok([string]$m)   { Write-Host "[OK]       $m" -ForegroundColor Green }
function Info([string]$m) { Write-Host "           $m" }
function H1([string]$t)   { Write-Host "`n==================== $t ====================" -ForegroundColor Cyan }
function Ask([string]$q)  { if (-not $Fix) { return $false }; if ($Yes) { return $true }; (Read-Host "           $q [y/N]") -match '^[Yy]' }
function Record($What, $Old, $New) { [pscustomobject]@{ Time = (Get-Date -Format s); Item = $What; Old = $Old; New = $New } | Export-Csv -LiteralPath $Undo -Append -NoTypeInformation }
function Get-Reg([string]$Path, [string]$Name) { (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name }
function Set-Dword([string]$Path, [string]$Name, [int]$Value) {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    Record "$Path\$Name" (Get-Reg $Path $Name) $Value
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}

# Low-privileged principals: Everyone, Users, Authenticated Users, INTERACTIVE, Guests, Domain Users/Guests
$LowSids = @('S-1-1-0', 'S-1-5-32-545', 'S-1-5-11', 'S-1-5-4', 'S-1-5-32-546')
$domSid = try { ([Security.Principal.NTAccount]"$env:USERDOMAIN\Domain Users").Translate([Security.Principal.SecurityIdentifier]).Value } catch { $null }
if ($domSid) { $LowSids += $domSid; $LowSids += ($domSid -replace '-513$', '-514') }
# Rights that let someone replace or plant a file: WriteData/CreateFiles (0x2), AppendData/CreateDirectories (0x4),
# ChangePermissions (0x40000), TakeOwnership (0x80000), GENERIC_ALL (0x10000000), GENERIC_WRITE (0x40000000).
# (Modify and FullControl include these. Don't test against FullControl itself - it contains every bit.)
$WriteMask = 0x2 -bor 0x4 -bor 0x40000 -bor 0x80000 -bor 0x10000000 -bor 0x40000000

function Get-Sid($ref) { try { $ref.Translate([Security.Principal.SecurityIdentifier]).Value } catch { $null } }
# Which low-privileged principals can modify this file/folder? Returns names, or nothing.
function Get-LowWriters([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return }
    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop } catch { return }
    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        if (([int64]$ace.FileSystemRights -band $WriteMask) -eq 0) { continue }
        if ($LowSids -contains (Get-Sid $ace.IdentityReference)) { "$($ace.IdentityReference) ($($ace.FileSystemRights))" }
    }
}
function Get-ExePath([string]$CommandLine) {
    if (-not $CommandLine) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($CommandLine.Trim())
    if ($c -match '^"([^"]+)"') { return $Matches[1] }
    if ($c -match '^(.+?\.(exe|com|bat|cmd|ps1|dll|sys))(\s|$)') { return $Matches[1] }
    ($c -split '\s+')[0]
}
function Remove-LowWrite([string]$Path) {
    # Stop inheriting (copy existing entries), then drop write entries for low-privileged principals
    $before = (icacls $Path) -join ' | '
    Record "ACL $Path" $before 'low-privileged write removed'
    icacls $Path /inheritance:d | Out-Null
    icacls $Path /remove:g ($LowSids | ForEach-Object { "*$_" }) | Out-Null
    # give Users back read/execute only
    if ((Get-Item -LiteralPath $Path).PSIsContainer) { icacls $Path /grant '*S-1-5-32-545:(OI)(CI)(RX)' | Out-Null }
    else { icacls $Path /grant '*S-1-5-32-545:(RX)' | Out-Null }
}

Write-Host "Privilege-escalation and LOLBin check of $env:COMPUTERNAME - $(Get-Date)"

# ------------------------------------------------------------------ services
H1 'SERVICES'
$found = $false
foreach ($s in Get-CimInstance Win32_Service) {
    $exe = Get-ExePath $s.PathName
    if (-not $exe) { continue }
    $raw = $s.PathName.Trim()
    # Unquoted path with a space before the program name: C:\Program Files\App\svc.exe -> C:\Program.exe
    if ($raw -notmatch '^"' -and $exe -match ' ' -and $exe -notmatch '^(?i)C:\\Windows\\') {
        $found = $true
        $dirs = @(); $parts = $exe -split '\\'
        for ($i = 1; $i -lt $parts.Count - 1; $i++) { if ($parts[$i] -match ' ') { $dirs += ($parts[0..($i - 1)] -join '\') } }
        $writable = @($dirs | Where-Object { Get-LowWriters $_ })
        $msg = "Service $($s.Name) has an unquoted path with spaces: $raw"
        if ($writable) { Crit "$msg - and users can write to $($writable -join ', ')" } else { Warn $msg }
        if ($raw.StartsWith($exe, [StringComparison]::OrdinalIgnoreCase) -and (Ask "Quote the path of $($s.Name)?")) {
            $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)"
            $old = Get-Reg $key ImagePath
            $new = '"' + $exe + '"' + $raw.Substring([Math]::Min($raw.Length, $exe.Length))
            Record "ImagePath $($s.Name)" $old $new
            Set-ItemProperty $key -Name ImagePath -Value $new
        }
    }
    $w = @(Get-LowWriters $exe)
    if ($w) { $found = $true; Crit "Service $($s.Name) (runs as $($s.StartName)) program is writable by $($w -join ', '): $exe"
              if (Ask "Remove low-privileged write access on $exe?") { Remove-LowWrite $exe } }
    $folder = Split-Path $exe -Parent
    if ($folder -and $folder -notmatch '^(?i)C:\\Windows') {
        $w = @(Get-LowWriters $folder)
        if ($w) { $found = $true; Crit "Service $($s.Name) folder is writable by $($w -join ', '): $folder (replace the program or plant a DLL)"
                  if (Ask "Remove low-privileged write access on $folder?") { Remove-LowWrite $folder } }
    }
    try {
        $racl = Get-Acl "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)" -ErrorAction Stop
        foreach ($ace in $racl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and $_.RegistryRights -match 'FullControl|SetValue|WriteKey|ChangePermissions|TakeOwnership' }) {
            if ($LowSids -contains (Get-Sid $ace.IdentityReference)) { $found = $true; Crit "Service $($s.Name) registry key is writable by $($ace.IdentityReference) - can change its program" }
        }
    } catch { }
}
if (-not $found) { Ok 'No exploitable service configurations' }

# ------------------------------------------------------------------ scheduled tasks
H1 'SCHEDULED TASKS'
$found = $false
foreach ($t in Get-ScheduledTask -ErrorAction SilentlyContinue) {
    $elevated = $t.Principal.UserId -match 'SYSTEM|LOCAL SERVICE|NETWORK SERVICE' -or $t.Principal.RunLevel -eq 'Highest' -or $t.Principal.GroupId -match 'Administrators'
    if (-not $elevated) { continue }
    foreach ($a in $t.Actions | Where-Object Execute) {
        $exe = Get-ExePath $a.Execute
        foreach ($p in @($exe, (Split-Path $exe -Parent)) | Where-Object { $_ -and $_ -notmatch '^(?i)C:\\Windows' }) {
            $w = @(Get-LowWriters $p)
            if ($w) { $found = $true; Crit "Task $($t.TaskPath)$($t.TaskName) runs as $($t.Principal.UserId) but $p is writable by $($w -join ', ')" }
        }
        foreach ($arg in [regex]::Matches("$($a.Arguments)", '[A-Za-z]:\\[^"\s]+\.(ps1|bat|cmd|vbs|js|exe|dll)')) {
            $w = @(Get-LowWriters $arg.Value)
            if ($w) { $found = $true; Crit "Task $($t.TaskName) runs script $($arg.Value) as $($t.Principal.UserId); writable by $($w -join ', ')" }
        }
    }
}
if (-not $found) { Ok 'No elevated task runs a file that users can modify' }

# ------------------------------------------------------------------ installer, PATH
H1 'INSTALLER AND PATH'
$aieM = Get-Reg 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' AlwaysInstallElevated
$aieU = Get-Reg 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' AlwaysInstallElevated
if ($aieM -eq 1) {
    Crit "AlwaysInstallElevated is on (machine$(if ($aieU -eq 1) { ' + user' })) - any user can install an MSI as SYSTEM"
    if (Ask 'Turn AlwaysInstallElevated off?') { Set-Dword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' AlwaysInstallElevated 0 }
} else { Ok 'AlwaysInstallElevated off' }
$found = $false
foreach ($d in ([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';' | Where-Object { $_ } | Select-Object -Unique)) {
    $d = [Environment]::ExpandEnvironmentVariables($d)
    $w = @(Get-LowWriters $d)
    if ($w) { $found = $true; Crit "System PATH folder writable by $($w -join ', '): $d (programs/DLLs planted here run as whoever searches PATH)"
              if (Ask "Remove low-privileged write access on $d?") { Remove-LowWrite $d } }
}
if (-not $found) { Ok 'No system PATH folder is writable by users' }
foreach ($pf in @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ -and (Test-Path $_) }) {
    foreach ($d in Get-ChildItem $pf -Directory -ErrorAction SilentlyContinue) {
        $w = @(Get-LowWriters $d.FullName)
        if ($w) { Warn "Program folder writable by $($w -join ', '): $($d.FullName)" }
    }
}

# ------------------------------------------------------------------ credentials
H1 'STORED CREDENTIALS'
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if (Get-Reg $wl DefaultPassword) {
    Crit "Autologon password stored in the registry (Winlogon DefaultPassword) for $(Get-Reg $wl DefaultUserName)"
    if (Ask 'Remove the stored autologon password?') { Record 'Winlogon DefaultPassword' 'set' 'removed'; Remove-ItemProperty $wl -Name DefaultPassword; Set-ItemProperty $wl -Name AutoAdminLogon -Value '0' }
} else { Ok 'No autologon password' }
foreach ($f in 'C:\unattend.xml', 'C:\Windows\Panther\Unattend.xml', 'C:\Windows\Panther\Unattend\Unattend.xml', 'C:\Windows\System32\sysprep\unattend.xml',
               'C:\Windows\System32\sysprep\Panther\unattend.xml', 'C:\Windows\system32\sysprep.inf') {
    if ((Test-Path $f) -and (Select-String -LiteralPath $f -Pattern '<Password>|<AdministratorPassword>|AdminPassword' -Quiet)) { Crit "Setup answer file with a password: $f" }
}
foreach ($h in Get-ChildItem 'C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt' -ErrorAction SilentlyContinue) {
    $hits = @(Select-String -LiteralPath $h.FullName -Pattern '(?i)password|passwd|-AsPlainText|ConvertTo-SecureString|net user .* /add|cred' | Select-Object -First 3)
    if ($hits) { Warn "PowerShell history with credentials-looking lines: $($h.FullName)"; $hits | ForEach-Object { Info "  line $($_.LineNumber): $($_.Line.Trim())" } }
}
foreach ($k in 'HKLM:\SOFTWARE\RealVNC\WinVNC4', 'HKLM:\SOFTWARE\TightVNC\Server', 'HKLM:\SOFTWARE\ORL\WinVNC3\Default') {
    if (Get-Reg $k Password) { Warn "VNC password stored in $k (weakly encrypted)" }
}
$samAcl = (icacls "$env:SystemRoot\System32\config\SAM") -join ' '
if ($samAcl -match 'BUILTIN\\Users:\(I\)\(RX\)|BUILTIN\\Users:\(RX\)') {
    Crit 'The SAM / SYSTEM hives are readable by Users (HiveNightmare, CVE-2021-36934) - any user can read password hashes from shadow copies'
    if (Ask 'Fix the hive permissions (icacls config\*.* /inheritance:e)?') {
        Record 'config hive ACL' $samAcl 'inheritance:e'
        icacls "$env:SystemRoot\System32\config\*.*" /inheritance:e | Out-Null
        Info 'Also delete shadow copies taken before the fix (they keep the old permissions): vssadmin list shadows'
    }
} else { Ok 'SAM hive not readable by Users' }
if (Test-Path 'C:\inetpub') {
    foreach ($wc in Get-ChildItem C:\inetpub -Recurse -Filter web.config -ErrorAction SilentlyContinue | Select-String -Pattern '(?i)password\s*=' -List) {
        $w = @(Get-LowWriters $wc.Path)
        Warn "web.config contains a password: $($wc.Path)$(if ($w) { " - and it's writable by $($w -join ', ')" })"
    }
}
Info "Saved Windows credentials of THIS user (run as each admin to see theirs):"; (cmdkey /list) | Where-Object { $_ -match 'Target' } | ForEach-Object { Info "  $_" }

# ------------------------------------------------------------------ privileges and groups
H1 'DANGEROUS PRIVILEGES AND GROUPS'
$inf = Join-Path $env:TEMP "privesc-$Stamp.inf"
secedit /export /cfg $inf /areas USER_RIGHTS /quiet | Out-Null
$allowed = @{
    SeDebugPrivilege = @('S-1-5-32-544'); SeTcbPrivilege = @(); SeCreateTokenPrivilege = @()
    SeTakeOwnershipPrivilege = @('S-1-5-32-544'); SeLoadDriverPrivilege = @('S-1-5-32-544', 'S-1-5-32-550')
    SeBackupPrivilege = @('S-1-5-32-544', 'S-1-5-32-551', 'S-1-5-32-549'); SeRestorePrivilege = @('S-1-5-32-544', 'S-1-5-32-551', 'S-1-5-32-549')
    SeImpersonatePrivilege = @('S-1-5-32-544', 'S-1-5-19', 'S-1-5-20', 'S-1-5-6', 'S-1-5-32-568')
    SeAssignPrimaryTokenPrivilege = @('S-1-5-19', 'S-1-5-20', 'S-1-5-82'); SeManageVolumePrivilege = @('S-1-5-32-544')
    SeEnableDelegationPrivilege = @('S-1-5-32-544'); SeSecurityPrivilege = @('S-1-5-32-544')
}
$found = $false
if (Test-Path $inf) {
    foreach ($line in Get-Content $inf) {
        if ($line -notmatch '^(Se\w+)\s*=\s*(.*)$' -or -not $allowed.ContainsKey($Matches[1])) { continue }
        $priv = $Matches[1]
        foreach ($who in $Matches[2] -split ',') {
            $sid = $who.Trim().TrimStart('*')
            if ($allowed[$priv] -contains $sid -or $sid -like 'S-1-5-82-*' -or $sid -like 'S-1-5-80-*') { continue }   # app pool / service SIDs
            $name = try { ([Security.Principal.SecurityIdentifier]$sid).Translate([Security.Principal.NTAccount]).Value } catch { $sid }
            $found = $true; Crit "$name holds $priv - a direct path to SYSTEM"
        }
    }
    Remove-Item $inf -ErrorAction SilentlyContinue
}
if (-not $found) { Ok 'Dangerous privileges held only by their default accounts' }
if ((Get-CimInstance Win32_OperatingSystem).ProductType -ne 2) {   # not a DC (DCs use AD groups - see ad_audit.ps1)
    foreach ($g in 'Backup Operators', 'Hyper-V Administrators', 'Remote Management Users', 'Distributed COM Users', 'Network Configuration Operators', 'Event Log Readers') {
        $m = @(Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue)
        if ($m) { Warn "$g has members: $(($m | ForEach-Object Name) -join ', ')" }
    }
}

# ------------------------------------------------------------------ settings
H1 'SECURITY SETTINGS ATTACKERS RELY ON'
$sys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
if ((Get-Reg $sys EnableLUA) -eq 0) { Crit 'UAC is turned off (EnableLUA=0)'; if (Ask 'Turn UAC on (needs a reboot)?') { Set-Dword $sys EnableLUA 1 } }
elseif ((Get-Reg $sys ConsentPromptBehaviorAdmin) -eq 0) { Warn 'UAC elevates admins without prompting (ConsentPromptBehaviorAdmin=0)' }
else { Ok 'UAC on' }
if ((Get-Reg $sys LocalAccountTokenFilterPolicy) -eq 1) {
    Crit 'LocalAccountTokenFilterPolicy=1 - local admin accounts get full rights over the network (pass-the-hash)'
    if (Ask 'Set LocalAccountTokenFilterPolicy to 0?') { Set-Dword $sys LocalAccountTokenFilterPolicy 0 }
}
$wd = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
if ((Get-Reg $wd UseLogonCredential) -eq 1) { Crit 'WDigest stores plaintext passwords in memory (UseLogonCredential=1)'; if (Ask 'Turn it off?') { Set-Dword $wd UseLogonCredential 0 } }
if ((Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' RunAsPPL) -ne 1) { Warn 'LSA protection (RunAsPPL) is off - LSASS can be dumped; harden.ps1 turns it on' }
$pp = 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
$spooler = Get-Service Spooler -ErrorAction SilentlyContinue
if ($spooler.Status -eq 'Running' -and ((Get-Reg $pp NoWarningNoElevationOnInstall) -eq 1 -or (Get-Reg $pp RestrictDriverInstallationToAdministrators) -eq 0)) {
    Crit 'Print Spooler running with unsafe Point and Print settings (PrintNightmare)'
    if (Ask 'Restrict printer driver installation to administrators?') { Set-Dword $pp RestrictDriverInstallationToAdministrators 1; Set-Dword $pp NoWarningNoElevationOnInstall 0 }
}
$wu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
if ((Get-Reg $wu WUServer) -match '^http://' -and (Get-Reg "$wu\AU" UseWUServer) -eq 1) { Crit "Windows Update uses WSUS over plain HTTP ($(Get-Reg $wu WUServer)) - fake updates can run as SYSTEM" }
$al = try { @((Get-AppLockerPolicy -Effective -ErrorAction Stop).RuleCollections | ForEach-Object { $_ }).Count } catch { 0 }
if (-not $al) { Info 'No AppLocker / WDAC rules - built-in tools (LOLBins) can run freely; -BlockLolbinEgress at least cuts their network access' }

# ------------------------------------------------------------------ LOLBins
H1 "LIVING OFF THE LAND (running now + last $Hours h of events)"
$LolCrit = '(?i)(certutil.*(-urlcache|-verifyctl|-decode|-encode|http)|bitsadmin.*(/transfer|/addfile|http)|mshta(\.exe)?["\s]+(http|javascript|vbscript)|' +
    'regsvr32.*(/i:\s*http|scrobj)|rundll32.*(javascript:|http|comsvcs.*minidump|url\.dll|advpack|ShellExec_RunDLL)|' +
    '(powershell|pwsh).*(\s-e(nc|ncodedcommand)?\s|downloadstring|downloadfile|\biex\b|invoke-expression|frombase64string|\s-w(indowstyle)?\s+h|net\.webclient|start-bitstransfer)|' +
    'wmic.*(process\s+call\s+create|/node:|shadowcopy\s+delete)|msiexec.*/q.*http|(msbuild|installutil|regasm|regsvcs)(\.exe)?.*\\(temp|users|programdata|public)\\|' +
    'cmstp.*\.inf|vssadmin.*(delete\s+shadows|create\s+shadow)|ntdsutil.*(ifm|snapshot)|reg(\.exe)?\s+save\s+hklm\\(sam|system|security)|' +
    'esentutl.*ntds|procdump.*(lsass|-ma\s)|sekurlsa|mimikatz|net1?(\.exe)?\s+(user\s+\S+\s+\S+\s+/add|localgroup\s+administrators\s+\S+\s+/add)|' +
    'schtasks.*/create.*(/ru\s+"?system|http|-enc)|certreq.*-post|hh(\.exe)?\s+http|(wscript|cscript).*\\(temp|appdata|public|programdata)\\)'
$LolRecon = '(?i)(whoami(\.exe)?\s+/(priv|all|groups)|nltest.*(/domain_trusts|/dclist)|net1?(\.exe)?\s+group\s+"?domain admins|net1?(\.exe)?\s+(view|session)|' +
    'quser|query\s+user|systeminfo|tasklist\s+/v|klist|setspn\s+-[qT]|dsquery|Get-ADUser|Get-NetDomain|Invoke-.*Hound|adfind)'
# PowerShell script block text (4104) doesn't contain "powershell.exe" - match the content itself
$PsCrit = '(?i)(downloadstring|downloadfile|net\.webclient|\biex\b|invoke-expression|frombase64string|start-bitstransfer|invoke-mimikatz|' +
    'sekurlsa|amsiutils|amsiinitfailed|virtualalloc.*createthread|\[reflection\.assembly\]::load|invoke-shellcode|invoke-kerberoast|' +
    'get-gpppassword|out-minidump|minidumpwritedump)'
$ours = '(?i)\\CCDC\\|ProgramData\\CCDC|CCDC-'   # our own scripts contain these patterns - skip them
$found = $false
foreach ($p in Get-CimInstance Win32_Process | Where-Object CommandLine) {
    if ($p.CommandLine -match $ours) { continue }
    if ($p.CommandLine -match $LolCrit) { $found = $true; Crit "Running now: PID $($p.ProcessId) $($p.CommandLine)" }
}
$since = (Get-Date).AddHours(-$Hours)
$events = @()
try { $events += Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = $since } -MaxEvents 20000 -ErrorAction Stop |
          ForEach-Object { [pscustomobject]@{ Time = $_.TimeCreated; Who = $_.Properties[1].Value; Cmd = "$($_.Properties[8].Value)"; Src = '4688' } } } catch { }
try { $events += Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1; StartTime = $since } -MaxEvents 20000 -ErrorAction Stop |
          ForEach-Object { [pscustomobject]@{ Time = $_.TimeCreated; Who = $_.Properties[12].Value; Cmd = "$($_.Properties[10].Value)"; Src = 'sysmon' } } } catch { }
try { $events += Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; StartTime = $since } -MaxEvents 5000 -ErrorAction Stop |
          Where-Object { "$($_.Properties[4].Value)" -notmatch $ours } |
          ForEach-Object { [pscustomobject]@{ Time = $_.TimeCreated; Who = "$($_.UserId)"; Cmd = "$($_.Properties[2].Value)"; Src = '4104' } } } catch { }
if (-not $events) { Info 'No process / PowerShell events to search - harden.ps1 turns on command-line auditing (4688) and script block logging (4104)' }
$critHits = @($events | Where-Object { $_.Cmd -notmatch $ours -and (($_.Cmd -match $LolCrit) -or ($_.Src -eq '4104' -and $_.Cmd -match $PsCrit)) })
foreach ($e in $critHits | Sort-Object Time -Descending | Select-Object -First 25) {
    $found = $true; $c = $e.Cmd -replace '\s+', ' '; if ($c.Length -gt 300) { $c = $c.Substring(0, 300) + '...' }
    Crit "$($e.Time) [$($e.Src)] $($e.Who): $c"
}
if ($critHits.Count -gt 25) { Warn "$($critHits.Count - 25) more LOLBin events - see the event logs / Splunk" }
$recon = @($events | Where-Object { $_.Cmd -notmatch $ours -and $_.Cmd -match $LolRecon })
if ($recon) {
    Warn "$($recon.Count) reconnaissance commands (whoami /priv, nltest, net group, BloodHound...) - check who ran them:"
    $recon | Sort-Object Time -Descending | Select-Object -First 10 | ForEach-Object { Info "  $($_.Time) $($_.Who): $(($_.Cmd -replace '\s+', ' ').Substring(0, [Math]::Min(150, ($_.Cmd -replace '\s+', ' ').Length)))" }
}
if (-not $found -and -not $recon) { Ok 'No LOLBin abuse found in running processes or recent events' }

if ($BlockLolbinEgress) {
    H1 'BLOCKING OUTBOUND NETWORK FOR LOLBINS'
    $names = 'certutil.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'cmstp.exe', 'wscript.exe', 'cscript.exe', 'hh.exe', 'certreq.exe'
    $paths = foreach ($n in $names) { "$env:SystemRoot\System32\$n"; "$env:SystemRoot\SysWOW64\$n" }
    $paths += Get-ChildItem "$env:SystemRoot\Microsoft.NET\Framework*\v*\" -Include msbuild.exe, installutil.exe, regasm.exe, regsvcs.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object FullName
    foreach ($p in $paths | Where-Object { Test-Path $_ }) {
        $rule = 'CCDC-LOLBin-Egress-' + ($p -replace '^.*\\Windows\\', '' -replace '[\\:]', '_')
        if (Get-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue) { continue }
        New-NetFirewallRule -Name $rule -DisplayName "$rule (CCDC: no network for LOLBin)" -Direction Outbound -Action Block -Program $p -Profile Any | Out-Null
        Record "firewall $rule" 'none' 'block outbound'
        Info "blocked outbound: $p"
    }
    Info 'Undo: Get-NetFirewallRule -Name CCDC-LOLBin-Egress-* | Remove-NetFirewallRule'
}

H1 'SUMMARY'
Write-Host "Critical: $script:Crit   Warnings: $script:Warn   Log: $Log$(if (Test-Path $Undo) { "   Undo record: $Undo" })"
if ($script:Crit -and -not $Fix) { Write-Host 'Fix what can be fixed: .\privesc.ps1 -Fix (asks each time); cut LOLBin network access: -BlockLolbinEgress' }
Stop-Transcript | Out-Null
if ($script:Crit) { exit 2 } elseif ($script:Warn) { exit 1 } else { exit 0 }
