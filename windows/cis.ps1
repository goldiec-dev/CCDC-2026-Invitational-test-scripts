<#
.SYNOPSIS
CIS Benchmark Level 1 controls that harden.ps1 / secure.ps1 / passwords.ps1 don't already cover, made scoring-safe.

.DESCRIPTION
Windows Server 2022 / 2019 (CIS sections 2.3, 9, 17, 18, 19) and Windows 11. Report by default; -Fix applies the
fixes, asking once per section (-Yes: don't ask). -Role: dc | mssql | workstation (deploy.ps1 passes it).

Sections:
  audit     advanced audit policy (CIS 17.x), subcategories override legacy policy, event log sizes (18.9.27)
  uac       User Account Control (2.3.17); UAC remote restrictions for local accounts (18.4.1, not on the DC)
  lsa       no LM hashes, no blank-password network logons, no anonymous enumeration (2.3.10, 2.3.11)
  smb       no insecure guest logons, SMB1 client driver off, no plaintext passwords to SMB servers (18.4, 18.6)
  network   no source routing / ICMP redirects / NetBIOS name release / mDNS (18.4, 18.6)
  autorun   AutoPlay / AutoRun off (18.9.8)
  logon     logon banner, don't show the last user, 15-minute lock, cached logons (2.3.7)
  remote    RDP: no Remote Assistance, no drive redirection, always prompt for the password, encrypted RPC (18.9.65);
            WinRM client: no Basic / Digest (18.9.102)
  printing  only admins install printer drivers (PrintNightmare) (18.4.x)
  defender  cloud protection, PUA blocking, network protection, attack surface reduction rules (18.9.47)
  powershell module logging and transcription to C:\ProgramData\CCDC\transcripts (18.9.100)
  rights    user rights: debug only for Administrators, Guests denied network/RDP/console logon (2.2) - not on the DC
  services  services CIS lists as unnecessary (5.x) - asks per service

Report only (scoring or lockout risk): account lockout (deliberately off), password minimum age (0, so passwords can
be rotated again), renaming Administrator/Guest (the rules forbid username changes), WinRM *service* Basic/unencrypted
(the scorer may use them - secure.ps1 asks), LDAP signing on the DC (the Email box binds over plain LDAP), Kerberos
AES-only, Credential Guard (reboot). Full list: checklists/CIS.md. Previous values: C:\ProgramData\CCDC\cis-<time>-undo.csv.

.EXAMPLE
.\cis.ps1 -Role mssql
.\cis.ps1 -Role dc -Fix
#>
param(
    [ValidateSet('workstation', 'web', 'dc', 'ftp', 'mssql')]
    [string]$Role = 'workstation',
    [switch]$Fix,
    [switch]$Yes,
    [string[]]$Section = @()
)

$ErrorActionPreference = 'Continue'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this from an elevated (Administrator) PowerShell.' -ForegroundColor Red; exit 1 }

$OutDir = "$env:ProgramData\CCDC"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$UndoCsv = Join-Path $OutDir "cis-$Stamp-undo.csv"
Start-Transcript -LiteralPath (Join-Path $OutDir "cis-$Stamp.log") | Out-Null

$IsDC = $Role -eq 'dc'
$IsServer = (Get-CimInstance Win32_OperatingSystem).ProductType -ne 1
$script:Fails = 0; $script:SecFails = 0
function Pass([string]$m) { Write-Host "[PASS] $m" -ForegroundColor Green }
function Fail([string]$m) { $script:Fails++; $script:SecFails++; Write-Host "[FAIL] $m" -ForegroundColor Red }
function Note([string]$m) { Write-Host "[NOTE] $m" -ForegroundColor Yellow }
function H1([string]$t)   { Write-Host "`n== $t ==" -ForegroundColor Cyan; $script:SecFails = 0 }
function Want([string]$s) { $Section.Count -eq 0 -or $Section -contains $s }
function Fixing([string]$q) {
    if (-not $Fix -or $script:SecFails -eq 0) { return $false }
    if ($Yes) { return $true }
    (Read-Host "    Fix: $q [y/N]") -match '^[Yy]'
}
function Record($What, $Old, $New) {
    [pscustomobject]@{ Time = (Get-Date -Format s); Item = $What; Old = "$Old"; New = "$New" } |
        Export-Csv -LiteralPath $UndoCsv -Append -NoTypeInformation
}

# ------------------------------------------------------------------ registry controls
# @(Path, Name, Value, Type, Roles, Title)  Roles: all | server | member | dc | workstation | nondc
function Applies([string]$r) {
    switch ($r) {
        'all' { $true } 'server' { $IsServer } 'dc' { $IsDC } 'nondc' { -not $IsDC }
        'member' { $IsServer -and -not $IsDC } 'workstation' { -not $IsServer } default { $true }
    }
}
function Test-RegControls([object[]]$Controls) {
    $bad = @()
    foreach ($c in $Controls) {
        $path, $name, $value, $type, $roles, $title = $c
        if (-not (Applies $roles)) { continue }
        $cur = (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name
        if ("$cur" -eq "$value") { Pass "$title" }
        else { Fail "$title (now: $(if ($null -eq $cur) { 'not set' } else { $cur }))"; $bad += , $c }
    }
    , $bad
}
function Set-RegControls([object[]]$Controls) {
    foreach ($c in $Controls) {
        $path, $name, $value, $type, $roles, $title = $c
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        $old = (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name
        Record "$path\$name" $old $value
        New-ItemProperty -Path $path -Name $name -Value $value -PropertyType $type -Force | Out-Null
    }
    Pass "set $($Controls.Count) value(s) (old values: $UndoCsv)"
}
function Reg-Section([string]$Title, [string]$Question, [object[]]$Controls) {
    H1 $Title
    $bad = Test-RegControls $Controls
    if ($bad.Count -and (Fixing $Question)) { Set-RegControls $bad }
}

$Lsa   = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$Sys   = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
$Srv   = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
$Wks   = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'
$TS    = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$Win   = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$Banner = (Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\checklists\motd-banner.txt') -Raw -ErrorAction SilentlyContinue)
if (-not $Banner) { $Banner = 'Authorized use only. Activity on this system is logged and monitored.' }
$Banner = ($Banner -replace '\s+', ' ').Trim()

# ============================================================================ audit
if (Want 'audit') {
    H1 'audit: advanced audit policy and log sizes (CIS 17.x, 18.9.27)'
    # subcategory GUIDs (language-independent) and what CIS wants: S = success, F = failure
    $sub = [ordered]@{
        'Credential Validation' = @('{0CCE923F-69AE-11D9-BED3-505054503030}', 'SF')
        'Kerberos Authentication Service' = @('{0CCE9242-69AE-11D9-BED3-505054503030}', 'SF')
        'Kerberos Service Ticket Operations' = @('{0CCE9240-69AE-11D9-BED3-505054503030}', 'SF')
        'Computer Account Management' = @('{0CCE9236-69AE-11D9-BED3-505054503030}', 'S')
        'Other Account Management Events' = @('{0CCE923A-69AE-11D9-BED3-505054503030}', 'S')
        'Security Group Management' = @('{0CCE9237-69AE-11D9-BED3-505054503030}', 'S')
        'User Account Management' = @('{0CCE9235-69AE-11D9-BED3-505054503030}', 'SF')
        'PNP Activity' = @('{0CCE9248-69AE-11D9-BED3-505054503030}', 'S')
        'Process Creation' = @('{0CCE922B-69AE-11D9-BED3-505054503030}', 'S')
        'Directory Service Access' = @('{0CCE923B-69AE-11D9-BED3-505054503030}', 'F')
        'Directory Service Changes' = @('{0CCE923C-69AE-11D9-BED3-505054503030}', 'S')
        'Account Lockout' = @('{0CCE9217-69AE-11D9-BED3-505054503030}', 'F')
        'Group Membership' = @('{0CCE9249-69AE-11D9-BED3-505054503030}', 'S')
        'Logoff' = @('{0CCE9216-69AE-11D9-BED3-505054503030}', 'S')
        'Logon' = @('{0CCE9215-69AE-11D9-BED3-505054503030}', 'SF')
        'Other Logon/Logoff Events' = @('{0CCE921C-69AE-11D9-BED3-505054503030}', 'SF')
        'Special Logon' = @('{0CCE921B-69AE-11D9-BED3-505054503030}', 'S')
        'Detailed File Share' = @('{0CCE9244-69AE-11D9-BED3-505054503030}', 'F')
        'File Share' = @('{0CCE9224-69AE-11D9-BED3-505054503030}', 'SF')
        'Other Object Access Events' = @('{0CCE9227-69AE-11D9-BED3-505054503030}', 'SF')
        'Removable Storage' = @('{0CCE9245-69AE-11D9-BED3-505054503030}', 'SF')
        'Audit Policy Change' = @('{0CCE922F-69AE-11D9-BED3-505054503030}', 'S')
        'Authentication Policy Change' = @('{0CCE9230-69AE-11D9-BED3-505054503030}', 'S')
        'Authorization Policy Change' = @('{0CCE9231-69AE-11D9-BED3-505054503030}', 'S')
        'MPSSVC Rule-Level Policy Change' = @('{0CCE9232-69AE-11D9-BED3-505054503030}', 'SF')
        'Other Policy Change Events' = @('{0CCE9234-69AE-11D9-BED3-505054503030}', 'F')
        'Sensitive Privilege Use' = @('{0CCE9228-69AE-11D9-BED3-505054503030}', 'SF')
        'IPsec Driver' = @('{0CCE9213-69AE-11D9-BED3-505054503030}', 'SF')
        'Other System Events' = @('{0CCE9214-69AE-11D9-BED3-505054503030}', 'SF')
        'Security State Change' = @('{0CCE9210-69AE-11D9-BED3-505054503030}', 'S')
        'Security System Extension' = @('{0CCE9211-69AE-11D9-BED3-505054503030}', 'S')
        'System Integrity' = @('{0CCE9212-69AE-11D9-BED3-505054503030}', 'SF')
    }
    if (-not $IsDC) { 'Kerberos Authentication Service', 'Kerberos Service Ticket Operations', 'Directory Service Access', 'Directory Service Changes' | ForEach-Object { $sub.Remove($_) } }
    # current settings: auditpol /r gives CSV with the GUID and "Inclusion Setting"
    $cur = @{}
    auditpol /get /category:* /r | ConvertFrom-Csv | ForEach-Object { $cur[$_.'Subcategory GUID'.ToUpper()] = $_.'Inclusion Setting' }
    $badAudit = @()
    foreach ($k in $sub.Keys) {
        $guid, $need = $sub[$k]
        $have = $cur[$guid.ToUpper()]
        $ok = ($need -notmatch 'S' -or $have -match 'Success') -and ($need -notmatch 'F' -or $have -match 'Failure')
        if (-not $ok) { $badAudit += $k }
    }
    if ($badAudit) { Fail "audit subcategories missing: $($badAudit -join ', ')" } else { Pass "all $($sub.Count) audit subcategories set" }
    $force = (Get-ItemProperty $Lsa -Name SCENoApplyLegacyAuditPolicy -ErrorAction SilentlyContinue).SCENoApplyLegacyAuditPolicy
    if ($force -eq 1) { Pass 'subcategory settings override the legacy audit policy' } else { Fail 'legacy audit policy can override subcategories (SCENoApplyLegacyAuditPolicy)' }
    $sizes = @{ Security = $(if ($IsDC) { 1GB } else { 512MB }); Application = 32MB; System = 32MB; 'Microsoft-Windows-PowerShell/Operational' = 64MB }
    $badLog = @()
    foreach ($l in $sizes.Keys) {
        $max = [long](((wevtutil gl $l 2>$null | Select-String 'maxSize:').Line) -replace '\D', '')
        if ($max -lt $sizes[$l]) { $badLog += $l; Fail "$l log max $([int]($max / 1MB)) MB (want $([int]($sizes[$l] / 1MB)) MB+)" }
    }
    if (-not $badLog) { Pass 'event log sizes OK' }
    if (Fixing 'set the audit subcategories, the override, and the log sizes') {
        foreach ($k in $badAudit) {
            $guid, $need = $sub[$k]
            $sArg = if ($need -match 'S') { '/success:enable' } else { '/success:disable' }
            $fArg = if ($need -match 'F') { '/failure:enable' } else { '/failure:disable' }
            # never turn OFF something that's already on
            if ($cur[$guid.ToUpper()] -match 'Success') { $sArg = '/success:enable' }
            if ($cur[$guid.ToUpper()] -match 'Failure') { $fArg = '/failure:enable' }
            auditpol /set /subcategory:"$guid" $sArg $fArg | Out-Null
        }
        Record "$Lsa\SCENoApplyLegacyAuditPolicy" $force 1
        New-ItemProperty $Lsa -Name SCENoApplyLegacyAuditPolicy -Value 1 -PropertyType DWord -Force | Out-Null
        foreach ($l in $badLog) { wevtutil sl $l /ms:$($sizes[$l]) }
        Pass 'audit policy and log sizes set'
    }
}

# ============================================================================ uac / lsa / smb / network / autorun / logon / remote / printing
if (Want 'uac') {
    Reg-Section 'uac: User Account Control (CIS 2.3.17, 18.4.1)' 'set the UAC values' @(
        , @($Sys, 'EnableLUA', 1, 'DWord', 'all', 'UAC on')
        , @($Sys, 'ConsentPromptBehaviorAdmin', 2, 'DWord', 'all', 'admins confirm elevation on the secure desktop')
        , @($Sys, 'ConsentPromptBehaviorUser', 0, 'DWord', 'all', 'standard users can''t elevate')
        , @($Sys, 'PromptOnSecureDesktop', 1, 'DWord', 'all', 'elevation prompt on the secure desktop')
        , @($Sys, 'FilterAdministratorToken', 1, 'DWord', 'all', 'admin approval mode for the built-in Administrator')
        , @($Sys, 'EnableInstallerDetection', 1, 'DWord', 'all', 'installers prompt for elevation')
        , @($Sys, 'LocalAccountTokenFilterPolicy', 0, 'DWord', 'nondc', 'local admin accounts get no admin rights over the network (pass-the-hash)')
    )
}
if (Want 'lsa') {
    Reg-Section 'lsa: credentials and anonymous access (CIS 2.3.10, 2.3.11)' 'set the LSA / anonymous-access values' @(
        , @($Lsa, 'NoLMHash', 1, 'DWord', 'all', 'no LM password hashes stored')
        , @($Lsa, 'LimitBlankPasswordUse', 1, 'DWord', 'all', 'blank passwords only at the console')
        , @($Lsa, 'RestrictAnonymousSAM', 1, 'DWord', 'all', 'no anonymous enumeration of accounts')
        , @($Lsa, 'RestrictAnonymous', 1, 'DWord', 'all', 'no anonymous enumeration of accounts and shares')
        , @($Lsa, 'EveryoneIncludesAnonymous', 0, 'DWord', 'all', 'Everyone doesn''t include anonymous users')
        , @($Lsa, 'ForceGuest', 0, 'DWord', 'all', 'classic sharing model (local users authenticate as themselves)')
        , @($Srv, 'RestrictNullSessAccess', 1, 'DWord', 'all', 'no null-session access to shares and pipes')
        , @("$Lsa\MSV1_0", 'allownullsessionfallback', 0, 'DWord', 'all', 'no NULL session fallback for LocalSystem')
    )
}
if (Want 'smb') {
    H1 'smb: SMB client settings (CIS 18.4, 18.6)'
    $ctl = @(
        , @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation', 'AllowInsecureGuestAuth', 0, 'DWord', 'all', 'no insecure guest logons to SMB servers')
        , @($Wks, 'EnablePlainTextPassword', 0, 'DWord', 'all', 'no plaintext passwords to SMB servers')
    )
    $bad = Test-RegControls $ctl
    $smb1 = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name Start -ErrorAction SilentlyContinue).Start
    if ($null -ne $smb1 -and $smb1 -ne 4) { Fail "SMB1 client driver (mrxsmb10) start = $smb1 (want 4 = disabled)"; $bad += , @('HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10', 'Start', 4, 'DWord', 'all', 'SMB1 client driver disabled') }
    else { Pass 'SMB1 client driver disabled or absent' }
    if ($bad.Count -and (Fixing 'set the SMB client values (SMB1 driver: after a reboot)')) { Set-RegControls $bad }
}
if (Want 'network') {
    Reg-Section 'network: IP / name resolution settings (CIS 18.4, 18.6)' 'set the network values' @(
        , @('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters', 'DisableIPSourceRouting', 2, 'DWord', 'all', 'IPv4 source routing off')
        , @('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters', 'DisableIPSourceRouting', 2, 'DWord', 'all', 'IPv6 source routing off')
        , @('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters', 'EnableICMPRedirect', 0, 'DWord', 'all', 'ICMP redirects ignored (ping itself stays on)')
        , @('HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters', 'NoNameReleaseOnDemand', 1, 'DWord', 'all', 'NetBIOS names not released on request')
        , @('HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters', 'EnableMDNS', 0, 'DWord', 'all', 'mDNS off (spoofable name resolution)')
    )
}
if (Want 'autorun') {
    Reg-Section 'autorun: AutoPlay / AutoRun (CIS 18.9.8)' 'turn AutoPlay / AutoRun off' @(
        , @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer', 'NoDriveTypeAutoRun', 255, 'DWord', 'all', 'AutoPlay off on every drive')
        , @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer', 'NoAutorun', 1, 'DWord', 'all', 'autorun.inf commands ignored')
        , @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer', 'NoAutoplayfornonVolume', 1, 'DWord', 'all', 'no AutoPlay for MTP devices')
    )
}
if (Want 'logon') {
    Reg-Section 'logon: interactive logon (CIS 2.3.7)' 'set the logon banner and options' @(
        , @($Sys, 'LegalNoticeCaption', 'Authorized use only', 'String', 'all', 'logon banner title')
        , @($Sys, 'LegalNoticeText', $Banner, 'String', 'all', 'logon banner text (checklists/motd-banner.txt)')
        , @($Sys, 'DontDisplayLastUserName', 1, 'DWord', 'all', 'last user name not shown')
        , @($Sys, 'DisableCAD', 0, 'DWord', 'all', 'Ctrl+Alt+Del required')
        , @($Sys, 'InactivityTimeoutSecs', 900, 'DWord', 'all', 'console locks after 15 idle minutes')
        , @($Sys, 'ShutdownWithoutLogon', 0, 'DWord', 'server', 'no shutdown from the logon screen')
        , @($Win, 'CachedLogonsCount', '4', 'String', 'nondc', 'at most 4 cached domain logons')
    )
}
if (Want 'remote') {
    Reg-Section 'remote: RDP and WinRM client (CIS 18.9.65, 18.9.102)' 'set the RDP / WinRM client values (RDP stays on)' @(
        , @($TS, 'fAllowToGetHelp', 0, 'DWord', 'all', 'no Remote Assistance')
        , @($TS, 'fDisableCdm', 1, 'DWord', 'all', 'no drive redirection over RDP')
        , @($TS, 'fPromptForPassword', 1, 'DWord', 'all', 'RDP always asks for the password')
        , @($TS, 'fEncryptRPCTraffic', 1, 'DWord', 'all', 'encrypted RDP RPC traffic')
        , @($TS, 'MinEncryptionLevel', 3, 'DWord', 'all', 'RDP high encryption')
        , @($TS, 'DeleteTempDirsOnExit', 1, 'DWord', 'all', 'RDP temp folders removed at logoff')
        , @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client', 'AllowBasic', 0, 'DWord', 'all', 'WinRM client: no Basic auth')
        , @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client', 'AllowDigest', 0, 'DWord', 'all', 'WinRM client: no Digest auth')
        , @('HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client', 'AllowUnencryptedTraffic', 0, 'DWord', 'all', 'WinRM client: no unencrypted traffic')
    )
    Note 'WinRM SERVICE settings (Basic / unencrypted) are left to secure.ps1 - the AD-WinRM scorer may depend on them'
}
if (Want 'printing') {
    Reg-Section 'printing: printer drivers (CIS 18.4 - PrintNightmare)' 'restrict printer driver installation to admins' @(
        , @('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint', 'RestrictDriverInstallationToAdministrators', 1, 'DWord', 'all', 'only admins install printer drivers')
        , @('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint', 'NoWarningNoElevationOnInstall', 0, 'DWord', 'all', 'Point and Print asks for elevation')
        , @('HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint', 'UpdatePromptSettings', 0, 'DWord', 'all', 'Point and Print updates ask for elevation')
    )
}

# ============================================================================ defender
if (Want 'defender') {
    H1 'defender: Microsoft Defender (CIS 18.9.47)'
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) -or -not (Get-Service WinDefend -ErrorAction SilentlyContinue)) { Note 'Defender not present' }
    else {
        $p = Get-MpPreference
        $want = @{ MAPSReporting = 2; SubmitSamplesConsent = 1; PUAProtection = 1; EnableNetworkProtection = 1; DisableRealtimeMonitoring = $false; DisableBehaviorMonitoring = $false; DisableScriptScanning = $false; DisableIOAVProtection = $false }
        $badDef = @()
        foreach ($k in $want.Keys) { if ("$($p.$k)" -ne "$($want[$k])") { $badDef += $k; Fail "Defender $k = $($p.$k) (want $($want[$k]))" } }
        if (-not $badDef) { Pass 'Defender protection settings OK' }
        # Attack surface reduction: a safe subset on servers, the wider set on the workstation
        $asr = [ordered]@{
            '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2' = 'credential stealing from LSASS'
            '56a863a9-875e-4185-98a7-b882c64b5ce5' = 'abuse of vulnerable signed drivers'
            'e6db77e5-3df2-4cf1-b95a-636979351e5b' = 'persistence through WMI event subscriptions'
        }
        if (-not $IsServer) {
            $asr['d4f940ab-401b-4efc-aadc-ad5f3c50688a'] = 'Office apps creating child processes'
            $asr['be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'] = 'executable content from email / webmail'
            $asr['d3e037e1-3eb8-44c8-a917-57927947596d'] = 'JavaScript / VBScript launching downloads'
            $asr['5beb7efe-fd9a-4556-801d-275e5ffc04cc'] = 'obfuscated scripts'
            $asr['d1e49aac-8f56-4280-b9ba-993a6d77406c'] = 'process creation from PsExec / WMI'
        }
        $on = @{}; for ($i = 0; $i -lt @($p.AttackSurfaceReductionRules_Ids).Count; $i++) { $on[$p.AttackSurfaceReductionRules_Ids[$i].ToLower()] = $p.AttackSurfaceReductionRules_Actions[$i] }
        $badAsr = @($asr.Keys | Where-Object { $on[$_] -ne 1 })
        if ($badAsr) { Fail "ASR rules not blocking: $(($badAsr | ForEach-Object { $asr[$_] }) -join '; ')" } else { Pass "ASR rules blocking ($($asr.Count))" }
        if (Fixing 'set Defender protection and the ASR rules (block mode)') {
            # Windows Server ignores network protection unless it's explicitly allowed there
            if ($IsServer) { Set-MpPreference -AllowNetworkProtectionOnWinServer $true -ErrorAction SilentlyContinue }
            Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -PUAProtection Enabled -EnableNetworkProtection Enabled `
                -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableScriptScanning $false -DisableIOAVProtection $false
            if ($badAsr) { Add-MpPreference -AttackSurfaceReductionRules_Ids $badAsr -AttackSurfaceReductionRules_Actions ($badAsr | ForEach-Object { 'Enabled' }) }
            Record 'Defender preferences + ASR' ($badDef + $badAsr -join ',') 'CIS values'
            Pass 'Defender set (ASR blocks: Event Viewer > Windows Defender > Operational, event 1121)'
        }
    }
}

# ============================================================================ powershell
if (Want 'powershell') {
    H1 'powershell: module logging and transcription (CIS 18.9.100)'
    $ps = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    $tdir = Join-Path $OutDir 'transcripts'
    $ctl = @(
        , @("$ps\ModuleLogging", 'EnableModuleLogging', 1, 'DWord', 'all', 'module logging on')
        , @("$ps\ScriptBlockLogging", 'EnableScriptBlockLogging', 1, 'DWord', 'all', 'script block logging on')
        , @("$ps\Transcription", 'EnableTranscripting', 1, 'DWord', 'all', 'transcription on')
        , @("$ps\Transcription", 'EnableInvocationHeader', 1, 'DWord', 'all', 'transcripts timestamp every command')
        , @("$ps\Transcription", 'OutputDirectory', $tdir, 'String', 'all', "transcripts go to $tdir")
    )
    $bad = Test-RegControls $ctl
    if ($bad.Count -and (Fixing "turn on module logging and transcription (every PowerShell session is recorded in $tdir)")) {
        Set-RegControls $bad
        if (-not (Test-Path "$ps\ModuleLogging\ModuleNames")) { New-Item "$ps\ModuleLogging\ModuleNames" -Force | Out-Null }
        New-ItemProperty "$ps\ModuleLogging\ModuleNames" -Name '*' -Value '*' -PropertyType String -Force | Out-Null
        New-Item -ItemType Directory -Force -Path $tdir | Out-Null
        # everyone can write a transcript, only admins can read them (a drop box)
        icacls $tdir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' '*S-1-5-11:(OI)(CI)W' '*S-1-3-0:(OI)(CI)(IO)F' | Out-Null
        Pass "transcripts: $tdir (users can write, only admins read)"
    }
}

# ============================================================================ rights
if (Want 'rights') {
    H1 'rights: user rights assignment (CIS 2.2)'
    if ($IsDC) { Note 'on the DC, user rights come from the Default Domain Controllers Policy GPO - change them there (local changes get overwritten)' }
    else {
        $inf = Join-Path $env:TEMP "cis-rights-$Stamp.inf"
        secedit /export /cfg $inf /areas USER_RIGHTS | Out-Null
        $cur = @{}
        foreach ($l in Get-Content $inf) { if ($l -match '^(Se\w+)\s*=\s*(.*)$') { $cur[$Matches[1]] = @($Matches[2] -split ',' | ForEach-Object { $_.Trim() }) } }
        # Guests S-1-5-32-546, Administrators S-1-5-32-544
        $need = [ordered]@{
            SeDebugPrivilege = @{ Exact = @('*S-1-5-32-544'); Title = 'debug programs: Administrators only' }
            SeDenyNetworkLogonRight = @{ Include = '*S-1-5-32-546'; Title = 'Guests denied network logon' }
            SeDenyRemoteInteractiveLogonRight = @{ Include = '*S-1-5-32-546'; Title = 'Guests denied RDP logon' }
            SeDenyInteractiveLogonRight = @{ Include = '*S-1-5-32-546'; Title = 'Guests denied console logon' }
        }
        $newLines = @()
        foreach ($r in $need.Keys) {
            $have = @($cur[$r] | Where-Object { $_ })
            $n = $need[$r]
            if ($n.Exact) {
                if ((@($have) -join ',') -eq ($n.Exact -join ',')) { Pass $n.Title } else { Fail "$($n.Title) (now: $($have -join ', '))"; $newLines += "$r = $($n.Exact -join ',')" }
            } elseif ($have -contains $n.Include) { Pass $n.Title }
            else { Fail $n.Title; $newLines += "$r = $((@($have) + $n.Include | Select-Object -Unique) -join ',')" }
        }
        if ($newLines -and (Fixing 'set these user rights (secedit)')) {
            $cfg = Join-Path $env:TEMP "cis-rights-new-$Stamp.inf"; $db = Join-Path $env:TEMP "cis-rights-$Stamp.sdb"
            @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[Privilege Rights]') + $newLines | Set-Content $cfg -Encoding Unicode
            Copy-Item $inf (Join-Path $OutDir "cis-$Stamp-rights-before.inf")
            secedit /configure /db $db /cfg $cfg /areas USER_RIGHTS | Out-Null
            Remove-Item $cfg, $db -ErrorAction SilentlyContinue
            Pass "user rights set (before: $OutDir\cis-$Stamp-rights-before.inf)"
        }
        Remove-Item $inf -ErrorAction SilentlyContinue
    }
}

# ============================================================================ services
if (Want 'services') {
    H1 'services: unnecessary services (CIS 5.x)'
    $list = [ordered]@{
        'XblAuthManager' = 'Xbox Live Auth Manager'; 'XblGameSave' = 'Xbox Live Game Save'; 'XboxNetApiSvc' = 'Xbox Live Networking'; 'XboxGipSvc' = 'Xbox Accessory Management'
        'WMPNetworkSvc' = 'Windows Media Player network sharing'; 'SharedAccess' = 'Internet Connection Sharing'; 'icssvc' = 'Mobile Hotspot'
        'lltdsvc' = 'Link-Layer Topology Discovery Mapper'; 'RpcLocator' = 'Remote Procedure Call Locator'; 'MapsBroker' = 'Downloaded Maps Manager'
        'lfsvc' = 'Geolocation'; 'PushToInstall' = 'Windows PushToInstall'
    }
    $found = @()
    foreach ($n in $list.Keys) {
        $s = Get-Service -Name $n -ErrorAction SilentlyContinue
        if ($s -and $s.StartType -ne 'Disabled') { $found += $s; Fail "$($list[$n]) ($n) is $($s.StartType) / $($s.Status)" }
    }
    if (-not $found) { Pass 'none of the listed services enabled' }
    if ($found -and $Fix) {
        foreach ($s in $found) {
            if ($Yes -or (Read-Host "    Disable $($s.DisplayName)? [y/N]") -match '^[Yy]') {
                Record "service $($s.Name)" "$($s.StartType)/$($s.Status)" 'Disabled'
                Stop-Service $s.Name -Force -ErrorAction SilentlyContinue; Set-Service $s.Name -StartupType Disabled
            }
        }
    }
}

# ============================================================================ deviations (report only)
Write-Host "`n== deliberate deviations (not changed) ==" -ForegroundColor Cyan
Note 'account lockout: off (the red team would lock out the scored users)'
Note 'password minimum age: 0 (we rotate passwords several times); history: 5'
Note 'Administrator / Guest not renamed (the rules forbid username changes)'
Note 'LDAP signing / channel binding not forced on the DC (the Email box binds over plain LDAP)'
Note 'Kerberos AES-only, Credential Guard, Secure Boot / VBS: report-only (compatibility, reboots)'
if (Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue | Where-Object { $_.SecurityServicesRunning -contains 1 }) { Pass 'Credential Guard running' }

Write-Host ''
if ($script:Fails -eq 0) { Pass 'every control passes' } else { Write-Host "$($script:Fails) control(s) not passing$(if (-not $Fix) { ' - run with -Fix to apply the safe fixes' })" -ForegroundColor Yellow }
Write-Host "Old values: $UndoCsv   Deviations and why: checklists\CIS.md"
Stop-Transcript | Out-Null
exit $(if ($script:Fails) { 1 } else { 0 })
