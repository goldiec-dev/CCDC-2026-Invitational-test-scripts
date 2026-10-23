<#
.SYNOPSIS
Baseline hardening for the Windows machines (Windows 11, Server 2019 MSSQL, Server 2022 AD).

.DESCRIPTION
Each setting below can be switched off. Nothing here changes IIS sites, bindings
or ports, and nothing is downloaded. Every change is logged to
C:\ProgramData\CCDC\harden-<time>.log, and the previous registry values are saved
next to it so a change can be undone by hand.

-Role adds inbound allow rules (any source) for that role's scored ports BEFORE the
firewall is turned on, so a profile that was off can't start blocking a scored service:
  dc     DNS, Kerberos, LDAP, SMB, RPC, global catalog, NTP, WinRM 5985/5986 (scored)
  mssql  SMB 445, RDP 3389, SQL 1433 + whatever port sqlservr.exe listens on
  web 80,443 / ftp 21,990 / workstation none

Run from an elevated PowerShell:  .\harden.ps1 -Role mssql
#>
param(
    [ValidateSet('workstation', 'web', 'dc', 'ftp', 'mssql')]
    [string]$Role = 'workstation'
)

# ------------------------------------------------------------------ settings
$DisableRDP          = $false   # RDP may be a scored service - only disable if it isn't
$DisableSMB1         = $true
$RequireSMBSigning   = $true
$DisableLLMNR        = $true
$DisableNetBIOS      = $true
$DisableWDigest      = $true    # stops plaintext passwords being kept in memory
$EnableLSAProtection = $true    # needs a reboot to take effect
$DisableGuest        = $true
$AllowScoredPorts    = $true    # allow rules for -Role's scored ports (before the firewall goes on)
$FirewallOnAndLog    = $true    # turns profiles on and logs drops; does not change other rules
$AllowPing           = $true    # competition rule: ICMP must stay up on every system
$DefenderRealtime    = $true
$CommandLineAuditing = $true    # process creation events (4688) with command lines
$PowerShellLogging   = $true    # script block logging (event 4104)
# ---------------------------------------------------------------------------

$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Error 'Run this from an elevated (Administrator) PowerShell.' }

$OutDir = "$env:ProgramData\CCDC"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Log = Join-Path $OutDir "harden-$Stamp.log"
$Undo = Join-Path $OutDir "harden-$Stamp-previous-values.csv"

function Write-Log([string]$Message) {
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $Message"
    Write-Host $line
    Add-Content -LiteralPath $Log -Value $line
}

# Set a DWORD, creating the key if needed, and remember the old value
function Set-Dword([string]$Path, [string]$Name, [int]$Value) {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    $old = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
    [pscustomobject]@{ Path = $Path; Name = $Name; Old = $old; New = $Value } |
        Export-Csv -LiteralPath $Undo -Append -NoTypeInformation
    New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null
}

# Run one step; a failure is logged and the rest still run
function Step([string]$Name, [scriptblock]$Action) {
    try { & $Action; Write-Log "OK    $Name" }
    catch { Write-Log "FAIL  $Name : $($_.Exception.Message)" }
}

Write-Log "Hardening $env:COMPUTERNAME ($((Get-CimInstance Win32_OperatingSystem).Caption))"

if ($DisableRDP) {
    Step 'Disable RDP' { Set-Dword 'HKLM:\System\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 1 }
} else {
    Step 'Require Network Level Authentication for RDP' {
        Set-Dword 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 1
    }
}

if ($DisableSMB1) {
    Step 'Disable SMB1 server' { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force }
}
if ($RequireSMBSigning) {
    Step 'Require SMB signing (server)' { Set-SmbServerConfiguration -RequireSecuritySignature $true -Force }
    Step 'Require SMB signing (client)' {
        Set-Dword 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' 'RequireSecuritySignature' 1
    }
}

if ($DisableLLMNR) {
    Step 'Disable LLMNR' { Set-Dword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast' 0 }
}
if ($DisableNetBIOS) {
    Step 'Disable NetBIOS over TCP/IP on every interface' {
        Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' | ForEach-Object {
            Set-Dword $_.PSPath 'NetbiosOptions' 2
        }
    }
}

if ($DisableWDigest) {
    Step 'Disable WDigest plaintext credential caching' {
        Set-Dword 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' 'UseLogonCredential' 0
    }
}
if ($EnableLSAProtection) {
    Step 'Enable LSA protection (after reboot)' { Set-Dword 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'RunAsPPL' 1 }
}

if ($DisableGuest) {
    Step 'Disable Guest account' {
        $guest = Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }
        if ($guest) { Disable-LocalUser -SID $guest.SID }
    }
}

if ($AllowScoredPorts) {
    $tcp = switch ($Role) {
        'dc'    { @(53, 88, 135, 389, 445, 464, 636, 3268, 3269, 5985, 5986) }
        'mssql' { @(445, 1433, 3389) }
        'web'   { @(80, 443) }
        'ftp'   { @(21, 990) }
        default { @() }
    }
    $udp = if ($Role -eq 'dc') { @(53, 88, 123, 389, 464) } else { @() }
    if ($Role -eq 'mssql') {
        # Named instances often listen on a non-default port
        $sql = @(Get-Process sqlservr -ErrorAction SilentlyContinue | ForEach-Object Id)
        if ($sql) { $tcp += @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $sql -contains $_.OwningProcess } | ForEach-Object { [int]$_.LocalPort }) }
        else { Write-Log 'WARN  sqlservr.exe is not running - only port 1433 allowed; check SQL Server Configuration Manager' }
    }
    foreach ($r in @(@{ Proto = 'TCP'; Ports = @($tcp | Sort-Object -Unique) }, @{ Proto = 'UDP'; Ports = @($udp) })) {
        if (-not $r.Ports) { continue }
        $ruleName = "CCDC-Scored-$Role-$($r.Proto)"
        Step "Allow scored $($r.Proto) ports in from anywhere: $($r.Ports -join ',')" {
            Remove-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
            New-NetFirewallRule -Name $ruleName -DisplayName "$ruleName (CCDC: scored services)" -Direction Inbound -Action Allow `
                -Protocol $r.Proto -LocalPort $r.Ports -Profile Any -ErrorAction Stop | Out-Null
        }
    }
}

if ($FirewallOnAndLog) {
    Step 'Firewall on for all profiles, log dropped packets' {
        Set-NetFirewallProfile -All -Enabled True -LogBlocked True -LogMaxSizeKilobytes 16384
    }
}

if ($AllowPing) {
    # Windows blocks inbound echo requests by default on most profiles
    Step 'Allow inbound ping (ICMPv4/ICMPv6 echo request) - competition rule' {
        foreach ($r in @(@{ Name = 'CCDC-Ping-v4'; Proto = 'ICMPv4'; Type = '8' }, @{ Name = 'CCDC-Ping-v6'; Proto = 'ICMPv6'; Type = '128' })) {
            Remove-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue
            New-NetFirewallRule -Name $r.Name -DisplayName "$($r.Name) (CCDC: keep ICMP up)" -Direction Inbound -Action Allow `
                -Protocol $r.Proto -IcmpType $r.Type -Profile Any -ErrorAction Stop | Out-Null
        }
    }
}

if ($DefenderRealtime) {
    Step 'Defender real-time protection on' {
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false
    }
}

if ($CommandLineAuditing) {
    Step 'Audit process creation with command lines' {
        auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null
        Set-Dword 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled' 1
    }
}
if ($PowerShellLogging) {
    Step 'PowerShell script block logging' {
        Set-Dword 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging' 1
    }
}

Write-Log "Done. Log: $Log   Previous values: $Undo"
if ($EnableLSAProtection) { Write-Log 'Reboot when convenient for LSA protection to take effect.' }
