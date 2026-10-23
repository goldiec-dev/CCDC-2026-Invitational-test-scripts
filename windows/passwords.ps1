<#
.SYNOPSIS
Change every local account password and apply the password policy (Windows 11 / Server 2019).

.DESCRIPTION
- You type a new password for the account you are logged in as; every other local
  account gets a random 16-character password (or use -OnePassword).
- Disabled accounts get a new password too, and stay disabled.
- Services, IIS application pools and scheduled tasks that run as a local account
  get their stored password updated at the same time, so they keep working after
  a restart.
- New passwords go to C:\ProgramData\CCDC\passwords-<time>.csv, readable only by
  Administrators and SYSTEM. Scored users are printed separately - submit their
  password change right away.
- Policy: 14+ characters, complexity on, max age 90 days, min age 0, remember 5,
  account lockout OFF (the red team could use lockout against scored users).

.EXAMPLE
.\passwords.ps1 -ScoredUsers webadmin,jdoe
#>
param(
    [string[]]$ScoredUsers = @(),
    [switch]$OnePassword
)

$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Error 'Run this from an elevated (Administrator) PowerShell.' }

$OutDir = "$env:ProgramData\CCDC"
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
# Administrators and SYSTEM only
icacls $OutDir /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Csv = Join-Path $OutDir "passwords-$Stamp.csv"
$Log = Join-Path $OutDir "passwords-$Stamp.log"

function Write-Log([string]$Message, [string]$Color = 'Gray') {
    Write-Host $Message -ForegroundColor $Color
    Add-Content -LiteralPath $Log -Value "[$(Get-Date -Format 'HH:mm:ss')] $Message"
}

function New-RandomPassword {
    $chars = [char[]]'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes = New-Object byte[] 1
    do {
        $p = -join (1..16 | ForEach-Object {
            do { $rng.GetBytes($bytes) } while ($bytes[0] -ge (256 - (256 % $chars.Length)))
            $chars[$bytes[0] % $chars.Length]
        })
    } until ($p -cmatch '[A-Z]' -and $p -cmatch '[a-z]' -and $p -match '[0-9]')
    $p
}

function Read-NewPassword([string]$Prompt) {
    while ($true) {
        $a = Read-Host -Prompt $Prompt -AsSecureString
        $b = Read-Host -Prompt 'Again' -AsSecureString
        $pa = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($a))
        $pb = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($b))
        if ($pa -ne $pb)              { Write-Host 'Did not match.' -ForegroundColor Yellow }
        elseif ($pa.Length -lt 14)    { Write-Host 'Use at least 14 characters.' -ForegroundColor Yellow }
        elseif ($pa -notmatch '^[A-Za-z0-9_-]+$') { Write-Host 'Letters, digits, - and _ only.' -ForegroundColor Yellow }
        else { return $pa }
    }
}

if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
    Write-Log 'This machine is domain-joined: only LOCAL accounts are changed here. Domain accounts must be changed on the domain controller.' 'Yellow'
}

# ------------------------------------------------------------- who runs as whom
$me = $env:USERNAME
$computer = $env:COMPUTERNAME
function Get-LocalName([string]$Account) {
    # ".\user", "COMPUTER\user" or "user" -> "user" if that local user exists;
    # domain and built-in accounts (LocalSystem, NT AUTHORITY\...) -> $null
    $name = $null
    if ($Account -match '^(\.|' + [regex]::Escape($computer) + ')\\(.+)$') { $name = $Matches[2] }
    elseif ($Account -and $Account -notmatch '\\|@') { $name = $Account }
    if ($name -and (Get-LocalUser -Name $name -ErrorAction SilentlyContinue)) { return $name }
    return $null
}

$services = @(Get-CimInstance Win32_Service | Where-Object { Get-LocalName $_.StartName })
$tasks = @(Get-ScheduledTask | Where-Object { $_.Principal.LogonType -eq 'Password' -and (Get-LocalName $_.Principal.UserId) })
$appPools = @()
if (Get-Module -ListAvailable -Name WebAdministration) {
    Import-Module WebAdministration
    $appPools = @(Get-ChildItem IIS:\AppPools | Where-Object {
        $_.processModel.identityType -eq 'SpecifiedUser' -and (Get-LocalName $_.processModel.userName) })
}

# ------------------------------------------------------------- change passwords
$one = $null; $mine = $null
if ($OnePassword) { $one = Read-NewPassword 'New password for ALL local accounts' }
else { $mine = Read-NewPassword "New password for $me (you)" }

'user,password,scored,enabled,note' | Set-Content -LiteralPath $Csv
$failed = @()
foreach ($u in Get-LocalUser) {
    $sid = $u.SID.Value
    if ($sid -like '*-503' -or $sid -like '*-504') { continue }   # DefaultAccount, WDAGUtilityAccount: managed by Windows
    $pw = if ($one) { $one } elseif ($u.Name -eq $me) { $mine } else { New-RandomPassword }
    $secure = ConvertTo-SecureString $pw -AsPlainText -Force
    $notes = @()
    try {
        Set-LocalUser -SID $u.SID -Password $secure
        foreach ($s in $services | Where-Object { (Get-LocalName $_.StartName) -eq $u.Name }) {
            $r = Invoke-CimMethod -InputObject $s -MethodName Change -Arguments @{ StartName = $s.StartName; StartPassword = $pw }
            if ($r.ReturnValue -eq 0) { $notes += "service $($s.Name) updated" }
            else { $notes += "SERVICE $($s.Name) NOT UPDATED (code $($r.ReturnValue))" }
        }
        foreach ($t in $tasks | Where-Object { (Get-LocalName $_.Principal.UserId) -eq $u.Name }) {
            Set-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -User $t.Principal.UserId -Password $pw | Out-Null
            $notes += "task $($t.TaskPath)$($t.TaskName) updated"
        }
        foreach ($p in $appPools | Where-Object { (Get-LocalName $_.processModel.userName) -eq $u.Name }) {
            Set-ItemProperty "IIS:\AppPools\$($p.Name)" -Name processModel.password -Value $pw
            $notes += "app pool $($p.Name) updated"
        }
        $scored = if ($ScoredUsers -contains $u.Name) { 'yes' } else { 'no' }
        "$($u.Name),$pw,$scored,$($u.Enabled),$($notes -join '; ')" | Add-Content -LiteralPath $Csv
        Write-Log "Changed $($u.Name)$(if ($notes) { ' - ' + ($notes -join '; ') })"
    } catch {
        $failed += $u.Name
        Write-Log "FAILED $($u.Name): $($_.Exception.Message)" 'Red'
    }
}
icacls $Csv /inheritance:r /grant:r '*S-1-5-32-544:F' '*S-1-5-18:F' | Out-Null
Write-Log "New passwords: $Csv (Administrators only)" 'Green'
if ($failed) { Write-Log "Could not change: $($failed -join ', ')" 'Red' }

foreach ($s in $ScoredUsers) {
    if (-not (Get-LocalUser -Name $s -ErrorAction SilentlyContinue)) {
        Write-Log "Scored user '$s' does not exist on this machine - check the name" 'Yellow'
    }
}
$scoredRows = Import-Csv -LiteralPath $Csv | Where-Object { $_.scored -eq 'yes' }
if ($scoredRows) {
    Write-Host "`nSubmit these password changes for scored accounts NOW (Quotient > PCR tab, paste as-is):" -ForegroundColor Cyan
    $scoredRows | ForEach-Object { Write-Host "$($_.user),$($_.password)" }
} elseif (-not $ScoredUsers) {
    Write-Log 'No -ScoredUsers given - make sure scored accounts'' new passwords get submitted.' 'Yellow'
}

# ------------------------------------------------------------- policy
Write-Host ''
try {
    net accounts /minpwlen:14 /maxpwage:90 /minpwage:0 /uniquepw:5 /lockoutthreshold:0 | Out-Null
    $cfg = Join-Path $env:TEMP "secpol-$Stamp.inf"
    $db = Join-Path $env:TEMP "secpol-$Stamp.sdb"
    secedit /export /cfg $cfg /areas SECURITYPOLICY | Out-Null
    (Get-Content $cfg) -replace '^PasswordComplexity\s*=.*', 'PasswordComplexity = 1' `
                       -replace '^ClearTextPassword\s*=.*', 'ClearTextPassword = 0' | Set-Content $cfg
    secedit /configure /db $db /cfg $cfg /areas SECURITYPOLICY | Out-Null
    Remove-Item $cfg, $db -ErrorAction SilentlyContinue
    Write-Log 'Policy: 14+ chars, complexity on, max age 90 days, min age 0, remember 5, no lockout' 'Green'
} catch {
    Write-Log "Policy update failed: $($_.Exception.Message)" 'Red'
}

Write-Host "`nPasswords this script does NOT change - do these too:" -ForegroundColor Cyan
Write-Host '    - Web app / CMS admin logins and database passwords used by the IIS site'
Write-Host '    - Domain accounts (on the domain controller), firewall and router accounts'

# ------------------------------------------------------------- other sessions
Write-Host "`nOther sessions on this machine:" -ForegroundColor Cyan
$sessions = @()
try { $sessions = @(quser 2>$null | Select-Object -Skip 1) }
catch { Write-Host '    quser is not available here (Windows Home?) - check sessions in Task Manager > Users' }
$any = $false
foreach ($line in $sessions) {
    if ($line -match '^\s*(?<cur>>)?(?<user>\S+)\s+(?:(?<name>\S+)\s+)?(?<id>\d+)\s+(?<state>Active|Disc)') {
        if ($Matches.cur) { continue }
        $any = $true
        $id = $Matches.id
        $answer = Read-Host "    $($Matches.user) (session $id, $($Matches.state)) - log it off? Ask your team first [y/N]"
        if ($answer -match '^[Yy]') { logoff $id; Write-Log "Logged off session $id ($($Matches.user))" }
    }
}
if (-not $any) { Write-Host '    none' }
