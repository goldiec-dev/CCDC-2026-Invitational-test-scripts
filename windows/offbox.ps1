<#
.SYNOPSIS
Copy this Windows machine's backups off the box - encrypted - to the vault (linux/vault.sh), and get them back.

.DESCRIPTION
  push   zips the backups (C:\CCDC-backup, the newest share backup + hashes from secure.ps1, the DNS zone
         exports C:\Windows\System32\dns\ccdc-*.bak, plus any -Include paths), encrypts the zip with the
         team backup passphrase (AES-256, the same format as `openssl enc -aes-256-cbc -pbkdf2 -iter 200000
         -md sha256`, so linux/offbox.sh decrypt can open it too), writes a .sha256, and uploads both over
         SFTP during a vault window. Password files (passwords-*.csv) are never included.
  fetch  downloads a backup the vault serves (vault.sh serve <file>), checks it, decrypts it and unzips
         it to C:\CCDC-restore-<time>.
  decrypt  decrypt + unzip a .ccdc-win.enc that's already here.

The vault person opens a window first (sudo linux/vault.sh open) and reads out its password. Outbound
TCP is allowed by the Windows firewall by default; nothing listens on this machine. Needs the built-in
OpenSSH client (sftp.exe): Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 if it's missing.

.EXAMPLE
.\offbox.ps1 push
.\offbox.ps1 push -Include 'D:\SQLBackups'
.\offbox.ps1 fetch -File DC01__20261024-091500.ccdc-win.enc
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('push', 'fetch', 'decrypt')]
    [string]$Command,
    [string]$File,
    [string[]]$Include = @(),
    [string]$Vault,
    [string]$Config = (Join-Path $PSScriptRoot '..\ccdc.conf')
)

$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this from an elevated (Administrator) PowerShell.' -ForegroundColor Red; exit 1 }

# ccdc.conf: only the simple NAME=value lines are needed here
$C = @{}
if (Test-Path -LiteralPath $Config) {
    foreach ($line in Get-Content -LiteralPath $Config) {
        if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)=("([^"]*)"|''([^'']*)''|(\S*))') {
            $C[$Matches[1]] = "$($Matches[3])$($Matches[4])$($Matches[5])"
        }
    }
}
$Port = if ($C['BACKUP_VAULT_PORT']) { $C['BACKUP_VAULT_PORT'] } else { '2222' }
if (-not $Vault) { $Vault = $C['BACKUP_VAULT'] }
if ($Command -ne 'decrypt' -and -not $Vault) { Write-Host 'Set BACKUP_VAULT in ccdc.conf (or -Vault IP)' -ForegroundColor Red; exit 1 }

$Out = "$env:ProgramData\CCDC\offbox"
New-Item -ItemType Directory -Force -Path $Out | Out-Null
icacls "$env:ProgramData\CCDC" /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
$Known = Join-Path $Out 'known_hosts'

function Ok([string]$m)   { Write-Host "[OK]   $m" -ForegroundColor Green }
function Fail([string]$m) { Write-Host "[FAIL] $m" -ForegroundColor Red; exit 1 }

function Read-Passphrase([bool]$Confirm) {
    $a = Read-Host 'Team backup passphrase' -AsSecureString
    $p = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($a))
    if ($p.Length -lt 12) { Fail 'at least 12 characters' }
    if ($Confirm) {
        $b = Read-Host 'Again' -AsSecureString
        $q = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($b))
        if ($p -ne $q) { Fail 'they don''t match' }
    }
    $p
}

# openssl enc format: "Salted__" + 8-byte salt + AES-256-CBC(PKCS7); key||IV = PBKDF2-HMAC-SHA256(pass, salt, 200000, 48)
function Get-KeyIv([string]$Pass, [byte[]]$Salt) {
    $kdf = New-Object Security.Cryptography.Rfc2898DeriveBytes($Pass, $Salt, 200000, [Security.Cryptography.HashAlgorithmName]::SHA256)
    $b = $kdf.GetBytes(48); $kdf.Dispose()
    , @($b[0..31], $b[32..47])
}
function Protect-File([string]$In, [string]$OutFile, [string]$Pass) {
    $salt = New-Object byte[] 8
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
    $k = Get-KeyIv $Pass $salt
    $aes = [Security.Cryptography.Aes]::Create()
    $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = [byte[]]$k[0]; $aes.IV = [byte[]]$k[1]
    $fo = [IO.File]::Create($OutFile)
    try {
        $fo.Write([Text.Encoding]::ASCII.GetBytes('Salted__'), 0, 8); $fo.Write($salt, 0, 8)
        $cs = New-Object Security.Cryptography.CryptoStream($fo, $aes.CreateEncryptor(), [Security.Cryptography.CryptoStreamMode]::Write)
        $fi = [IO.File]::OpenRead($In)
        try { $fi.CopyTo($cs); $cs.FlushFinalBlock() } finally { $fi.Close(); $cs.Close() }
    } finally { $fo.Close(); $aes.Dispose() }
}
function Unprotect-File([string]$In, [string]$OutFile, [string]$Pass) {
    $fi = [IO.File]::OpenRead($In)
    try {
        $hdr = New-Object byte[] 16
        if ($fi.Read($hdr, 0, 16) -ne 16 -or [Text.Encoding]::ASCII.GetString($hdr, 0, 8) -ne 'Salted__') { throw 'not an encrypted backup' }
        $k = Get-KeyIv $Pass ([byte[]]$hdr[8..15])
        $aes = [Security.Cryptography.Aes]::Create()
        $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = [byte[]]$k[0]; $aes.IV = [byte[]]$k[1]
        $cs = New-Object Security.Cryptography.CryptoStream($fi, $aes.CreateDecryptor(), [Security.Cryptography.CryptoStreamMode]::Read)
        $fo = [IO.File]::Create($OutFile)
        try { $cs.CopyTo($fo) } finally { $fo.Close(); $cs.Close() }
    } finally { $fi.Close() }
}
function Write-Sha256([string]$Path) {
    $h = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
    [IO.File]::WriteAllText("$Path.sha256", "$h  $(Split-Path $Path -Leaf)`n")    # sha256sum format, LF
}
function Test-Sha256([string]$Path) {
    $want = ((Get-Content -LiteralPath "$Path.sha256" -Raw) -split '\s+')[0]
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower() -eq $want.ToLower()
}
function Invoke-VaultSftp([string[]]$Commands) {
    if (-not (Get-Command sftp.exe -ErrorAction SilentlyContinue)) { Fail 'sftp.exe missing: Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0' }
    # BatchMode=no before -b: ssh keeps the first value, so the password prompt still works
    $Commands | & sftp.exe -o BatchMode=no -b - -P $Port -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$Known" `
        -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o ConnectTimeout=10 "ccdc-vault@$Vault"
    $LASTEXITCODE -eq 0
}
function Show-HostKey {
    $fp = & ssh-keygen.exe -l -F "[$Vault]:$Port" -f $Known 2>$null | Where-Object { $_ -notmatch '^#' } | Select-Object -First 1
    if ($fp) { Write-Host "Vault host key: $(($fp -split '\s+')[1..2] -join ' ')  - must match one shown on the vault's screen" }
}
function Expand-Backup([string]$Zip) {
    $dest = "C:\CCDC-restore-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Expand-Archive -LiteralPath $Zip -DestinationPath $dest
    Ok "unpacked to $dest - copy back what you need (see checklists/BACKUP_AND_RECOVERY.md)"
}

switch ($Command) {
    'push' {
        $paths = @()
        foreach ($p in @('C:\CCDC-backup') + $Include) { if (Test-Path -LiteralPath $p) { $paths += $p } }
        $share = Get-ChildItem "$env:ProgramData\CCDC" -Directory -Filter 'share-backup-*' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1
        if ($share) { $paths += $share.FullName }
        $paths += @(Get-ChildItem "$env:ProgramData\CCDC" -Filter 'share-*-hashes-*.csv' -ErrorAction SilentlyContinue | ForEach-Object FullName)
        $paths += @(Get-ChildItem "$env:SystemRoot\System32\dns" -Filter 'ccdc-*.bak' -ErrorAction SilentlyContinue | ForEach-Object FullName)
        $paths = @($paths | Where-Object { $_ -notmatch 'passwords-.*\.csv$' })
        if (-not $paths) { Fail 'nothing to send: make the backups in the checklist''s section 0 first (C:\CCDC-backup)' }
        $paths | ForEach-Object { Write-Host "  including $_" }
        $name = "$($env:COMPUTERNAME)__$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        $zip = Join-Path $Out "$name.zip"
        Compress-Archive -LiteralPath $paths -DestinationPath $zip -CompressionLevel Optimal
        $pass = Read-Passphrase $true
        $enc = Join-Path $Out "$name.ccdc-win.enc"
        Protect-File $zip $enc $pass
        Remove-Item -LiteralPath $zip
        Write-Sha256 $enc
        Ok "encrypted: $enc ($([math]::Round((Get-Item $enc).Length / 1MB, 1)) MB)"
        Write-Host "Uploading to ${Vault}:$Port - type the vault window's password:"
        $e = $enc -replace '\\', '/'
        if (Invoke-VaultSftp @("put `"$e`" /incoming/", "put `"$e.sha256`" /incoming/")) {
            Ok "uploaded $(Split-Path $enc -Leaf) - the vault checks it when its window closes"; Show-HostKey
        } else { Fail "upload failed (window open? right password? ping $Vault)" }
    }
    'fetch' {
        if (-not $File) { Fail '-File <name> (the vault person runs: vault.sh serve <name>)' }
        $name = Split-Path $File -Leaf
        $o = $Out -replace '\\', '/'
        Write-Host "Downloading $name from ${Vault}:$Port - type the vault window's password:"
        if (-not (Invoke-VaultSftp @("get /outgoing/$name `"$o/`"", "get /outgoing/$name.sha256 `"$o/`""))) { Fail 'download failed' }
        Show-HostKey
        $enc = Join-Path $Out $name
        if (-not (Test-Sha256 $enc)) { Fail 'checksum mismatch - not using it' }
        Ok 'checksum OK'
        $zip = $enc -replace '\.enc$', '.zip'
        try { Unprotect-File $enc $zip (Read-Passphrase $false) } catch { Fail 'could not decrypt - wrong passphrase or damaged file' }
        Expand-Backup $zip
    }
    'decrypt' {
        if (-not $File -or -not (Test-Path -LiteralPath $File)) { Fail '-File <path to .ccdc-win.enc>' }
        $zip = $File -replace '\.enc$', '.zip'
        try { Unprotect-File $File $zip (Read-Passphrase $false) } catch { Fail 'could not decrypt - wrong passphrase or damaged file' }
        Expand-Backup $zip
    }
}
