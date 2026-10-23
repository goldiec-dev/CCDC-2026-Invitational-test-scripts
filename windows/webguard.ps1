<#
.SYNOPSIS
Web defacement guard for IIS: baseline a web root, detect changes, optionally restore.

.DESCRIPTION
  init     Take a known-good baseline. Look at the site in a browser first!
  check    Compare once against the baseline and report (exit 1 if changed)
  watch    Check every -Interval seconds until stopped
  restore  Put every changed/deleted file back and quarantine new ones, now

Directories with legit runtime writes (App_Data, uploads, cache, temp, logs) are
excluded automatically; add more with -Exclude. New or changed SCRIPT files
(.aspx, .config, .php, .exe, ...) inside excluded directories are still caught -
that is where webshells get uploaded.

Re-run init after any legitimate site change (e.g. an inject asks you to edit a
page), or -AutoRestore will revert it. Nothing is ever deleted: modified and new
files are copied to the evidence folder first, for incident reports. Alerts also
go to the Application event log (source WebGuard) so Splunk picks them up.

.EXAMPLE
.\webguard.ps1 init -WebRoot C:\inetpub\wwwroot
.\webguard.ps1 watch -AutoRestore
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('init', 'check', 'watch', 'restore')]
    [string]$Command,
    [string]$WebRoot = 'C:\inetpub\wwwroot',
    [string[]]$Exclude = @(),
    [switch]$AutoRestore,
    [int]$Interval = 15,
    [string]$Store = "$env:ProgramData\WebGuard"
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $WebRoot -PathType Container)) { Write-Error "Web root not found: $WebRoot" }
$WebRoot = (Resolve-Path -LiteralPath $WebRoot).Path.TrimEnd('\')
$StoreDir = Join-Path $Store ($WebRoot -replace '[:\\]', '_')
if ("$StoreDir\".StartsWith("$WebRoot\", [StringComparison]::OrdinalIgnoreCase)) { Write-Error '-Store must be outside the web root' }
$Base     = Join-Path $StoreDir 'files'
$Manifest = Join-Path $StoreDir 'manifest.csv'
$Config   = Join-Path $StoreDir 'config.json'
$Evidence = Join-Path $StoreDir 'evidence'
$LogFile  = Join-Path $Store 'webguard.log'

# Directories that legitimately change at runtime in common IIS/ASP.NET/PHP apps
$DefaultExcludes = @('App_Data', 'uploads', 'upload', 'temp', 'tmp', 'cache', 'logs', 'sessions',
                     'wp-content\uploads', 'wp-content\cache', 'media\cache')
$ScriptExt = @('.asp', '.aspx', '.ashx', '.asmx', '.ascx', '.cshtml', '.config', '.php', '.phtml',
               '.jsp', '.cgi', '.pl', '.py', '.ps1', '.bat', '.cmd', '.vbs', '.exe', '.dll')
$TextExt = @('.htm', '.html', '.css', '.js', '.txt', '.xml', '.json') + $ScriptExt

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Warning 'Not running as Administrator - restores may fail.' }

function Write-Log([string]$Message) {
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Write-Host $line
    Add-Content -LiteralPath $LogFile -Value $line -ErrorAction SilentlyContinue
    try {
        if (-not [Diagnostics.EventLog]::SourceExists('WebGuard')) { New-EventLog -LogName Application -Source WebGuard }
        Write-EventLog -LogName Application -Source WebGuard -EventId 4100 -EntryType Warning -Message $Message
    } catch { }
}

# Manifest: SHA256 of every file outside excluded dirs, plus script files inside them
function Get-Manifest {
    Get-ChildItem -LiteralPath $WebRoot -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
        $rel = $_.FullName.Substring($WebRoot.Length + 1)
        foreach ($e in $script:Excludes) {
            if ($rel -like "$e\*" -and $ScriptExt -notcontains $_.Extension.ToLower()) { return }
        }
        try   { $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash }
        catch { $hash = 'UNREADABLE' }
        [pscustomobject]@{ Path = $rel; Hash = $hash }
    }
}

function Get-Changes {
    $baseline = @{}
    Import-Csv -LiteralPath $Manifest | ForEach-Object { $baseline[$_.Path] = $_.Hash }
    $seen = @{}
    foreach ($f in Get-Manifest) {
        $seen[$f.Path] = $true
        if (-not $baseline.ContainsKey($f.Path)) {
            [pscustomobject]@{ Type = 'NEW'; Hash = $f.Hash; Path = $f.Path }
        } elseif ($baseline[$f.Path] -ne $f.Hash) {
            [pscustomobject]@{ Type = 'MODIFIED'; Hash = $f.Hash; Path = $f.Path }
        }
    }
    foreach ($p in $baseline.Keys) {
        if (-not $seen.ContainsKey($p)) { [pscustomobject]@{ Type = 'DELETED'; Hash = '-'; Path = $p } }
    }
}

function Copy-WithRobocopy([string]$From, [string]$To) {
    # /COPY:DAT - restored files inherit the web folder's normal ACLs
    New-Item -ItemType Directory -Force -Path (Split-Path $To) | Out-Null
    robocopy (Split-Path $From) (Split-Path $To) (Split-Path $From -Leaf) /COPY:DAT /R:1 /W:1 /NJH /NJS /NP /NFL /NDL | Out-Null
    return ($LASTEXITCODE -lt 8)
}

function Invoke-Handle($Change, [string]$EvidenceDir) {
    $live  = Join-Path $WebRoot $Change.Path
    $saved = Join-Path $EvidenceDir $Change.Path
    $orig  = Join-Path $Base $Change.Path
    Write-Log "$($Change.Type): $live"

    if ($Change.Type -ne 'DELETED') {
        New-Item -ItemType Directory -Force -Path (Split-Path $saved) | Out-Null
        Copy-Item -LiteralPath $live -Destination $saved -Force -ErrorAction SilentlyContinue
    }
    if ($Change.Type -eq 'MODIFIED' -and $TextExt -contains [IO.Path]::GetExtension($live).ToLower() -and
        (Get-Item -LiteralPath $live).Length -lt 1MB) {
        # Diff is best-effort; it must never block the restore below
        try {
            $before = @(Get-Content -LiteralPath $orig) + ''
            $after  = @(Get-Content -LiteralPath $live) + ''
            $diff = Compare-Object $before $after |
                ForEach-Object { if ($_.SideIndicator -eq '=>') { "+ $($_.InputObject)" } else { "- $($_.InputObject)" } }
            Add-Content -LiteralPath (Join-Path $EvidenceDir 'changes.diff') -Value (@("=== $($Change.Path)") + @($diff))
        } catch { }
    }

    if (-not $AutoRestore) { return }
    if ($Change.Type -eq 'NEW') {
        if (Test-Path -LiteralPath $saved) {
            Remove-Item -LiteralPath $live -Force
            Write-Log "  quarantined to $saved"
        } else {
            Write-Log '  NOT quarantined: could not copy it to evidence first'
        }
    } else {
        # Remove first so we never write through a link an attacker swapped in
        if (Test-Path -LiteralPath $live) { Remove-Item -LiteralPath $live -Force }
        if (Copy-WithRobocopy $orig $live) { Write-Log '  restored from baseline' }
        else { Write-Log '  RESTORE FAILED' }
    }
}

function Load-Config {
    if (-not (Test-Path -LiteralPath $Config) -or -not (Test-Path -LiteralPath $Manifest)) {
        Write-Error "No baseline for $WebRoot. Run: .\webguard.ps1 init -WebRoot $WebRoot"
    }
    $script:Excludes = @((Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json).Excludes)
    if ($Exclude.Count -gt 0) { Write-Host "NOTE: -Exclude is only read at init; using the baseline's list" }
}

# Runs one pass. Only reports changes not already reported last pass (for watch).
$script:Previous = @()
function Invoke-Check {
    $changes = @(Get-Changes)
    $keys = $changes | ForEach-Object { "$($_.Type)|$($_.Hash)|$($_.Path)" }
    $new = @($changes | Where-Object { $script:Previous -notcontains "$($_.Type)|$($_.Hash)|$($_.Path)" })
    $script:Previous = if ($AutoRestore) { @() } else { @($keys) }
    if ($new.Count -eq 0) { return $false }
    $ev = Join-Path $Evidence (Get-Date -Format 'yyyyMMdd-HHmmss')
    New-Item -ItemType Directory -Force -Path $ev | Out-Null
    foreach ($c in $new) {
        # One bad file (locked, vanished mid-check) must not stop the watch loop
        try { Invoke-Handle $c $ev } catch { Write-Log "  ERROR handling $($c.Path): $_" }
    }
    Write-Log "Evidence saved in $ev"
    return $true
}

switch ($Command) {
    'init' {
        $script:Excludes = @()
        foreach ($e in ($DefaultExcludes + $Exclude)) {
            $e = $e.Trim('\').Replace('/', '\')
            if (Test-Path -LiteralPath (Join-Path $WebRoot $e) -PathType Container) { $script:Excludes += $e }
        }
        if (-not (Test-Path -LiteralPath $Store)) {
            New-Item -ItemType Directory -Force -Path $Store | Out-Null
            # Administrators and SYSTEM only, so a webshell can't tamper with the baseline
            icacls $Store /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
        }
        if (Test-Path -LiteralPath $StoreDir) {
            Rename-Item -LiteralPath $StoreDir -NewName ((Split-Path $StoreDir -Leaf) + '.old-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
            Write-Host 'Previous baseline kept alongside it (.old-*)'
        }
        New-Item -ItemType Directory -Force -Path $Base | Out-Null
        @{ Excludes = $script:Excludes } | ConvertTo-Json | Set-Content -LiteralPath $Config
        $files = @(Get-Manifest)
        $files | Export-Csv -LiteralPath $Manifest -NoTypeInformation
        # One bulk copy of everything outside excluded dirs, then only script files inside them
        $rc = @('/E', '/COPY:DAT', '/R:1', '/W:1', '/NJH', '/NJS', '/NP', '/NFL', '/NDL')
        $xd = @($script:Excludes | ForEach-Object { Join-Path $WebRoot $_ })
        if ($xd.Count -gt 0) { robocopy $WebRoot $Base @rc /XD @xd | Out-Null } else { robocopy $WebRoot $Base @rc | Out-Null }
        $patterns = @($ScriptExt | ForEach-Object { "*$_" })
        foreach ($e in $script:Excludes) {
            robocopy (Join-Path $WebRoot $e) (Join-Path $Base $e) @patterns @rc | Out-Null
        }
        if ($LASTEXITCODE -ge 8) { Write-Warning 'robocopy reported errors - check the baseline folder' }
        Write-Host "Baseline of ${WebRoot}: $($files.Count) files -> $StoreDir"
        Write-Host "Excluded (runtime-writable, only script files watched): $(if ($script:Excludes) { $script:Excludes -join ', ' } else { 'none' })"
        Write-Log "Baseline taken for $WebRoot"
    }
    'check' {
        Load-Config
        if (Invoke-Check) { exit 1 } else { Write-Host 'No changes.'; exit 0 }
    }
    'restore' {
        Load-Config
        $AutoRestore = $true
        if (-not (Invoke-Check)) { Write-Host 'Nothing to restore.' }
    }
    'watch' {
        Load-Config
        $mode = if ($AutoRestore) { 'auto-restore' } else { 'alert only' }
        Write-Log "Watching $WebRoot every ${Interval}s ($mode)"
        while ($true) {
            [void](Invoke-Check)
            Start-Sleep -Seconds $Interval
        }
    }
}
