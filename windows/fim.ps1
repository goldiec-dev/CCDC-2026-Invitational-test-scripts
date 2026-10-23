<#
.SYNOPSIS
File integrity monitor for the important system folders on Windows 11 / Server 2019.

.DESCRIPTION
  init     Baseline every watched file. Run it AFTER the machine is hardened and audited.
  check    Compare once and report (exit 1 if anything changed)
  watch    Check every -Interval seconds until stopped; each change is reported once
  accept   After a change you made on purpose, take -Path files/folders into the baseline
           (no -Path: re-baseline everything)
  list     Show what is watched

Watched: hosts file folder, scheduled task files, Group Policy scripts, startup folders
(machine and every user), PowerShell profiles, OpenSSH config and keys, our own watcher scripts
(C:\ProgramData\CCDC\bin), the top-level
System32 programs (sethc.exe, utilman.exe, ...), and on -Role web the IIS config and
IIS modules. Add more with -ExtraPaths at init (or WIN_FIM_EXTRA_PATHS via deploy.ps1).
The IIS site itself is covered by webguard.ps1.

Alert only: nothing is changed or restored. Changed and new files are copied to the
evidence folder, with a diff against the baseline copy for text files. Alerts go to the
Application event log (source CCDC-FIM, event 4300) so Splunk sees them.

Only file size and timestamps are compared on most passes; every file is re-hashed on
the first pass and every 10th, which catches faked timestamps.

.EXAMPLE
.\fim.ps1 init -Role web
.\fim.ps1 watch
.\fim.ps1 accept -Path C:\Windows\System32\drivers\etc\hosts
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('init', 'check', 'watch', 'accept', 'list')]
    [string]$Command,
    [ValidateSet('workstation', 'web')]
    [string]$Role = 'workstation',
    [string[]]$Path = @(),
    [string[]]$ExtraPaths = @(),
    [int]$Interval = 60,
    [string]$Store = "$env:ProgramData\CCDC\fim"
)

$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host 'Run this from an elevated (Administrator) PowerShell.' -ForegroundColor Red; exit 1 }

$Baseline   = Join-Path $Store 'baseline.csv'
$ConfigFile = Join-Path $Store 'config.json'
$Copies     = Join-Path $Store 'copies'
$Evidence   = Join-Path $Store 'evidence'
$LogFile    = Join-Path $Store 'fim.log'
$FullEvery  = 10
$BinaryExt  = @('.exe', '.dll', '.sys', '.cpl', '.ocx', '.scr', '.msi', '.zip', '.pol')

function Write-Log([string]$Message) {
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $Message"
    Write-Host $line
    Add-Content -LiteralPath $LogFile -Value $line -ErrorAction SilentlyContinue
    try {
        if (-not [Diagnostics.EventLog]::SourceExists('CCDC-FIM')) { New-EventLog -LogName Application -Source CCDC-FIM }
        Write-EventLog -LogName Application -Source CCDC-FIM -EventId 4300 -EntryType Warning -Message $Message
    } catch { }
}

# ------------------------------------------------------------------ what to watch
# Rebuilt on every pass so new user profiles are covered.
function Get-WatchList {
    $sys = "$env:windir\System32"
    $list = @(
        @{ Path = "$sys\drivers\etc";  Recurse = $true; Copy = $true }
        @{ Path = "$sys\Tasks";        Recurse = $true; Copy = $true }
        @{ Path = "$sys\GroupPolicy";  Recurse = $true; Copy = $true }
        @{ Path = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"; Recurse = $true; Copy = $true }
        @{ Path = "$env:ProgramData\ssh"; Recurse = $true; Copy = $true }
        @{ Path = $PSHOME;             Include = @('*profile*.ps1'); Copy = $true }
        @{ Path = $sys;                Include = @('*.exe') }
        @{ Path = "$env:ProgramData\CCDC\bin"; Recurse = $true; Copy = $true }   # our own watchers
    )
    foreach ($u in Get-ChildItem "$env:SystemDrive\Users" -Directory -Force -ErrorAction SilentlyContinue) {
        $list += @{ Path = "$($u.FullName)\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"; Recurse = $true; Copy = $true }
        $list += @{ Path = "$($u.FullName)\Documents\WindowsPowerShell"; Include = @('*profile*.ps1'); Copy = $true }
        $list += @{ Path = "$($u.FullName)\Documents\PowerShell"; Include = @('*profile*.ps1'); Copy = $true }
        $list += @{ Path = "$($u.FullName)\.ssh"; Recurse = $true; Copy = $true }
    }
    if ($script:Cfg.Role -eq 'web') {
        $list += @{ Path = "$sys\inetsrv\config"; Recurse = $true; Copy = $true }
        $list += @{ Path = "$sys\inetsrv"; Include = @('*.dll', '*.exe') }
    }
    foreach ($p in @($script:Cfg.ExtraPaths)) { if ($p) { $list += @{ Path = $p; Recurse = $true; Copy = $true } } }
    $list
}
# Files that change on their own
$ExcludeLike = @('*\ssh\logs\*', '*\inetsrv\config\history\*', '*\inetsrv\config\schema\*.tmp')

function Get-Files {
    $seen = @{}
    foreach ($w in Get-WatchList) {
        if (-not (Test-Path -LiteralPath $w.Path)) { continue }
        $items = if ($w.Recurse) {
            Get-ChildItem -LiteralPath $w.Path -File -Force -Recurse -ErrorAction SilentlyContinue
        } elseif (Test-Path -LiteralPath $w.Path -PathType Leaf) {
            Get-Item -LiteralPath $w.Path -Force
        } else {
            Get-ChildItem -LiteralPath $w.Path -File -Force -ErrorAction SilentlyContinue
        }
        foreach ($i in $items) {
            if ($seen.ContainsKey($i.FullName)) { continue }
            if ($w.Include -and -not ($w.Include | Where-Object { $i.Name -like $_ })) { continue }
            $full = $i.FullName
            if ($ExcludeLike | Where-Object { $full -like $_ }) { continue }
            $seen[$full] = $true
            [pscustomobject]@{
                Path = $full; Hash = ''; Length = $i.Length
                Write = $i.LastWriteTimeUtc.Ticks; Created = $i.CreationTimeUtc.Ticks
                Attr = [int]$i.Attributes -band -bnot 32; Copy = [bool]$w.Copy   # ignore the Archive bit
            }
        }
    }
}

# Hash files that are new or whose size/timestamps changed, or all of them when $Full
function Get-State($Previous, [bool]$Full) {
    $state = @{}
    foreach ($f in Get-Files) {
        $p = if ($Previous) { $Previous[$f.Path] } else { $null }
        if (-not $Full -and $p -and $p.Hash -ne 'UNREADABLE' -and "$($p.Length)" -eq "$($f.Length)" -and
            "$($p.Write)" -eq "$($f.Write)" -and "$($p.Created)" -eq "$($f.Created)") {
            $f.Hash = $p.Hash
        } else {
            try   { $f.Hash = (Get-FileHash -LiteralPath $f.Path -Algorithm SHA256).Hash }
            catch { $f.Hash = 'UNREADABLE' }
        }
        $state[$f.Path] = $f
    }
    $state
}

function Read-Baseline {
    $b = @{}
    Import-Csv -LiteralPath $Baseline | ForEach-Object { $b[$_.Path] = $_ }
    $b
}

function Save-Baseline($State) {
    $State.Values | Sort-Object Path | Select-Object Path, Hash, Length, Write, Created, Attr, Copy |
        Export-Csv -LiteralPath $Baseline -NoTypeInformation
}

function Get-CopyPath([string]$File) { Join-Path $Copies ($File -replace ':', '') }

function Save-Copies($Files) {
    foreach ($f in $Files) {
        if ("$($f.Copy)" -ne 'True' -or [int64]$f.Length -gt 1MB) { continue }
        $dest = Get-CopyPath $f.Path
        try {
            New-Item -ItemType Directory -Force -Path (Split-Path $dest) | Out-Null
            Copy-Item -LiteralPath $f.Path -Destination $dest -Force
        } catch { }
    }
}

function Get-Changes($Base, $State) {
    $out = @(foreach ($k in $State.Keys) {
        $s = $State[$k]
        if (-not $Base.ContainsKey($k)) {
            [pscustomobject]@{ Type = 'NEW'; Detail = $s.Hash; Path = $k }
        } elseif ($Base[$k].Hash -ne $s.Hash) {
            [pscustomobject]@{ Type = 'CHANGED'; Detail = $s.Hash; Path = $k }
        } elseif ("$($Base[$k].Attr)" -ne "$($s.Attr)") {
            $old = [IO.FileAttributes][int]$Base[$k].Attr; $new = [IO.FileAttributes][int]$s.Attr
            [pscustomobject]@{ Type = 'ATTRIBUTES'; Detail = "$old -> $new"; Path = $k }
        }
    })
    $out += @(foreach ($k in $Base.Keys) {
        if (-not $State.ContainsKey($k)) { [pscustomobject]@{ Type = 'DELETED'; Detail = '-'; Path = $k } }
    })
    $out | Sort-Object Path
}

function Invoke-Handle($Change, [string]$EvidenceDir) {
    switch ($Change.Type) {
        'ATTRIBUTES' { Write-Log "ATTRIBUTES: $($Change.Path) ($($Change.Detail))" }
        default      { Write-Log "$($Change.Type): $($Change.Path)" }
    }
    if ($Change.Type -notin 'CHANGED', 'NEW' -or -not (Test-Path -LiteralPath $Change.Path -PathType Leaf)) { return }
    $item = Get-Item -LiteralPath $Change.Path -Force
    if ($item.Length -le 50MB) {
        $saved = Join-Path $EvidenceDir ('files\' + ($Change.Path -replace ':', ''))
        New-Item -ItemType Directory -Force -Path (Split-Path $saved) | Out-Null
        Copy-Item -LiteralPath $Change.Path -Destination $saved -Force -ErrorAction SilentlyContinue
    }
    if ($BinaryExt -contains $item.Extension.ToLower() -or $item.Length -gt 1MB) { return }
    $diffFile = Join-Path $EvidenceDir 'changes.diff'
    try {
        $orig = Get-CopyPath $Change.Path
        if ($Change.Type -eq 'CHANGED' -and (Test-Path -LiteralPath $orig)) {
            $before = @(Get-Content -LiteralPath $orig) + ''
            $after  = @(Get-Content -LiteralPath $Change.Path) + ''
            $diff = Compare-Object $before $after |
                ForEach-Object { if ($_.SideIndicator -eq '=>') { "+ $($_.InputObject)" } else { "- $($_.InputObject)" } }
            Add-Content -LiteralPath $diffFile -Value (@("=== CHANGED $($Change.Path)") + @($diff))
        } elseif ($Change.Type -eq 'NEW') {
            Add-Content -LiteralPath $diffFile -Value (@("=== NEW $($Change.Path)") + @(Get-Content -LiteralPath $Change.Path -TotalCount 50))
        }
    } catch { }
}

# Reports only changes not already reported last pass
$script:Previous = @()
function Invoke-Report($State) {
    $changes = @(Get-Changes (Read-Baseline) $State)
    $keys = @($changes | ForEach-Object { "$($_.Type)|$($_.Detail)|$($_.Path)" })
    $new = @($changes | Where-Object { $script:Previous -notcontains "$($_.Type)|$($_.Detail)|$($_.Path)" })
    $script:Previous = $keys
    if ($new.Count -eq 0) { return $false }
    $ev = Join-Path $Evidence (Get-Date -Format 'yyyyMMdd-HHmmss')
    New-Item -ItemType Directory -Force -Path $ev | Out-Null
    foreach ($c in $new) {
        try { Invoke-Handle $c $ev } catch { Write-Log "  ERROR handling $($c.Path): $_" }
    }
    Write-Log "$($new.Count) change(s). Evidence: $ev  If you made the change: .\fim.ps1 accept -Path <file>"
    return $true
}

function Load-Store {
    if (-not (Test-Path -LiteralPath $ConfigFile) -or -not (Test-Path -LiteralPath $Baseline)) {
        Write-Host 'No baseline. Run: .\fim.ps1 init' -ForegroundColor Red; exit 1
    }
    $script:Cfg = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json
}

function Invoke-Init {
    if (Test-Path -LiteralPath $Store) {
        $old = "$Store.old-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        Move-Item -LiteralPath $Store -Destination $old
        Write-Host "Previous baseline kept in $old"
    }
    New-Item -ItemType Directory -Force -Path $Copies, $Evidence | Out-Null
    # Administrators and SYSTEM only
    icacls $Store /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' | Out-Null
    $script:Cfg = [pscustomobject]@{ Role = $Role; ExtraPaths = @($ExtraPaths | Where-Object { $_ }) }
    $script:Cfg | ConvertTo-Json | Set-Content -LiteralPath $ConfigFile
    Write-Host 'Hashing watched files...'
    $state = Get-State $null $true
    Save-Baseline $state
    Save-Copies $state.Values
    $sum = (Get-FileHash -LiteralPath $Baseline -Algorithm SHA256).Hash
    Write-Host "Baseline: $($state.Count) files -> $Store"
    Write-Log "Baseline taken (role $Role, $($state.Count) files, sha256 $sum)"
}

# ------------------------------------------------------------------ commands
switch ($Command) {
    'init' { Invoke-Init }

    'list' {
        Load-Store
        Get-WatchList | ForEach-Object {
            $how = if ($_.Include) { "files $($_.Include -join ', ')" } elseif ($_.Recurse) { 'everything below' } else { 'files' }
            $here = if (Test-Path -LiteralPath $_.Path) { '' } else { '  (not present)' }
            Write-Host ("  {0}  [{1}]{2}" -f $_.Path, $how, $here)
        }
    }

    'check' {
        Load-Store
        if (Invoke-Report (Get-State $null $true)) { exit 1 } else { Write-Host 'No changes.'; exit 0 }
    }

    'accept' {
        Load-Store
        if ($Path.Count -eq 0) {
            $a = Read-Host 'Re-baseline EVERY watched file? Only if the machine is known clean. [y/N]'
            if ($a -notmatch '^[Yy]') { exit 1 }
            $Role = $script:Cfg.Role; $ExtraPaths = @($script:Cfg.ExtraPaths)
            Invoke-Init
            break
        }
        $prefixes = @($Path | ForEach-Object { [IO.Path]::GetFullPath($_).TrimEnd('\') })
        function Test-Under([string]$p) {
            foreach ($x in $prefixes) {
                if ($p -eq $x -or $p.StartsWith("$x\", [StringComparison]::OrdinalIgnoreCase)) { return $true }
            }
            $false
        }
        $state = Get-State $null $true
        $base = Read-Baseline
        foreach ($k in @($base.Keys)) { if (Test-Under $k) { $base.Remove($k) } }
        $accepted = @($state.Values | Where-Object { Test-Under $_.Path })
        foreach ($f in $accepted) { $base[$f.Path] = $f }
        Save-Baseline $base
        Save-Copies $accepted
        $sum = (Get-FileHash -LiteralPath $Baseline -Algorithm SHA256).Hash
        Write-Log "Accepted current state of $($prefixes -join ', ') ($($accepted.Count) files) into the baseline, sha256 $sum"
    }

    'watch' {
        Load-Store
        Write-Log "Watching (role $($script:Cfg.Role)) every ${Interval}s, full re-hash every $FullEvery passes"
        $sum = (Get-FileHash -LiteralPath $Baseline -Algorithm SHA256).Hash
        $state = $null
        $pass = 0
        while ($true) {
            try {
                $now = (Get-FileHash -LiteralPath $Baseline -Algorithm SHA256).Hash
                if ($now -ne $sum) {
                    Write-Log "Baseline file changed since the last pass (fim.ps1 accept, or someone tampering) - now sha256 $now"
                    $sum = $now
                }
                $state = Get-State $state (($pass % $FullEvery) -eq 0)
                [void](Invoke-Report $state)
            } catch {
                Write-Log "ERROR during check: $_"
            }
            $pass++
            Start-Sleep -Seconds $Interval
        }
    }
}
