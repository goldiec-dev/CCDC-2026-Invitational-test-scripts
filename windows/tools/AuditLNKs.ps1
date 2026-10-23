# throws a LOT of false positives

function Test-ShortcutIntegrity {
    param (
        [string[]]$FolderPaths = @(
            "$env:USERPROFILE\Desktop",
            "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu",
            "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch",
            "$env:APPDATA\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"
        )
    )

    $shell = New-Object -ComObject WScript.Shell
    
    try {
        foreach ($folderPath in $FolderPaths) {
            if (Test-Path $folderPath) {
                Write-Host "`nChecking shortcuts in: $folderPath"
                $shortcuts = Get-ChildItem -Path $folderPath -Filter "*.lnk" -Recurse
                
                foreach ($shortcut in $shortcuts) {
                    $link = $shell.CreateShortcut($shortcut.FullName)
                    $isSuspicious = $false
                    $reason = ""

                    $chainOperators = @('&', '|', ';', '&&', '||')
                    foreach ($operator in $chainOperators) {
                        if ($link.TargetPath -like "*$operator*" -or $link.Arguments -like "*$operator*") {
                            $isSuspicious = $true
                            $reason = "Multiple commands detected"
                            break
                        }
                    }

                    # Check if target executable name matches link name
                    # TODO - account for caps lock differences
                    if (-not $isSuspicious) {
                        $shortcutNameWithoutExt = [System.IO.Path]::GetFileNameWithoutExtension($shortcut.Name)
                        $targetExeName = [System.IO.Path]::GetFileNameWithoutExtension($link.TargetPath)
                        
                        # Ignore Windows known exceptions
                        # may need more as used
                        $knownExceptions = @(
                            @{Link = "Chrome"; Target = "chrome"},
                            @{Link = "Word"; Target = "WINWORD"},
                            @{Link = "Excel"; Target = "EXCEL"},
                            @{Link = "PowerPoint"; Target = "POWERPNT"},
                            @{Link = "Edge"; Target = "msedge"},
                            @{Link = "Visual Studio Code"; Target = "Code"}
                        )

                        $isKnownException = $false
                        foreach ($exception in $knownExceptions) {
                            if ($shortcutNameWithoutExt -like "*$($exception.Link)*" -and $targetExeName -like "*$($exception.Target)*") {
                                $isKnownException = $true
                                break
                            }
                        }

                        if (-not $isKnownException -and -not ($shortcutNameWithoutExt -like "*$targetExeName*" -or $targetExeName -like "*$shortcutNameWithoutExt*")) {
                            $isSuspicious = $true
                            $reason = "Target name doesn't match shortcut name"
                        }
                    }

                    # Check for script execution in arguments
                    if (-not $isSuspicious) {
                        $scriptExtensions = @('.ps1', '.vbs', '.js', '.bat', '.cmd', '.hta', '.wsf')
                        foreach ($ext in $scriptExtensions) {
                            if ($link.Arguments -like "*$ext*") {
                                $isSuspicious = $true
                                $reason = "Script execution detected in arguments"
                                break
                            }
                        }
                    }
                    # pretty colors
                    if ($isSuspicious) {
                        Write-Host "`nSUSPICIOUS SHORTCUT FOUND:" -ForegroundColor Red
                        Write-Host "Shortcut: $($shortcut.Name)" -ForegroundColor Yellow
                        Write-Host "Location: $($shortcut.FullName)"
                        Write-Host "Points to: $($link.TargetPath)"
                        Write-Host "Arguments: $($link.Arguments)"
                        Write-Host "Reason: $reason" -ForegroundColor Magenta
                        Write-Host "Created: $($shortcut.CreationTime)"
                        Write-Host "Modified: $($shortcut.LastWriteTime)"
                    }
                }
            }
        }
    }
    catch {
        Write-Error "Error analyzing shortcuts: $_"
    }
    finally {
        if ($shell) {
            [System.Runtime.InteropServices.Marshal]::ReleaseComObject($shell) | Out-Null
        }
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}

# Run the check
Test-ShortcutIntegrity
