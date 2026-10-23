# Windows (Win 11 workstation, Server 2019 MSSQL, IIS) - incident response checklist

Order: **record → contain → clean up → check scored services → write the report.**
The incident report is worth points, so collect evidence *before* you fix anything. Use **PowerShell as Administrator**.

## Signs of trouble
- New local users or new Administrators members; scored users can't log in
- `audit.ps1` exits with code 2 (CRITICAL), or `CCDC-Audit` events in the Application log / Splunk
- File integrity alerts: `CCDC-FIM` events in the Application log (hosts file, scheduled task files, startup folders, profiles, System32 programs, IIS config). Evidence and diffs: `C:\ProgramData\CCDC\fim\evidence\`
- Beacon alerts: `CCDC-Beacon` events, or `.\beacon.ps1 report` - a program connecting out on a timer (alert includes its path and signer)
- Defender turned off, new Defender exclusions, or detections: `Get-MpThreatDetection`
- Unknown programs connecting out: `Get-NetTCPConnection -State Established | ? RemoteAddress -notmatch '^(127\.|::1)'`
- RDP sessions you don't recognise: `quser`
- IIS server: website defaced, webguard alerts, new `.aspx/.asp/.php` files

Useful event IDs: **4624/4625** logon ok/failed (type 10 = RDP, 3 = network) · **4720** user created · **4732** added to local group · **7045** service installed · **4698** scheduled task created · **4688** process started · **4104** PowerShell script · **1102** security log cleared · **1116** Defender detection

## 1. Record (before changing anything) - tell the captain right away
```powershell
$E = "C:\ProgramData\CCDC\ir-$(Get-Date -Format HHmm)"; New-Item -ItemType Directory $E | Out-Null
Get-Date | Out-File $E\time.txt
Get-NetTCPConnection | Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{n='Proc';e={(Get-Process -Id $_.OwningProcess -EA 0).Path}} | Export-Csv $E\connections.csv -NoType
Get-CimInstance Win32_Process | Select ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine | Export-Csv $E\processes.csv -NoType
quser 2>$null | Out-File $E\sessions.txt
Get-LocalUser | Select Name,Enabled,LastLogon | Export-Csv $E\users.csv -NoType
Get-LocalGroupMember Administrators | Out-File $E\admins.txt
foreach ($l in 'Security','System','Application','Microsoft-Windows-PowerShell/Operational') {
    wevtutil epl $l "$E\$($l -replace '/','-').evtx" }
```
- [ ] Find the attacker's IP. Successful network/RDP logons:
      `Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 300 | ? { $_.Properties[8].Value -in 3,10 } | Select TimeCreated,@{n='User';e={$_.Properties[5].Value}},@{n='IP';e={$_.Properties[18].Value}}`
      Failed logons (the fields are in different places in 4625):
      `Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 300 | Select TimeCreated,@{n='User';e={$_.Properties[5].Value}},@{n='IP';e={$_.Properties[19].Value}}`
- [ ] Screenshot what you show in the report

## 2. Contain (keep RDP and the website up)
- [ ] **Attacker session**: `quser` → `logoff <ID>`
- [ ] **Account they used**: new password right away: `Set-LocalUser <name> -Password (Read-Host -AsSecureString)`. Scored user → give the new password to the captain. Accounts nobody needs: `Disable-LocalUser <name>`.
- [ ] **Bad process**: save the file first, then stop it:
      `$p = Get-Process -Id <PID>; Copy-Item $p.Path $E\; Stop-Process -Id <PID> -Force`
- [ ] **Block the attacker's IP** on the Palo Alto, or here:
      `New-NetFirewallRule -DisplayName "CCDC block <IP>" -Direction Inbound -RemoteAddress <IP> -Action Block`
      (same again with `-Direction Outbound`). **Never block the scoring engine's IP.**
- [ ] Any admin account was used → change all passwords again: `.\passwords.ps1 -ScoredUsers <users>`

## 3. Clean up
- [ ] `.\audit.ps1 -Fix`: Run keys, services, tasks, WMI, accessibility backdoors, Defender exclusions. Files go to `C:\ProgramData\CCDC\quarantine-*`; registry keys are exported first.
- [ ] Remove unknown users from Administrators: `Remove-LocalGroupMember Administrators <name>`
- [ ] Defender back on and scanning: `Set-MpPreference -DisableRealtimeMonitoring $false; Start-MpScan -ScanType QuickScan`
- [ ] Settings changed back? Re-run `.\harden.ps1` (safe to repeat)

### IIS server extra
- [ ] Copy the IIS logs: `Copy-Item C:\inetpub\logs\LogFiles $E\iislogs -Recurse`
- [ ] Find the webshell's requests (attacker IP and time): `Select-String -Path C:\inetpub\logs\LogFiles\*\*.log -Pattern '<shell file name>'`
- [ ] Put the site back: `.\webguard.ps1 restore` (from `C:\CCDC\windows`) (copies go to `C:\ProgramData\WebGuard\evidence` first)
- [ ] Worker process running commands? `Get-CimInstance Win32_Process | ? { (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.ParentProcessId)").Name -eq 'w3wp.exe' }`: `cmd.exe`/`powershell.exe` under `w3wp.exe` = webshell in use
- [ ] App DB password may be stolen (webshells read `web.config`): change it and the config back to back
- [ ] Recycle only the affected app pool, not `iisreset`: `Restart-WebAppPool <name>`

- [ ] If the good state is a NEW version of a watched file (you edited it on purpose), record it: `.\fim.ps1 accept -Path <file>`

## 3b. Recover from a backup
Full procedure: `../BACKUP_AND_RECOVERY.md`. Record evidence first.
- [ ] **MSSQL - SOP files deleted or changed:** compare hashes (`../mssql/HARDENING.md` 3.2), then
      `Copy-Item C:\CCDC-backup\share\* <share path> -Recurse -Force` (or `C:\ProgramData\CCDC\share-backup-<time>\<share>\*`)
- [ ] **MSSQL - database damaged:** `sqlcmd -S localhost -E -Q "ALTER DATABASE [<db>] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; RESTORE DATABASE [<db>] FROM DISK='C:\CCDC-backup\<db>.bak' WITH REPLACE; ALTER DATABASE [<db>] SET MULTI_USER"`
- [ ] **A quarantined file was legitimate:** it's in `C:\ProgramData\CCDC\quarantine-<time>\` - `Move-Item` it back
- [ ] **A setting our scripts changed broke something:** the old value is in `C:\ProgramData\CCDC\*-undo.csv` / `harden-*-previous-values.csv`
- [ ] **IIS site defaced:** `.\webguard.ps1 restore` (section 3 above)
- [ ] Local backups gone: vault `serve <file>` → `.\windows\offbox.ps1 fetch -File <file>` → `C:\CCDC-restore-<time>\`

## 4. Check scored services
- [ ] RDP in from another machine as a scored user
- [ ] MSSQL: from another machine `Test-NetConnection 172.20.240.120 -Port 1433` and `-Port 445`; a scored SQL login and query still work; the SOP files are still in the share
- [ ] Website loads from another machine (IIS boxes); `.\webguard.ps1 check` is clean
- [ ] `.\audit.ps1` (report only) shows no CRITICAL findings

## 5. Write the incident report (`Blank Inject Template.docx`)
Include: time detected and contained · machine name and IP · attacker IP(s) · what they did (event IDs and times, process paths, the webshell path) · how you found it · actions in order · current status · prevention.
Attach evidence from `$E` (the exported `.evtx` logs, `connections.csv`) and the webguard evidence folder.
