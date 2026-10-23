# Startup scripts: set up, verify, and check integrity

Our monitors must survive a reboot, and nobody but an admin may be able to change them -
they run as root / SYSTEM, so an editable monitor script is a free backdoor for the red team.
`deploy.sh` and `deploy.ps1` already do all of this; this page is how to check it and how to add
a startup script of your own.

## What starts at boot
| Monitor | Linux (systemd service) | Windows (scheduled task, runs as SYSTEM at startup) |
|---|---|---|
| Website defacement guard | `ccdc-webguard` (web boxes) | `CCDC-WebGuard` (IIS server) |
| Beacon detector | `ccdc-beacon` | `CCDC-Beacon` |
| Outbound SSH detector | `ccdc-outbound-ssh` | (covered by `evidence.ps1` / `audit.ps1`) |
| File integrity monitor | `ccdc-fim` | `CCDC-FIM` |
| Scripts run from | `/opt/ccdc` (root only, `700`) | `C:\ProgramData\CCDC\bin` (Administrators + SYSTEM only) |
| Checksums | `/opt/ccdc/SHA256SUMS` | `C:\ProgramData\CCDC\bin\SHA256SUMS.txt` |

The file integrity monitor watches the script folder **and** the unit files / task files, so any
change to a monitor or the way it starts raises an alert.

## Verify (after deploy, and after every reboot)
**Linux**
```bash
systemctl is-enabled ccdc-fim ccdc-beacon ccdc-outbound-ssh ccdc-webguard    # enabled = starts at boot
systemctl is-active  ccdc-fim ccdc-beacon ccdc-outbound-ssh ccdc-webguard    # active  = running now
cd /opt/ccdc && sudo sha256sum -c SHA256SUMS                                 # every line must say OK
sudo ls -la /opt/ccdc /opt/ccdc/linux                                        # owner root, no group/other access
systemctl cat ccdc-fim                                                       # ExecStart must point into /opt/ccdc
```
**Windows** (Administrator PowerShell)
```powershell
Get-ScheduledTask -TaskName 'CCDC-*' | Select TaskName, State, @{n='RunAs';e={$_.Principal.UserId}}
Get-ScheduledTask CCDC-FIM | Select -Expand Actions | Select Execute, Arguments   # must point into C:\ProgramData\CCDC\bin
Get-FileHash C:\ProgramData\CCDC\bin\*.ps1 | Format-Table Hash, Path               # compare with bin\SHA256SUMS.txt
icacls C:\ProgramData\CCDC\bin                                                     # only Administrators and SYSTEM
```
Or run the evidence script, section `startup`: `sudo linux/evidence.sh --section startup` /
`.\windows\evidence.ps1 -Section startup` - it does all of the above.

**Reboot test** (once things are stable, at a quiet moment): reboot one box, then run the checks again.

## If a check fails
- Checksum mismatch or wrong owner → treat as an incident (box `IR.md`): save a copy of the changed
  file, then re-run the deploy step to reinstall: `sudo bash ./deploy.sh --role <role> --only beacon,fim`
  / `.\deploy.ps1 -Role <role> -Only beacon,fim`.
- Service/task not running → `journalctl -u ccdc-fim -n 30` / `Get-ScheduledTaskInfo CCDC-FIM` (LastTaskResult).
- After editing `ccdc.conf`, re-run the deploy steps so `/opt/ccdc` gets the new copy, then
  `sudo /opt/ccdc/linux/fim.sh accept /opt/ccdc`.

## Adding your own startup script safely
**Linux** - a systemd service, script in a root-only folder:
```bash
sudo install -m 700 -o root -g root myscript.sh /opt/ccdc/myscript.sh
sudo tee /etc/systemd/system/ccdc-myscript.service > /dev/null <<'EOF'
[Unit]
Description=CCDC myscript
After=network-online.target
[Service]
ExecStart=/opt/ccdc/myscript.sh
Restart=always
RestartSec=10
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable --now ccdc-myscript
sudo /opt/ccdc/linux/fim.sh accept /opt/ccdc/myscript.sh /etc/systemd/system/ccdc-myscript.service
```
**Windows** - a SYSTEM task, script in the admin-only folder:
```powershell
Copy-Item .\myscript.ps1 C:\ProgramData\CCDC\bin\
$a = New-ScheduledTaskAction -Execute powershell.exe -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\CCDC\bin\myscript.ps1"'
Register-ScheduledTask -TaskName CCDC-MyScript -Action $a -Trigger (New-ScheduledTaskTrigger -AtStartup) `
  -Principal (New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest)
Start-ScheduledTask CCDC-MyScript
.\windows\fim.ps1 accept -Path C:\ProgramData\CCDC\bin\myscript.ps1, C:\Windows\System32\Tasks\CCDC-MyScript
```
Never: put a startup script in a user's home, `/tmp`, `C:\Users\...`, or a folder created directly
under `C:\` (ordinary users can write there); use `-WindowStyle Hidden` or `-EncodedCommand` (our
audit flags those as attacker tricks); or add lines to `rc.local` / `.bashrc` / Run keys.

## Attacker startup persistence - where to look
| Linux | Windows |
|---|---|
| `systemctl list-unit-files --state=enabled`, unit files in `/etc/systemd/system`, `~/.config/systemd/user` | `Get-ScheduledTask`, `C:\Windows\System32\Tasks` |
| cron: `/etc/crontab`, `/etc/cron.*`, `crontab -l -u <user>`, `@reboot` lines | Run / RunOnce keys (HKLM and each user), Winlogon Shell/Userinit |
| `/etc/rc.local`, `/etc/init.d`, `/etc/profile.d`, `~/.bashrc`, `~/.profile` | Startup folders (machine and each user) |
| `/etc/ld.so.preload`, PAM modules, `authorized_keys` | Services with odd paths, WMI event subscriptions |

`linux/audit.sh scan` and `windows/audit.ps1` check all of these.
