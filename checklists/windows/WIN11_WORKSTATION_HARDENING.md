# Windows 11 workstation - hardening checklist

| | |
|---|---|
| Address | DHCP on the LAN (172.20.240.x); no public address of its own (outbound shows as 172.31.(20+N).2) |
| OS | Windows 11 |
| Default login | `sysadmin` (paper only: ________ ) |
| **Scored** | nothing directly (nothing outside can reach it) - but it's a **user workstation**: it must stay usable, and it may not be re-tasked |
| Script role | `workstation` (`deploy.ps1 -Role workstation`) |
| Also | one of the two consoles for the Palo Alto web UI (`https://172.20.240.200`) and Splunk (`http://172.20.240.20:8000`) |

Work from the VM console in an **Administrator PowerShell**. A workstation is where the red team likes to start
(phishing-style injects, stolen domain logins) - harden it like a server. Incident response: `IR.md`.

> The Windows scripts have **not been run on a real Windows machine yet** - practise on a VM first.

---

## 0. Before touching anything (3 min)
- [ ] `ipconfig | findstr IPv4` - DHCP address: ____________
- [ ] Domain-joined? `(Get-CimInstance Win32_ComputerSystem) | Select Domain, PartOfDomain` - if True, domain passwords are changed on the DC.
- [ ] `Get-LocalUser | ft Name, Enabled, LastLogon`; `Get-LocalGroupMember Administrators` - write down what's there.
- [ ] Palo Alto UI and Splunk open in Edge (your tools - check they work before changing anything).
- [ ] Snapshot of what runs: `Get-Process | ? Path | Sort Path | Select Name, Path | Out-File C:\CCDC-start-processes.txt`

## 1. Passwords - first 5 minutes
- [ ] Scripts to `C:\CCDC` (`../GETTING_SCRIPTS.md`), `ccdc.conf` filled in.
- [ ] `cd C:\CCDC; powershell -ExecutionPolicy Bypass -File .\deploy.ps1 -Role workstation -Skip fim`
- [ ] `passwords` step: every local account (you type yours). Printed scored users → captain (normally none here).

## 2. The rest of the deploy steps
| Step | What to watch for |
|---|---|
| harden | Ping allowed, firewall on + logging, SMB1 off, SMB signing, LLMNR/NetBIOS off, WDigest off, LSA protection (reboot later), Defender on, command-line + PowerShell logging. |
| secure | RDP settings (NLA, TLS) if RDP is on. |
| cis | CIS Level 1 controls not covered elsewhere: advanced audit policy + log sizes, UAC, anonymous access, SMB client, AutoPlay, logon banner, RDP/WinRM client options, printer drivers, Defender + ASR, PowerShell transcription, user rights, unneeded services. Asks per section; WinRM service / lockout / renames stay as they are (`../CIS.md`). |
| forwarder | Splunk forwarder → `172.20.240.20:9997`. |
| audit | Run keys, services, tasks, WMI, startup, Defender exclusions - read every CRITICAL. |
| services | Legacy features off after asking (SMB1, PowerShell 2.0, Telnet, SNMP, Remote Registry...). |
| beacon | Outbound-connection watcher (task `CCDC-Beacon`). |

## 3. Manual hardening
### 3.1 Accounts
- [ ] Administrators: only the accounts that belong there - `Remove-LocalGroupMember Administrators <name>` (ask first).
- [ ] Unknown local users: `Disable-LocalUser <name>` (don't delete).
- [ ] Built-in Administrator disabled unless it's the account you use: `Get-LocalUser Administrator | Select Enabled`
- [ ] UAC on and prompting on the secure desktop:
      ```powershell
      $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
      Set-ItemProperty $k EnableLUA 1; Set-ItemProperty $k ConsentPromptBehaviorAdmin 2; Set-ItemProperty $k PromptOnSecureDesktop 1
      ```

### 3.2 Remote access
- [ ] **RDP:** not scored here (no inbound path from outside) and we work from the console - turn it off:
      `Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections 1`
      (an inject may ask for it back: set `0`).
- [ ] Remote Assistance off: `Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' fAllowToGetHelp 0`
- [ ] WinRM: not needed on a workstation - `Stop-Service WinRM; Set-Service WinRM -StartupType Disabled`
- [ ] OpenSSH server (optional feature): `Get-WindowsCapability -Online -Name OpenSSH.Server*` → if Installed: `Stop-Service sshd; Set-Service sshd -StartupType Disabled`
- [ ] Remote-control tools that shouldn't be there (AnyDesk, TeamViewer, ngrok, VNC, ScreenConnect): Settings → Apps, and
      `Get-Process | ? Path | Sort Path | ft Name, Path` vs `C:\CCDC-start-processes.txt`.

### 3.3 Defender and attack surface reduction
- [ ] Real-time protection on, no exclusions: `Get-MpComputerStatus | fl RealTimeProtectionEnabled, IsTamperProtected`;
      `Get-MpPreference | fl Exclusion*` → remove unknown: `Remove-MpPreference -ExclusionPath <path>`
- [ ] Cloud protection and sample submission: `Set-MpPreference -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples`
- [ ] Potentially unwanted apps blocked: `Set-MpPreference -PUAProtection Enabled`
- [ ] **Attack Surface Reduction rules** (block common attacker tricks; safe on a workstation):
      ```powershell
      $asr = @(
        '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'   # credential stealing from LSASS
        'd4f940ab-401b-4efc-aadc-ad5f3c50688a'   # Office apps creating child processes
        'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'   # executable content from email / webmail
        'd3e037e1-3eb8-44c8-a917-57927947596d'   # JavaScript / VBScript launching downloaded executables
        '5beb7efe-fd9a-4556-801d-275e5ffc04cc'   # obfuscated scripts
        'e6db77e5-3df2-4cf1-b95a-636979351e5b'   # persistence through WMI event subscriptions
        'd1e49aac-8f56-4280-b9ba-993a6d77406c'   # process creation from PsExec and WMI commands
        '56a863a9-875e-4185-98a7-b882c64b5ce5'   # abuse of vulnerable signed drivers
      )
      Add-MpPreference -AttackSurfaceReductionRules_Ids $asr -AttackSurfaceReductionRules_Actions ($asr | % { 'Enabled' })
      Get-MpPreference | Select -Expand AttackSurfaceReductionRules_Ids
      ```
      Blocks show up in Event Viewer → Microsoft → Windows → Windows Defender → Operational (event 1121).
- [ ] Quick scan: `Start-MpScan -ScanType QuickScan`; results: `Get-MpThreatDetection`

### 3.4 Persistence spots (audit.ps1 checks these; look yourself too)
- [ ] Startup folders: `Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp", "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"`
- [ ] Run keys: `Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run, HKCU:\Software\Microsoft\Windows\CurrentVersion\Run`
- [ ] Scheduled tasks not from Microsoft: `Get-ScheduledTask | ? { $_.TaskPath -notlike '\Microsoft\*' } | ft TaskName, TaskPath, State`
- [ ] Shortcut (`.lnk`) tricks on the desktop / start menu: `.\windows\tools\AuditLNKs.ps1`
- [ ] Browser extensions (Edge: `edge://extensions`) - remove unknown ones; don't save firewall / Splunk passwords in the browser.

### 3.5 Network and protocols
- [ ] Firewall on for every profile, inbound default block: `Get-NetFirewallProfile | ft Name, Enabled, DefaultInboundAction`
- [ ] Inbound allow rules you don't recognise: `Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | ft DisplayName, Profile`
- [ ] File sharing not needed on a workstation: `Get-SmbShare` → only `ADMIN$`, `C$`, `IPC$`. Unknown shares → `Remove-SmbShare <name>`.
- [ ] LOLBin network access (certutil, mshta, regsvr32... can't download tools): `.\windows\privesc.ps1 -BlockLolbinEgress`
- [ ] SmartScreen on: Settings → Privacy & security → Windows Security → App & browser control → Reputation-based protection → all on.

### 3.6 Logging
- [ ] Process creation with command lines and PowerShell script block logging (harden did both): Event Viewer → Security 4688, PowerShell/Operational 4104.
- [ ] Sysmon (detailed process/network logging), if the installer is available: `sysmon64 -accepteula -i C:\CCDC\windows\sysmon\sysmonconfig.xml`
- [ ] Logs reach Splunk: `index=* host=<name> earliest=-10m`

### 3.7 Take the baseline and back up (last)
- [ ] `powershell -ExecutionPolicy Bypass -File .\deploy.ps1 -Role workstation -Only fim`
- [ ] Workstation backups are optional; if the Palo Alto exports were saved on this box, push them:
      `.\windows\offbox.ps1 push -Include <folder with the exports>`
- [ ] Reboot when convenient (LSA protection); check the Palo Alto UI and Splunk still open afterwards.

## 4. Check
- [ ] The Palo Alto UI and Splunk still load in Edge; the domain user can still log in (if domain-joined).
- [ ] `.\windows\privesc.ps1` (report) shows nothing critical.

## 5. Every 30-60 minutes
- [ ] `.\windows\audit.ps1` (report); `.\windows\beacon.ps1 report`
- [ ] Defender detections: `Get-MpThreatDetection | Select -First 5`; ASR blocks: event 1121
- [ ] Administrators group unchanged; new scheduled tasks?

## Things that lose points - don't
- Don't re-task it (no server roles, no services for other boxes) - rule: workstations stay workstations
- Don't change its hostname or network settings (it gets its address by DHCP)
- Don't turn on account lockout (the red team can lock users out)
- Don't run Windows feature updates during the competition (surprise reboots)
- Don't block the Palo Alto UI / Splunk for yourself with the firewall
