# Windows scripts (Windows 11 workstation, Server 2022 AD, Server 2019 MSSQL; IIS/FTP for older topologies)

Usually run through `..\deploy.ps1 -Role dc|mssql|workstation` (`web`, `ftp`: older topologies), which runs them in this order and
reads `..\ccdc.conf`. To run one by hand, from an **Administrator** PowerShell in this folder:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\passwords.ps1 -ScoredUsers user1,user2       # FIRST: every local password + policy
.\harden.ps1 -Role mssql                       # baseline hardening (settings at the top of the file)
.\audit.ps1                                    # backdoor hunt, report only
.\audit.ps1 -Fix -ExpectedAdmins webadmin      # fix, asking before each one
```

**None of these have been run on a real Windows machine yet. Test them on practice VMs.**

| Script | Notes |
|---|---|
| `passwords.ps1` | You type your own password; others get random 16-char ones (`-OnePassword` for one typed password). Updates services, scheduled tasks and IIS app pools that run as a changed user. CSV in `C:\ProgramData\CCDC\` (Administrators only). Lockout stays off on purpose. Local accounts only - domain accounts are changed on the DC. |
| `harden.ps1` | `-Role` first adds inbound allow rules for that role's scored ports (dc: DNS/AD/WinRM; mssql: 445/1433/3389 + the SQL instance's port) so turning the firewall on can't block them. Allows inbound ping (competition rule: ICMP must stay up), keeps RDP on (with NLA), SMB1 off, SMB signing, LLMNR/NetBIOS off, WDigest off, LSA protection (after reboot), firewall on + logging, Defender on, command-line and PowerShell logging. Never touches IIS sites, bindings or ports. Previous values saved next to the log. |
| `cis.ps1` | CIS Level 1 controls the other scripts don't cover, by `-Role`: advanced audit policy + log sizes, UAC, anonymous access, SMB client, network, AutoPlay, logon banner, RDP / WinRM client, printer drivers, Defender + ASR, PowerShell transcription, user rights (not on the DC - GPO there), unneeded services. Report; `-Fix` asks per section. Deviations: `../checklists/CIS.md`. Parsed and the control logic tested in PowerShell 7; **not run on Windows yet.** |
| `offbox.ps1` | `push`: zips `C:\CCDC-backup`, the newest share backup + hashes and the DNS zone exports (never password CSVs), encrypts them with the team passphrase in the same format as `openssl enc` (so `linux/offbox.sh decrypt` opens them too) and uploads during a vault window with the built-in `sftp.exe`. `fetch` / `decrypt`: back to `C:\CCDC-restore-<time>`. Format verified against openssl; **not run on Windows yet.** |
| `secure.ps1` | Scored-service hardening by `-Role`, each section tested and undone if its test fails. dc: DNS (no zone transfers, secure updates, cache locking, rate limiting, audit log, optional LAN-only recursion), WinRM (HTTPS listener added; Basic/unencrypted/CredSSP off only if you say so). mssql: SMB (share backup + hashes, no null sessions, auditing, optional read-only for Everyone-style write), RDP (NLA, TLS, high encryption), SQL Server (xp_cmdshell & co. off after asking, login auditing, weak-login report). **Not tested on Windows yet.** |
| `audit.ps1` | Admins, Run keys, Winlogon, IFEO, accessibility backdoors, services, tasks, WMI, startup folders, Defender exclusions, firewall, temp-dir processes, connections, IIS webshells, shares, hosts file, PowerShell profiles. Fixes never delete: files are quarantined, registry keys exported. Exit 2 = critical, 1 = warnings. |
| `webguard.ps1` | IIS defacement guard, see below |
| `fim.ps1` | File integrity monitor for system folders, see below |
| `beacon.ps1` | Detects outbound connections that repeat on a timer, see below |
| `ad_passwords.ps1` | **Domain controller only** (`deploy.ps1 -Role dc` runs it): every domain account password (you type yours, others random; scored users printed for reporting; service accounts with SPNs skipped and listed), domain password policy (14+, complexity, history 5, 90 days, lockout off), fixes AS-REP-roastable / password-not-required / reversible-encryption accounts, reviews privileged groups, optional `-ResetKrbtgt`. **Not tested yet.** |
| `ad_audit.ps1` | **Domain controller.** Read-only AD audit: new users/computers, privileged group members and *when* they were added, SID history, adminCount leftovers, passwords in descriptions, AS-REP-roastable and Kerberoastable (esp. privileged) accounts, unconstrained / constrained / resource-based delegation, machine account quota, DCSync rights, dangerous rights on the domain root / AdminSDHolder / Domain Admins, DnsAdmins + DNS plugin DLL backdoor, GPO changes, GPO tasks/scripts, GPP `cpassword`, trusts, rogue DCs, recent account/group/DCSync events. `-Fix` (asks) for the safe fixes. **Not tested yet.** |
| `privesc.ps1` | Any Windows box. Privilege-escalation paths (unquoted / writable services, writable task programs, AlwaysInstallElevated, writable PATH folders, stored passwords, HiveNightmare, dangerous privileges, UAC/WDigest/PrintNightmare/WSUS settings) and LOLBin abuse in running processes and the last 24 h of 4688 / Sysmon / PowerShell events. `-Fix` (asks); `-BlockLolbinEgress` blocks network access for certutil, mshta, regsvr32, rundll32, msbuild... Detection patterns checked against 15 attack and 9 normal command lines. **Not tested on Windows yet.** |
| `portscan.ps1` | Network port scan of the team's hosts (nmap or built-in TCP connects), same labels and NEW/GONE comparison as `linux/portscan.sh`; refuses targets outside the team ranges. `.\portscan.ps1`, `.\portscan.ps1 172.20.240.120 -Ports 1-1024 -Banner`. **Not tested on Windows yet.** |
| `services.ps1` | Service inventory, legacy features/services/protocols to remove, end-of-life software, pending Windows updates, see below |

## Defacement guard (`webguard.ps1`)
1. Check the site in a browser and confirm it looks right.
2. Baseline: `.\webguard.ps1 init -WebRoot C:\inetpub\wwwroot`
3. Watch: `.\webguard.ps1 watch -WebRoot C:\inetpub\wwwroot` (alert only) or add `-AutoRestore`.
   `deploy.ps1` runs this as the SYSTEM scheduled task `CCDC-WebGuard`.
4. **After any legitimate site change, run `init` again**, or auto-restore will revert it.

`check` compares once, `restore` puts changed files back now. Runtime folders (App_Data, uploads,
cache, temp, logs) are skipped, but new or changed script files there are still caught. Evidence
(copies + diff) goes to `C:\ProgramData\WebGuard\`. Alerts go to the Application event log, source `WebGuard`.

## File integrity monitor (`fim.ps1`)
Watches the hosts file folder, `System32\Tasks` (scheduled task files), `System32\GroupPolicy`,
startup folders (machine and every user), PowerShell profiles, OpenSSH config and `.ssh` folders,
the top-level `System32\*.exe` (sethc, utilman...), and with `-Role web` the IIS config
(`applicationHost.config`) and IIS modules. More with `-ExtraPaths` / `WIN_FIM_EXTRA_PATHS`.

```powershell
.\fim.ps1 init -Role web            # AFTER hardening + audit, so the baseline is clean
.\fim.ps1 watch                     # deploy.ps1 runs this as the SYSTEM task CCDC-FIM
.\fim.ps1 check                     # one full comparison, exit 1 if anything changed
.\fim.ps1 accept -Path C:\Windows\System32\drivers\etc\hosts   # changed on purpose
```
Reports NEW, CHANGED, DELETED and ATTRIBUTES (e.g. a file made Hidden/System), once per change.
Alert only - nothing is restored. Evidence and diffs go to `C:\ProgramData\CCDC\fim\evidence\`,
alerts to the Application event log (source `CCDC-FIM`, event 4300). Every 10th pass re-hashes
every file, the others only files whose size or timestamps changed.

## Beacon detector (`beacon.ps1`)
```powershell
.\beacon.ps1 watch -Allow '172.20.240.20:9997' -Inside 172.20.240.0/24   # deploy.ps1: task CCDC-Beacon
.\beacon.ps1 report                                                     # beacons first
```
Polls `Get-NetTCPConnection` (TCP only; recently closed TIME_WAIT connections are still listed).
Same rule as Linux: 8+ connections, gaps 10 s+, 80% within 25% of the typical gap = BEACON.
Windows 11 has its own regular traffic (Defender, Update, OneDrive, time sync), so every alert
includes the program's path and signer - a Microsoft-signed `svchost`/`MsMpEng` is usually fine,
an unsigned program in `AppData` or `ProgramData` is not. Alerts: Application log, source `CCDC-Beacon`.

## Services: legacy removal and updates (`services.ps1`)
```powershell
.\services.ps1 -Role web              # report (includes a Windows Update search, max 3 min)
.\services.ps1 -Role web -Fix         # remove/disable each legacy item, asking first
.\services.ps1 -InstallUpdates        # install Security/Critical updates, asking per update; never reboots
```
Flags SMB1 (feature and protocol), PowerShell 2.0, Telnet/TFTP clients, SNMP, Simple TCP/IP services,
IIS FTP / WebDAV / IIS 6 compatibility, WINS, Remote Registry, Telnet server, Fax, UPnP/SSDP (servers),
WebClient, Print Spooler on servers, SSL/TLS 1.0/1.1 not disabled, LM/NTLMv1; end-of-life Windows builds
and software (Flash, Silverlight, Python 2, PHP < 8.2, MySQL 5.x/8.0, old Tomcat/SQL Server).
Items on `-ScoredPorts` (default dc 53,88,135,389,445,464,636,3268,3269,5985,5986 / mssql 135,445,1433,3389 / web 80,443 / workstation 3389) are never touched.
Every change is recorded with its old value in `C:\ProgramData\CCDC\services-<time>-undo.csv`.
**Not tested on Windows yet.**

## Evidence for injects (`evidence.ps1`)
`.\evidence.ps1 [-Section ...] [-FimTest] [-LogTest] [-Splunk IP] [-Wazuh IP] [-Dns IP]` - system info, time,
connectivity, firewall policy, startup/watcher integrity, file integrity proof, logging status and a
traffic profile (incl. outbound SSH) in one report: `C:\ProgramData\CCDC\evidence-<host>-<time>.txt`.

## Where the watchers run
`deploy.ps1` copies `webguard.ps1`, `beacon.ps1` and `fim.ps1` into the admin-only `C:\ProgramData\CCDC\bin`
(hashes in `bin\SHA256SUMS.txt`) and the SYSTEM tasks run them from there - never from a folder ordinary
users can write to. `fim.ps1` watches that folder and the task files.

## `tools/`
Older hunting helpers, run by hand: `Tool-Check.ps1` (searches the disk for hacking tools - slow),
`AuditUsers.ps1`, `AuditLNKs.ps1` (shortcut hijacks), `RegisterAudit` (registry autostart review).
`sysmon/sysmonconfig.xml` is a Sysmon config; the Sysmon binary itself isn't included.
