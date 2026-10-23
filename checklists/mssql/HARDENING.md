# Server 2019 MSSQL - hardening checklist

| | |
|---|---|
| Address | `172.20.240.120`, public `172.25.(20+N).120` |
| OS / software | Windows Server 2019 Standard, Microsoft SQL Server, a file share with the water-facility "SOPs" |
| Default login | `sysadmin` (paper only: ________ ); SQL logins such as `sa` (paper only: ________ ) |
| **Scored** | **MSSQL SMB** (logs in to SMB, checks the planted SOP files exist - *local or domain user? find out*), **MSSQL RDP** (3389 with authentication), **MSSQL MSSQL** (1433 open, then a SQL login and a query); ping |
| Script role | `mssql` (`deploy.ps1 -Role mssql`) |

Work from the VM console in an **Administrator PowerShell**. Assume every password (Windows, domain, SQL logins) is
known to the red team. Incident response: `../windows/IR.md`.

> The Windows scripts have **not been run on a real Windows machine yet** - practise on a VM first.

---

## 0. Before touching anything (5 min)
- [ ] Machine facts: `hostname; (Get-CimInstance Win32_ComputerSystem) | Select Domain, PartOfDomain`
- [ ] Listening now: `Get-NetTCPConnection -State Listen | ? LocalPort -in 135,445,1433,1434,3389,5985 | Sort LocalPort | ft LocalAddress, LocalPort, OwningProcess`
- [ ] **The share and the SOPs:**
      ```powershell
      Get-SmbShare | ? { $_.Name -notmatch '\$$' } | ft Name, Path, Description
      Get-SmbShareAccess <share>                                  # share permissions
      (Get-Acl <share path>).Access | ft IdentityReference, FileSystemRights, AccessControlType   # NTFS permissions
      Get-ChildItem <share path> -Recurse | Select FullName, Length, LastWriteTime
      ```
      SOP share: ____________  Accounts with access (these are probably what the SMB check uses): ____________
      Local or domain accounts? [ ] local (change here, `passwords` step)  [ ] domain (changed on the DC)
- [ ] **SQL Server:** `Get-Service *SQL* | ft Name, Status, StartType`; account each runs as:
      `Get-CimInstance Win32_Service -Filter "Name like '%SQL%'" | ft Name, StartName`
      Instance name: ____________ (`MSSQLSERVER` = default instance, connect as `localhost`; otherwise `localhost\<name>`)
- [ ] SQL logins (SQL tools: `sqlcmd`; if missing, SSMS):
      ```powershell
      sqlcmd -S localhost -E -Q "SELECT name, type_desc, is_disabled FROM sys.server_principals WHERE type IN ('S','U','G') ORDER BY name"
      sqlcmd -S localhost -E -Q "SELECT name FROM sys.databases"
      ```
      Database the scored query probably uses: ____________   SQL login it uses (Quotient / injects): ____________
- [ ] Backups (only undo you have):
      ```powershell
      New-Item -ItemType Directory C:\CCDC-backup -Force | Out-Null
      Copy-Item <share path> C:\CCDC-backup\share -Recurse
      sqlcmd -S localhost -E -Q "SELECT name FROM sys.databases WHERE database_id > 4" -h -1 -W | ? { $_ } | % {
          sqlcmd -S localhost -E -Q "BACKUP DATABASE [$_] TO DISK='C:\CCDC-backup\$_.bak' WITH COPY_ONLY, INIT" }
      ```
      (If SQL Server can't write to `C:\CCDC-backup`, give its service account write access or back up to its default `Backup` folder.)

## 1. Passwords - first 5 minutes
- [ ] Scripts to `C:\CCDC`, team number + `SCORED_USERS` (local share/RDP users) in `ccdc.conf`, `CONFIG_REVIEWED=yes`.
- [ ] `cd C:\CCDC; powershell -ExecutionPolicy Bypass -File .\deploy.ps1 -Role mssql -Skip fim`
- [ ] `passwords` step: every **local** account; services and scheduled tasks running as them are updated too.
      **Scored users printed as `username,password` → captain → Quotient PCR now.** Domain users: changed on the DC.
- [ ] SQL Server service account: if it's a **domain** account, the DC skipped it (it has an SPN). Change it in both places
      together: DC `Set-ADAccountPassword <svc> -Reset`, here `services.msc` → SQL Server → Log On → new password → restart
      SQL Server (1433 is down for ~30 s - tell the captain).
- [ ] **SQL logins (no script changes these):**
      ```powershell
      sqlcmd -S localhost -E -Q "ALTER LOGIN [sa] WITH PASSWORD = N'<new>'"          # and every other SQL_LOGIN
      ```
      The scorer logs in to SQL - **every changed SQL login it might use → PCR right away.** Don't disable `sa` or switch
      to Windows-only authentication.

## 2. The rest of the deploy steps
| Step | What to watch for |
|---|---|
| harden | Adds allow rules for 445, 3389, 1433 (and the port `sqlservr.exe` really listens on) **before** turning the firewall on; RDP kept on with NLA; SMB1 off; SMB signing required (test the share from another box afterwards); LLMNR/NetBIOS off; WDigest off; LSA protection after a reboot. |
| secure | SMB: share backup + hash list, no anonymous/null sessions, share-access auditing; asks before making Everyone-style write access read-only. RDP: NLA, TLS, high encryption. SQL: asks before turning off xp_cmdshell / OLE Automation / ad hoc queries / CLR; login auditing; reports weak SQL logins, sysadmins, startup procedures, linked servers. Undoes a section whose test fails. |
| cis | CIS Level 1 controls not covered elsewhere: advanced audit policy + log sizes, UAC, anonymous access, SMB client, AutoPlay, logon banner, RDP/WinRM client options, printer drivers, Defender + ASR, PowerShell transcription, user rights, unneeded services. Asks per section; WinRM service / lockout / renames stay as they are (`../CIS.md`). |
| forwarder | Splunk forwarder: Security/System/Application logs. |
| audit | Run keys, services, tasks, WMI, IFEO, startup, Defender exclusions... |
| services | 135/445/1433/3389 protected. Print Spooler flagged → disable. SQL Server 2014 or older flagged as end-of-life. |
| beacon | Outbound-connection watcher. |

## 3. Manual hardening (after each change: `Test-NetConnection 127.0.0.1 -Port 1433`, `-Port 445`, `-Port 3389`)
### 3.1 Local accounts and groups
- [ ] `Get-LocalUser | ft Name, Enabled, LastLogon, PasswordLastSet`; unknown → `Disable-LocalUser <name>` (don't delete).
- [ ] `Get-LocalGroupMember Administrators` - only the team's accounts (+ `Domain Admins` if joined). Remove others: `Remove-LocalGroupMember Administrators <name>`.
- [ ] `Get-LocalGroupMember 'Remote Desktop Users'` - **keep the scored RDP user(s)**, remove unknown ones.
- [ ] Guest disabled (harden did it): `Get-LocalUser Guest | Select Enabled`

### 3.2 The SOP share (MSSQL SMB check)
- [ ] Files unchanged? `Get-ChildItem <share path> -Recurse -File | Get-FileHash | Select Hash, Path` vs the
      `C:\ProgramData\CCDC\share-<name>-hashes-*.csv` from `secure`. Missing / changed file → restore from `C:\CCDC-backup\share`.
- [ ] Share permissions: the scored account needs **Read**. Everyone/Users with Full/Change = anyone with any password can
      delete the SOPs → Read only (`secure` asks). By hand: `Grant-SmbShareAccess -Name <share> -AccountName Everyone -AccessRight Read -Force`
- [ ] NTFS permissions: `icacls <share path>` - remove write for groups that don't need it, keep read for the scored account.
      Test from another box after every change (section 4).
- [ ] Unknown shares: `Get-SmbShare` - anything new besides `ADMIN$`, `C$`, `IPC$` and the SOP share → `Remove-SmbShare <name>` (after noting it for the incident report).
- [ ] Open sessions / files right now (who is connected): `Get-SmbSession | ft ClientComputerName, ClientUserName`; `Get-SmbOpenFile`

### 3.3 RDP (MSSQL RDP check)
- [ ] After `secure`: `Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' | Select UserAuthentication, SecurityLayer, MinEncryptionLevel` → 1, 2, 3.
- [ ] RDP on and on 3389: `(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections` → 0;
      `(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').PortNumber` → 3389.
- [ ] Sticky-keys / utilman backdoors (classic RDP-login-screen backdoor) - `audit.ps1` checks; by hand:
      `Get-Item C:\Windows\System32\sethc.exe, utilman.exe, osk.exe | Get-AuthenticodeSignature | ft Path, Status` → all Valid;
      `Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' | ? { $_.GetValue('Debugger') }` → none.
- [ ] Who logged in over RDP: `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 200 | ? { $_.Properties[8].Value -eq 10 } | select TimeCreated, @{n='User';e={$_.Properties[5].Value}}, @{n='From';e={$_.Properties[18].Value}}`

### 3.4 SQL Server (MSSQL check)
Run each in `sqlcmd -S localhost -E -Q "..."` (or SSMS as a sysadmin).
- [ ] Logins with blank / own-name passwords (`secure` reports them): change them now, PCR if scored.
- [ ] Logins without the Windows password policy: `SELECT name FROM sys.sql_logins WHERE is_policy_checked = 0` →
      `ALTER LOGIN [<name>] WITH CHECK_POLICY = ON` (after the password is strong - it fails otherwise).
- [ ] sysadmin members - only `sa`, the team, the service SIDs: `SELECT name FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin', name) = 1`
      Remove unknown: `ALTER SERVER ROLE sysadmin DROP MEMBER [<name>]` (ask first - never the scored login).
- [ ] Hidden power: `SELECT pr.name, pe.permission_name FROM sys.server_permissions pe JOIN sys.server_principals pr ON pe.grantee_principal_id = pr.principal_id WHERE pe.permission_name IN ('CONTROL SERVER','IMPERSONATE','ALTER ANY LOGIN')`
- [ ] Code-execution features off (`secure` asks): `SELECT name, value_in_use FROM sys.configurations WHERE name IN ('xp_cmdshell','Ole Automation Procedures','Ad Hoc Distributed Queries','clr enabled','external scripts enabled')` → all 0 unless the app needs one.
- [ ] TRUSTWORTHY databases (a db_owner can become sysadmin): `SELECT name FROM sys.databases WHERE is_trustworthy_on = 1 AND name <> 'msdb'`
      → `ALTER DATABASE [<db>] SET TRUSTWORTHY OFF` (ask first - some apps rely on it; test the query after).
- [ ] Persistence inside SQL Server:
      - startup procedures: `SELECT name FROM master.sys.procedures WHERE OBJECTPROPERTY(object_id, 'ExecIsStartup') = 1`
      - SQL Agent jobs: `SELECT j.name, j.enabled, s.subsystem, s.command FROM msdb.dbo.sysjobs j JOIN msdb.dbo.sysjobsteps s ON j.job_id = s.job_id`
        (`CmdExec` / `PowerShell` steps you didn't create = incident → `EXEC msdb.dbo.sp_update_job @job_name='<name>', @enabled=0`)
      - linked servers: `EXEC sp_linkedservers`
      - server triggers: `SELECT name FROM sys.server_triggers`
- [ ] Data the scored query reads: don't drop, truncate or "clean up" anything. Changed rows = restore from `C:\CCDC-backup\<db>.bak` (ask the captain).
- [ ] Network: TCP/IP on, listening on 1433 (SQL Server Configuration Manager → Protocols). SQL Browser (UDP 1434) only
      needed for named instances (`secure` offers to stop it for a default instance).
- [ ] Encryption: leave **Force Encryption off** (clients that don't trust a self-signed certificate would fail the check).
- [ ] Login auditing failed + successful (`secure` sets it; active after the next SQL restart). Failed logins:
      `EXEC xp_readerrorlog 0, 1, N'Login failed'`

### 3.5 Services, firewall, protocols
- [ ] Firewall on, scored ports allowed: `Get-NetFirewallProfile | ft Name, Enabled`; `Get-NetFirewallRule -Name CCDC-Scored-* | ft Name, Enabled`
- [ ] Inbound allow rules you don't recognise: `Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | ft DisplayName, Profile`
- [ ] Print Spooler off: `Stop-Service Spooler; Set-Service Spooler -StartupType Disabled`
- [ ] WinRM: not scored here. If nobody uses it: `Stop-Service WinRM; Set-Service WinRM -StartupType Disabled` (check Quotient first).
- [ ] No anonymous enumeration (`secure` set it): `Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa | Select RestrictAnonymous, RestrictAnonymousSAM` → 1, 1
- [ ] Services not from Microsoft: `.\windows\services.ps1 -Role mssql` lists them - unknown ones = check the binary path.

### 3.6 Defender, logs, updates
- [ ] `Get-MpComputerStatus | fl RealTimeProtectionEnabled, AntivirusSignatureLastUpdated`; `Get-MpPreference | fl Exclusion*` →
      exclusions only for SQL data folders, if any (unknown ones = attacker hiding tools).
- [ ] `Start-MpScan -ScanType QuickScan`
- [ ] Bigger Security log: `wevtutil sl Security /ms:524288000`; file-share auditing (`secure`): events 5140/5145.
- [ ] Updates: `.\windows\services.ps1 -Role mssql` lists them; installing = reboot = all three checks down → only with the captain.

### 3.7 Take the baseline and back up (last)
- [ ] `powershell -ExecutionPolicy Bypass -File .\deploy.ps1 -Role mssql -Only fim`
- [ ] **Off the box:** at the next vault window (the captain calls it): `.\windows\offbox.ps1 push` (team backup passphrase,
      then the window password). It takes `C:\CCDC-backup` (share copy, SQL `.bak` files) and the newest share backup + hashes from `secure` - never the password CSVs.
      Big `.bak` files (zip limit 2 GB in PowerShell 5): push them on their own with `-Include C:\CCDC-backup\<db>.bak`.
- [ ] Optional: add the SOP share to the file monitor - `WIN_FIM_EXTRA_PATHS=('<share path>')` in `ccdc.conf`, then `-Only fim` again.

## 4. Check the scored services (from Kali = like the scorer, or the Windows workstation)
```bash
P=172.25.<20+N>.120
smbclient -L //$P -U '<user>%<new password>'                     # lists the SOP share
smbclient //$P/<share> -U '<user>%<new password>' -c 'ls'        # lists the SOP files
nc -zv $P 3389; nc -zv $P 1433; ping -c2 $P
```
(Kali has `impacket-mssqlclient '<sqluser>:<pw>@'$P` for a real SQL login + `SELECT @@version;`.)
Quotient: MSSQL SMB, RDP, MSSQL, ping up.

## 5. Every 30 minutes
- [ ] SOP hashes unchanged (3.2); shares unchanged (`Get-SmbShare`)
- [ ] `.\windows\audit.ps1` (report); `.\windows\beacon.ps1 report`
- [ ] Failed SQL logins (`xp_readerrorlog` above); failed Windows logons: `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddMinutes(-30)} | measure`
- [ ] sysadmin members and SQL Agent jobs unchanged (3.4)
- [ ] `Get-LocalGroupMember Administrators` unchanged

## Things that lose points - don't
- Don't delete, move or rename the share or the SOP files
- Don't stop SQL Server, change its port, disable TCP/IP, or force encryption
- Don't disable RDP or SMB, or restrict 445/1433/3389 to inside addresses
- Don't change a scored login's password (Windows, domain or SQL) without a PCR; don't disable `sa`
- Don't drop or "clean up" databases or tables - the scored query reads them
- Don't reboot or install updates during scoring without the captain
