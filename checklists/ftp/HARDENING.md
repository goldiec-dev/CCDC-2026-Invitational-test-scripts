# Server 2022 FTP server - first-hour hardening checklist

> **Not in the 2026 invitational topology** (no such VM in the team pack) - kept for older topologies.

2026: `172.20.240.104`, public `172.25.(20+N).162`, behind the Cisco FTD.
**Probably scored: FTP** (check the scoring portal's service list). FTP sends passwords in cleartext, so
the FTP user accounts are prime red team targets - change them, and report any the scorer uses.
Incident response: `../windows/IR.md` (plus the FTP log checks below).

## 0. Before touching anything (3 min)
- [ ] Which FTP server is it? `Get-Service ftpsvc, FileZilla* -ErrorAction SilentlyContinue`;
      `Get-NetTCPConnection -LocalPort 21 -State Listen | % { Get-Process -Id $_.OwningProcess }`
- [ ] IIS FTP: `Import-Module WebAdministration; Get-WebSite | ? { $_.Bindings.Collection.protocol -contains 'ftp' } | Select Name, State, PhysicalPath`
- [ ] Note: the FTP root folder, how users log in (anonymous? local users? AD users?), whether SSL is
      required, and the passive port range (IIS Manager > server > FTP Firewall Support).
- [ ] Prove it works and save the result: from another box `ftp 172.20.240.104` (or `curl ftp://user:pass@172.20.240.104/`)
- [ ] Back up the FTP content and IIS config: `Compress-Archive <ftp root> C:\CCDC-ftp-orig.zip`,
      `& $env:windir\system32\inetsrv\appcmd.exe add backup ccdc-orig`

## 1. Run the scripts
```powershell
cd C:\CCDC
powershell -ExecutionPolicy Bypass -File .\deploy.ps1 -Role ftp
```
- `-Role ftp` protects ports 20/21/990: the services step will **not** remove the IIS FTP feature.
- passwords: local accounts (FTP users included if they're local) - **report scored FTP users**. If FTP
  users are AD accounts, they're changed on the DC (`ad_passwords.ps1`).
- The file integrity monitor watches the IIS config (`applicationHost.config`), where FTP settings live.

## 2. Check next
- [ ] Privilege-escalation paths and LOLBin abuse: `.\windows\privesc.ps1` (report), then `-Fix`; consider `-BlockLolbinEgress` (certutil, mshta, regsvr32... lose network access - none are needed by scored services)
- [ ] **Anonymous login:** off, unless the scoring check uses it (check the portal / an inject). IIS: FTP site >
      FTP Authentication. Test after changing.
- [ ] **User isolation** (IIS: FTP User Isolation): users only see their own folder.
- [ ] **Permissions:** FTP users can't write outside their folder; the FTP root isn't inside a web root
      (an upload there becomes a webshell). FTP Authorization Rules: only the needed users, read/write as required.
- [ ] **SSL:** "Allow SSL connections" is fine; don't set "Require SSL" unless the scorer uses FTPS.
- [ ] **Logging on:** IIS > FTP Logging; logs in `C:\inetpub\logs\LogFiles\FTPSVC*`. Splunk: add that folder as an input.
- [ ] **Uploads watch:** alert on new executables/scripts in the FTP root (they shouldn't appear):
      `.\windows\webguard.ps1 init -WebRoot <ftp root>` then `watch` (alert only - never auto-restore here, uploads are legitimate)
- [ ] Passive ports: allowed in Windows Firewall (IIS adds "FTP Server Passive"); on the FTD, FTP inspection handles them.
- [ ] Other users / admins on the box: `Get-LocalGroupMember Administrators`

## What attacks look like in the FTP log
- Many `530` (login failed) lines from one IP - password guessing
- `STOR` of `.exe`, `.ps1`, `.aspx`, `.php` files; `DELE` of many files; logins as users nobody uses
- `Select-String C:\inetpub\logs\LogFiles\FTPSVC*\*.log -Pattern ' 530 ' | Group { ($_ -split ' ')[2] } | Sort Count -Desc`

## Things that lose points - don't
- Don't remove the FTP feature/service, change port 21, or require SSL without checking the scorer
- Don't change or disable the FTP account the scorer uses without reporting the new password
- Don't delete files from the FTP root - copy suspicious ones to `C:\ProgramData\CCDC\` first (evidence)
