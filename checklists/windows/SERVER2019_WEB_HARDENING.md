# Windows Server 2019 IIS web server - first-hour hardening checklist

> **Not in the 2026 invitational topology** (no such VM in the team pack) - kept for older topologies.

Scored service: **the website over HTTP (80)**, maybe HTTPS (443), and possibly RDP.
Defacement costs points too. Assume every password (Windows, web app, database) is already known to the red team.

> The Windows scripts have **not been run on a real Windows machine yet**. Test them on a practice VM before competition day.

## 0. Before touching anything (3 min)
- [ ] Open the website in a browser and screenshot it. That's what "working" looks like.
- [ ] **PowerShell as Administrator**, then:
  - `Import-Module WebAdministration; Get-Website | ft Name,State,PhysicalPath,Bindings` - write down the bindings, don't change them
  - `Get-ChildItem IIS:\AppPools | ft Name,State,@{n='Identity';e={$_.processModel.identityType}},@{n='User';e={$_.processModel.userName}}`
- [ ] Domain-joined? `(Get-CimInstance Win32_ComputerSystem).PartOfDomain`
- [ ] Back up IIS config and the site: `& $env:windir\system32\inetsrv\appcmd.exe add backup orig`, then `Compress-Archive C:\inetpub\wwwroot C:\CCDC-wwwroot-orig.zip`
- [ ] Copy the `CCDC Scripts` folder to the box (e.g. `C:\CCDC`)

## 1. Run the scripts
Set `WIN_WEBROOT` in `ccdc.conf` to the scored site's PhysicalPath from step 0.
```powershell
cd C:\CCDC
powershell -ExecutionPolicy Bypass -File .\deploy.ps1 -Role web
```
It runs these in order and asks before each: **passwords → harden → forwarder → audit → services → webguard → beacon → fim**.
Re-run one step: `.\deploy.ps1 -Role web -Only webguard`

If `deploy.ps1` fails, run the scripts by hand:
```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
cd C:\CCDC\windows
.\passwords.ps1 -ScoredUsers <user1>,<user2>      # FIRST: every local password + policy
.\harden.ps1                                      # baseline hardening; doesn't touch IIS sites/bindings
.\audit.ps1 -Fix -ExpectedAdmins <legit admin>    # hunt, including webshells in every site
.\webguard.ps1 init -WebRoot C:\inetpub\wwwroot   # ONLY after the site looks right AND audit removed webshells
.\webguard.ps1 watch -WebRoot C:\inetpub\wwwroot  # leave this window open (alerts only)
```

| Script | What to watch for |
|---|---|
| `passwords.ps1` | Scored users are printed: send them to the captain now. **App pools, services and tasks that run as a local user get the new password automatically.** Reload the site right after. |
| `harden.ps1` | OK/FAIL per line. Reboot later for LSA protection, at a quiet moment. |
| forwarder | Installs the Splunk forwarder (Application/Security/System logs to `SPLUNK`). Add IIS logs as an input afterwards. |
| `audit.ps1` | The IIS section lists `.aspx/.asp/.php` files with webshell patterns. They're quarantined to `C:\ProgramData\CCDC\quarantine-*`, not deleted. |
| services | Removes legacy features/services/protocols after asking (SMB1, PowerShell 2.0, Telnet, SNMP, Remote Registry, TLS 1.0/1.1...) - never one on a scored port. Lists pending Windows updates; install with `.\windows\services.ps1 -InstallUpdates` at a quiet time (may need a reboot). |
| webguard | Asks whether the site looks right, takes the baseline, then watches it from a SYSTEM scheduled task `CCDC-WebGuard` (survives reboot). Alerts: Event Viewer → Application, source WebGuard. **After an inject changes the site: `.\deploy.ps1 -Role web -Only webguard`** |
| beacon | Watches outbound TCP for anything calling home on a timer (task `CCDC-Beacon`; table: `.\windows\beacon.ps1 report`). Alerts show the program's path and signer. |
| fim | Runs last: baselines the hosts file, scheduled task files, startup folders, PowerShell profiles, System32 programs and IIS config/modules, then watches them from task `CCDC-FIM`. Alerts: Application log, source CCDC-FIM. **After changing a watched file on purpose:** `.\windows\fim.ps1 accept -Path <file>` |

## 2. Check next
- [ ] Privilege-escalation paths and LOLBin abuse: `.\windows\privesc.ps1` (report), then `-Fix`; consider `-BlockLolbinEgress` (certutil, mshta, regsvr32... lose network access - none are needed by scored services)
- [ ] Site loads from another machine; every app pool is Started: `Get-ChildItem IIS:\AppPools | ft Name,State`
- [ ] **Web app / DB passwords** (no script does these): find connection strings with
      `Select-String -Path C:\inetpub\wwwroot\*\web.config,C:\inetpub\wwwroot\web.config -Pattern 'connectionString|password' -ErrorAction SilentlyContinue`.
      Change the DB password and the config **back to back**, then reload the site. Change CMS admin passwords in the app's admin page.
- [ ] Directory browsing off:
      `Set-WebConfigurationProperty -PSPath IIS:\ -Filter /system.webServer/directoryBrowse -Name enabled -Value $false`
- [ ] Detailed errors only for local requests:
      `Set-WebConfigurationProperty -PSPath IIS:\ -Filter /system.webServer/httpErrors -Name errorMode -Value DetailedLocalOnly`
- [ ] App pool identities: should be `ApplicationPoolIdentity`, not `LocalSystem`. **Changing an identity can break DB access, so note it and ask instead of changing it mid-game.**
- [ ] Handler mappings / modules you don't recognise: `Get-WebGlobalModule | ft Name,Image` - native modules from outside `System32\inetsrv` are suspicious
- [ ] Upload folders shouldn't run scripts: in IIS Manager → folder → Handler Mappings → Edit Feature Permissions → untick *Script* (test uploads afterwards)
- [ ] FTP / WebDAV: if they're installed and **not** scored, stop the site, don't uninstall
- [ ] Administrators group, Defender exclusions, firewall rules: same checks as the workstation checklist
- [ ] Splunk: this server shows up in `index=* host=<name> earliest=-10m`. Add `C:\inetpub\logs\LogFiles` as an input for web-attack searches.
- [ ] Re-run `.\audit.ps1` every so often; check `Get-ScheduledTask CCDC-WebGuard` is Running

## Undo
- IIS config: `& $env:windir\system32\inetsrv\appcmd.exe restore backup orig`
- Site files: `C:\CCDC-wwwroot-orig.zip`, or `.\webguard.ps1 restore`

## Things that lose points - don't
- Don't change site bindings, ports, host headers, or the site's physical path
- Don't stop the Default Web Site if it's the scored one
- Don't change a DB or app-pool password without updating whatever uses it in the same minute
- Don't run `iisreset` casually: it drops every site at once (recycle a single app pool instead)
- Don't turn on webguard `-AutoRestore` until the baseline is known-good
- Don't run Windows Update during the competition
