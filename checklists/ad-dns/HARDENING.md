# Server 2022 AD / DNS (domain controller) - hardening checklist

| | |
|---|---|
| Address | `172.20.240.100`, public `172.25.(20+N).100` |
| OS / roles | Windows Server 2022 Standard: Active Directory Domain Services, DNS |
| Default login | `sysadmin` (paper only: ________ ); domain: ________ |
| **Scored** | **DNS** lookups; **AD-WinRM** (logs in to WinRM 5985/5986 and runs a PowerShell command); ping |
| Script role | `dc` (`deploy.ps1 -Role dc`) |
| Others depend on it | POP3/IMAP/webmail logins (AD usernames), MSSQL SMB/RDP if they use domain users, every domain-joined box |

Work from the VM console in an **Administrator PowerShell**. Assume every domain password is known to the red team.
If this box breaks, several scored services break with it - change one thing at a time and test DNS + WinRM after each.
Incident response: `IR.md`.

---

## 0. Before touching anything (5 min)
- [ ] Domain facts: `Get-ADDomain | Select DNSRoot, NetBIOSName, PDCEmulator, DomainMode`
- [ ] **Prove both scored checks work now:**
      ```powershell
      Get-DnsServerZone | ft ZoneName, ZoneType, IsDsIntegrated, DynamicUpdate, SecureSecondaries
      Resolve-DnsName <scored name> -Server 127.0.0.1          # each name Quotient checks (ask the captain)
      Test-WSMan localhost; Get-Service WinRM; winrm enumerate winrm/config/listener
      Invoke-Command -ComputerName localhost -ScriptBlock { hostname }
      ```
      Scored DNS names: ____________   WinRM check user (from Quotient / injects): ____________
- [ ] Backups (no VM snapshots in the invitational):
      ```powershell
      New-Item -ItemType Directory C:\CCDC-backup -Force | Out-Null
      Get-DnsServerZone | ? { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' } | % { Export-DnsServerZone -Name $_.ZoneName -FileName "ccdc-$($_.ZoneName).bak" }   # → C:\Windows\System32\dns\
      Get-DnsServerZone | % { $z = $_.ZoneName; Get-DnsServerResourceRecord -ZoneName $z | Select @{n='Zone';e={$z}}, HostName, RecordType, @{n='Data';e={"$($_.RecordData.IPv4Address)$($_.RecordData.HostNameAlias)$($_.RecordData.NameServer)"}} } | Export-Csv C:\CCDC-backup\dns-records.csv -NoType
      Backup-GPO -All -Path C:\CCDC-backup\gpo | Out-Null
      Get-ADUser -Filter * -Properties whenCreated, memberOf, adminCount | Select SamAccountName, Enabled, whenCreated, adminCount | Export-Csv C:\CCDC-backup\users.csv -NoType
      Get-ADGroupMember 'Domain Admins' | Select SamAccountName | Export-Csv C:\CCDC-backup\domain-admins.csv -NoType
      ```
- [ ] **The Email box's LDAP bind account** (ask the email person - section 0 of `../email/HARDENING.md`): ____________.
      Change it only together with the Email box's config, then test a POP3 login.

## 1. Passwords - first 5 minutes
- [ ] Scripts to `C:\CCDC` (`../GETTING_SCRIPTS.md`), team number + `SCORED_USERS` (the mail users and any AD user
      Quotient checks) in `ccdc.conf`, `CONFIG_REVIEWED=yes`.
- [ ] Deploy without the file-integrity baseline (it comes after the manual hardening):
      ```powershell
      cd C:\CCDC
      powershell -ExecutionPolicy Bypass -File .\deploy.ps1 -Role dc -Skip fim
      ```
- [ ] `passwords` step = `ad_passwords.ps1`: **every domain account**. You type yours; the rest get random ones.
      **Scored users are printed as `username,password` → captain → Quotient PCR now.**
      - Accounts with SPNs (service accounts, e.g. SQL Server's) are **skipped and listed** - change each one together
        with the service that uses it (`../mssql/HARDENING.md`).
      - The Email bind account: skip it here (`.\windows\ad_passwords.ps1 -Skip <name>` if you run it again) and change it with the email person.
- [ ] Local accounts on this box: a DC has none besides the built-ins; DSRM (directory restore) password:
      `ntdsutil "set dsrm password" "reset password on server null" q q`
- [ ] `krbtgt` (invalidates forged Kerberos tickets): once things are stable, `.\windows\ad_passwords.ps1 -ResetKrbtgt`,
      and **again 1-2 hours later** (the second reset is what kills golden tickets).

## 2. The rest of the deploy steps
| Step | What to watch for |
|---|---|
| harden | Allows DNS/AD/WinRM ports in **before** turning the firewall on; ping; SMB1 off; SMB signing; LLMNR/NetBIOS off; WDigest off; LSA protection (needs a reboot - pick a quiet moment, DNS is down meanwhile). "Disable Guest" may fail on a DC - expected. |
| secure | DNS: zone transfers off, secure dynamic updates, cache locking, rate limiting, audit log; asks about limiting recursion to the LAN. WinRM: running, HTTPS listener 5986 added (5985 kept); asks before turning off Basic / unencrypted / CredSSP - **answer n unless you know the scorer doesn't use them**. Tests and undoes a failing section. |
| cis | CIS Level 1 controls not covered elsewhere: advanced audit policy + log sizes, UAC, anonymous access, SMB client, AutoPlay, logon banner, RDP/WinRM client options, printer drivers, Defender + ASR, PowerShell transcription, user rights, unneeded services. Asks per section; WinRM service / lockout / renames stay as they are (`../CIS.md`). |
| forwarder | Splunk forwarder: Security/System/Application logs. |
| audit | Run keys, services, tasks, WMI, IFEO, startup... |
| services | 53/88/135/389/445/464/636/3268/3269/5985/5986 protected. Print Spooler flagged → disable it (PrintNightmare). LmCompatibilityLevel 5 offered (refuse LM/NTLMv1). |
| beacon | Outbound-connection watcher. |

## 3. Manual hardening (one change at a time; after each: `Resolve-DnsName <scored name> -Server 127.0.0.1` and `Invoke-Command localhost { 1 }`)
### 3.1 Privileged groups
- [ ] Members of the powerful groups - anything not in `C:\CCDC-backup\domain-admins.csv` / not the team = incident:
      ```powershell
      'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators','Print Operators','DnsAdmins','Group Policy Creator Owners','Remote Management Users' |
        % { $g = $_; Get-ADGroupMember $g -ErrorAction SilentlyContinue | Select @{n='Group';e={$g}}, SamAccountName, objectClass } | ft -AutoSize
      ```
      `DnsAdmins` members can run code on the DC (DLL loading) - should be empty. Remove: `Remove-ADGroupMember <group> <user> -Confirm:$false`.
- [ ] Accounts that were ever privileged (`adminCount=1`): `Get-ADUser -Filter 'adminCount -eq 1' | Select SamAccountName, Enabled`
- [ ] New accounts since the start: `Get-ADUser -Filter * -Properties whenCreated | ? whenCreated -gt (Get-Date).AddHours(-4) | Select SamAccountName, whenCreated`
- [ ] Unknown accounts: **disable, don't delete** (usernames can't change - rule 11): `Disable-ADAccount <name>`

- [ ] **AD Recycle Bin on** - deleted users/groups/OUs can then be restored in seconds (`../BACKUP_AND_RECOVERY.md`). One-way
      switch, harmless (needs forest level 2008 R2+):
      `Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADForest).Name -Confirm:$false`
      Check: `Get-ADOptionalFeature 'Recycle Bin Feature' | Select EnabledScopes`

### 3.2 Account settings attackers abuse (`ad_passwords.ps1` / `ad_audit.ps1` find most of these)
- [ ] Run `.\windows\ad_audit.ps1` (report), then `-Fix` for the safe fixes it offers. It covers AS-REP roasting,
      password-not-required, reversible encryption, DCSync rights, delegation, GPO changes.
- [ ] Kerberoastable accounts: `Get-ADUser -Filter 'ServicePrincipalName -like "*"' -Properties ServicePrincipalName, PasswordLastSet | Select SamAccountName, PasswordLastSet`
      → long random passwords, changed together with their service.
- [ ] Unconstrained delegation (only DCs should have it): `Get-ADComputer -Filter 'TrustedForDelegation -eq $true' | Select Name`;
      `Get-ADUser -Filter 'TrustedForDelegation -eq $true' | Select SamAccountName`
- [ ] Nobody can add computers to the domain (blocks noPac / RBCD attacks; normal users don't need it):
      ```powershell
      Get-ADDomain | Select -Expand DistinguishedName | % { Get-ADObject $_ -Properties ms-DS-MachineAccountQuota } | Select ms-DS-MachineAccountQuota
      Set-ADDomain (Get-ADDomain) -Replace @{'ms-DS-MachineAccountQuota' = 0}
      ```
- [ ] Unknown computer accounts: `Get-ADComputer -Filter * -Properties whenCreated | Select Name, Enabled, whenCreated | Sort whenCreated`
- [ ] DCSync rights (replication) only for DCs and admins:
      ```powershell
      (Get-Acl "AD:$((Get-ADDomain).DistinguishedName)").Access | ? { $_.ObjectType -in '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' } | Select IdentityReference, ActiveDirectoryRights
      ```
- [ ] `Pre-Windows 2000 Compatible Access` should not contain `Anonymous Logon` / `Everyone`: `Get-ADGroupMember 'Pre-Windows 2000 Compatible Access'` - note it; removing can break old apps, ask first.

### 3.3 Group Policy and SYSVOL
- [ ] Recently changed GPOs: `Get-GPO -All | Sort ModificationTime -Desc | Select -First 10 DisplayName, ModificationTime`
      → for a GPO changed during the competition: `Get-GPOReport -Name '<name>' -ReportType Html -Path C:\CCDC-backup\<name>.html` and read it.
- [ ] Scripts and scheduled tasks pushed by GPO (persistence on every domain box):
      `Get-ChildItem "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\Policies" -Recurse -Include *.ps1,*.bat,*.cmd,*.vbs,ScheduledTasks.xml,Scripts.ini | Select FullName, LastWriteTime`
- [ ] Old Group Policy Preferences passwords (decryptable by anyone): `findstr /S /I cpassword "\\%USERDNSDOMAIN%\SYSVOL\%USERDNSDOMAIN%\Policies\*.xml"` → any hit: delete that preference item in the GPO editor and change that password.
- [ ] Password policy (the script sets it in the Default Domain Policy): `Get-ADDefaultDomainPasswordPolicy` → 14+ characters, complexity on, **lockout threshold 0** (lockout lets the red team lock out scored users).

### 3.4 DNS
- [ ] After `secure`: `Get-DnsServerZone | ft ZoneName, DynamicUpdate, SecureSecondaries` → `Secure` (AD zones) and `NoTransfer`.
- [ ] Recursion: keep it working for the LAN (the boxes resolve the internet through this server). Forwarders: `Get-DnsServerForwarder` - unknown IPs = red team redirecting lookups; compare with the start.
- [ ] Records still match the start (scored names especially) - re-export and compare:
      ```powershell
      $now = Get-DnsServerZone | % { $z = $_.ZoneName; Get-DnsServerResourceRecord -ZoneName $z | Select @{n='Zone';e={$z}}, HostName, RecordType, @{n='Data';e={"$($_.RecordData.IPv4Address)$($_.RecordData.HostNameAlias)$($_.RecordData.NameServer)"}} }
      Compare-Object (Import-Csv C:\CCDC-backup\dns-records.csv) $now -Property Zone, HostName, RecordType, Data
      ```
- [ ] Global query block list on (stops WPAD/ISATAP hijacking; Windows default): `Get-DnsServerGlobalQueryBlockList`
- [ ] Windows Firewall lets DNS in: `Get-NetFirewallRule -DisplayGroup 'DNS Service' | ft DisplayName, Enabled`

### 3.5 WinRM (scored)
- [ ] Listeners: `winrm enumerate winrm/config/listener` → HTTP 5985 (and HTTPS 5986 after `secure`), `Address = *`.
- [ ] Who may use it: members of `Administrators` and `Remote Management Users` (list in 3.1). Remove unknown ones.
- [ ] Service settings: `winrm get winrm/config/service` → `AllowUnencrypted = false`, `Auth/Basic = false` are the
      secure values - change them only if you know the scorer's client works without them (test with Quotient right after).
- [ ] TrustedHosts (client side) should be empty: `Get-Item WSMan:\localhost\Client\TrustedHosts`

### 3.6 Protocols and services on the DC
- [ ] SMB1 off, signing required (harden did it): `Get-SmbServerConfiguration | fl EnableSMB1Protocol, RequireSecuritySignature`
- [ ] Print Spooler off (no printers on a DC): `Stop-Service Spooler; Set-Service Spooler -StartupType Disabled`
- [ ] NTLMv1/LM refused: `Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name LmCompatibilityLevel` → 5
- [ ] **LDAP signing / channel binding: don't force** - the Email box may bind with plain LDAP on 389; forcing breaks mail logins.
- [ ] RDP: not scored on this box and we work from the console. Off is safest:
      `Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' fDenyTSConnections 1`
      (only after checking Quotient has no RDP check for the DC). Undo: same with `0`.
- [ ] Shares: `Get-SmbShare` → only `ADMIN$`, `C$`, `IPC$`, `NETLOGON`, `SYSVOL` (+ any the packet mentions). Unknown share = incident.

### 3.7 Auditing and logs (evidence)
- [ ] Bigger Security log (default 128 MB fills quickly on a DC): `wevtutil sl Security /ms:1073741824`
- [ ] Audit policy for incident reports:
      ```powershell
      'Logon','Account Lockout','Special Logon','Kerberos Authentication Service','Kerberos Service Ticket Operations','Credential Validation','User Account Management','Security Group Management','Computer Account Management','Directory Service Changes','Directory Service Access','Process Creation','Audit Policy Change','Sensitive Privilege Use' |
        % { auditpol /set /subcategory:"$_" /success:enable /failure:enable | Out-Null }
      auditpol /get /category:* | Select-String 'Success'  | Measure-Object | Select Count
      ```
- [ ] Event IDs to watch: 4720 new user, 4728/4732/4756 added to a group, 4724 password reset, 4672 admin logon,
      4769 Kerberos ticket (Kerberoasting = many RC4 4769s), 5136 directory object changed, 4662 replication (DCSync), 1102 log cleared.
- [ ] PowerShell logging on (harden did it): `Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`

### 3.8 Defender and updates
- [ ] `Get-MpComputerStatus | fl RealTimeProtectionEnabled, AntivirusSignatureLastUpdated`; exclusions empty: `Get-MpPreference | fl Exclusion*`
- [ ] Quick scan: `Start-MpScan -ScanType QuickScan`
- [ ] Updates: `.\windows\services.ps1 -Role dc` lists pending ones. Installing needs a reboot = DNS and WinRM down → only with the captain, at a quiet time.

### 3.9 Take the baseline and back up (last)
- [ ] `powershell -ExecutionPolicy Bypass -File .\deploy.ps1 -Role dc -Only fim`
- [ ] Refresh the section-0 backups (GPOs, users, DNS records and zone exports) so they show the hardened state.
- [ ] **Off the box:** at the next vault window (the captain calls it): `.\windows\offbox.ps1 push` (team backup passphrase,
      then the window password). It takes `C:\CCDC-backup` and the DNS zone exports - never the password CSVs.
- [ ] Reboot for LSA protection when the captain says it's quiet; afterwards test DNS + WinRM + a POP3 login on the Email box.

## 4. Check the scored services (from Kali = like the scorer, or from the Windows workstation)
```bash
dig @172.25.<20+N>.100 <scored name> +short          # Kali; or: nslookup <scored name> 172.25.<20+N>.100
ping -c2 172.25.<20+N>.100
```
```powershell
# from the Windows 11 workstation
Test-WSMan 172.20.240.100
Invoke-Command -ComputerName 172.20.240.100 -Credential (Get-Credential) -ScriptBlock { hostname }
```
Quotient: DNS, AD-WinRM, ping up - and the Email box's POP3/IMAP (they log in against this DC).

## 5. Every 30-60 minutes
- [ ] `.\windows\ad_audit.ps1 -Hours 1` - changes in the last hour (users, groups, GPOs, ACLs)
- [ ] `.\windows\audit.ps1` (report only); `.\windows\beacon.ps1 report`
- [ ] Privileged group members (3.1) unchanged; DNS records (3.4) unchanged
- [ ] Recent admin logons: `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4672; StartTime=(Get-Date).AddMinutes(-30)} | select -First 20 TimeCreated, Message`
- [ ] Second `krbtgt` reset 1-2 hours after the first

## Things that lose points - don't
- Don't change the DC's name or IP, demote it, or remove the DNS role or zones
- Don't turn on account lockout (the red team locks out the scored users)
- Don't change a scored user's password without a PCR; don't change the Email bind account without updating the Email box
- Don't stop WinRM, delete its HTTP listener, or restrict 5985/5986 to inside addresses
- Don't force LDAP signing / channel binding; don't block 53, 88, 389, 636, 445 from the LAN
- Don't disable SMB or the SYSVOL/NETLOGON shares; don't add scored users to Protected Users (it blocks NTLM logins)
- Don't reboot during scoring checks without warning the team
