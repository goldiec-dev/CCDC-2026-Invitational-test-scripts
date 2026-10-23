# AD / DNS server - incident response checklist

Order: **record → contain → clean up → check DNS + logins → report.** General Windows steps (sessions,
processes, persistence) are in `../windows/IR.md`; this page adds what is specific to a domain controller.

## Signs of trouble
| What | Where | Event ID |
|---|---|---|
| New user / user enabled | Security log | 4720 / 4722 |
| Added to a privileged group | Security log | 4728 (global), 4732 (local), 4756 (universal) |
| Password reset by someone else | Security log | 4724 |
| Directory object changed (GPO, ACL) | Security log (needs DS Access auditing) | 5136 |
| Kerberoasting: service tickets with RC4 | Security log, Ticket Encryption Type 0x17 | 4769 |
| DCSync: replication requested by a non-DC | Security log, properties with the replication GUIDs | 4662 |
| DNS record created / deleted | Applications and Services Logs > Microsoft > Windows > DNS-Server > Audit | 515 / 516 |
| Log cleared | Security log | 1102 |

Quick look: `Get-WinEvent -FilterHashtable @{LogName='Security';Id=4720,4724,4728,4732,4756} -MaxEvents 50 | Select TimeCreated, Id, Message | Format-List`
Splunk: `index=* host=<dc name> (EventCode=4720 OR EventCode=4728 OR EventCode=4732 OR EventCode=4756 OR EventCode=4724)`

Fast triage: `.\windows\ad_audit.ps1 -Hours 2` - new users, group additions (with times), DCSync rights and
events, delegation changes, GPO changes and the DNS plugin backdoor in one report (saved for the incident report).

## 1. Record
- [ ] Run the `../windows/IR.md` record step (connections, processes, event log export).
- [ ] `Get-ADUser -Filter * -Properties whenCreated, whenChanged | Sort whenChanged -Desc | Select -First 20 SamAccountName, Enabled, whenCreated, whenChanged`
- [ ] Privileged group members now vs. `C:\CCDC-backup\users.csv`
- [ ] DNS records now vs. `C:\CCDC-backup\dns-records.csv` (export again and `Compare-Object` on HostName + Data)
- [ ] Screenshot the events that show who did what, from which computer/IP, and when.

## 2. Contain
- [ ] Disable accounts the attacker created or used (don't delete - evidence): `Disable-ADAccount <name>`
- [ ] Remove them from privileged groups: `Remove-ADGroupMember 'Domain Admins' <name>`
- [ ] Reset passwords of every account the attacker used; if a Domain Admin was compromised,
      run `ad_passwords.ps1` again (all accounts) and **reset krbtgt twice** (`-ResetKrbtgt`, then again later).
      Report scored users' new passwords.
- [ ] Block the source IP on the Palo Alto (`../palo-alto/IR.md`) - never the scoring engine.

## 3. Clean up
- [ ] Remove replication (DCSync) rights granted to non-DC accounts (the check in `HARDENING.md`) via
      Active Directory Users and Computers > domain > Properties > Security.
- [ ] Malicious GPO changes: compare with the backup (`Get-GPOReport -Name <gpo> -ReportType Html`); restore with
      `Restore-GPO -Name <gpo> -Path C:\CCDC-backup\gpo`; remove rogue scheduled tasks/scripts in SYSVOL.
- [ ] Wrong DNS records: fix them (`Remove-DnsServerResourceRecord` / `Add-DnsServerResourceRecordA`), or restore a
      file-backed zone from `C:\Windows\System32\dns\ccdc-<zone>.bak`. Then `Clear-DnsServerCache`.
- [ ] `.\windows\audit.ps1 -Fix` on the DC, and on any machine the attacker reached with domain credentials.

## 3b. Recover from a backup
Full procedure: `../BACKUP_AND_RECOVERY.md` (Windows → Domain controller). Record evidence first.
- [ ] **Deleted users / groups / OUs:** with the AD Recycle Bin on (`HARDENING.md` 3.1):
      `Get-ADObject -Filter 'samAccountName -eq "<name>"' -IncludeDeletedObjects | Restore-ADObject` → then set a new password (PCR if scored)
- [ ] **Privileged group changed:** compare with `C:\CCDC-backup\domain-admins.csv` and `users.csv`; remove the additions
- [ ] **GPO changed or deleted:** `Restore-GPO -Name '<name>' -Path C:\CCDC-backup\gpo`, then `gpupdate /force` on the DC
- [ ] **DNS records changed:** compare with `C:\CCDC-backup\dns-records.csv` (HARDENING 3.4), fix each record; whole zone: re-import
      `C:\Windows\System32\dns\ccdc-<zone>.bak` (steps in `../BACKUP_AND_RECOVERY.md`) - DNS is scored, test from Kali after each step
- [ ] Local backups gone: vault `serve <file>` → `.\windows\offbox.ps1 fetch -File <file>` → `C:\CCDC-restore-<time>\`

## 4. Check
- [ ] `Resolve-DnsName <scored name> -Server 172.20.240.100` from another box; Quotient shows DNS and AD-WinRM up
- [ ] POP3/IMAP login still works on the Email box (AD authentication); `Test-WSMan 172.20.240.100` from another box
- [ ] `dcdiag /q` reports no errors (no output = healthy)

## 5. Report (`../../injects/README.md`)
Source/destination IPs, timeline, accounts and passwords compromised, what changed (users, groups, GPOs,
DNS records), what was affected, remediation and prevention.
