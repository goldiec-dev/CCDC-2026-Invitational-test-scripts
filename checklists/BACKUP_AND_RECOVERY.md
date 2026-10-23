# Backups and recovery

There are **no VM snapshots or scrubs** in the invitational - the only full reset is a new lab reservation. Our
backups are the undo button for everything the red team (or we) break. Two copies of each:

1. **On the box** - fast to restore, but the red team can delete it once they have root/Administrator.
2. **Off the box, encrypted, on the vault** - survives a wrecked box.

| Box | On-box backup (made by) | Off-box copy |
|---|---|---|
| Linux servers + Ubuntu workstation + Kali | `/root/ccdc/full-backup-<time>/` (`linux/backup.sh`, deploy step `backup`) | `linux/offbox.sh push` |
| Windows (DC, MSSQL, Win 11) | `C:\CCDC-backup\` (checklist section 0), `C:\ProgramData\CCDC\share-backup-*` (`secure.ps1`), DNS zone exports `C:\Windows\System32\dns\ccdc-*.bak` | `windows\offbox.ps1 push` |
| Palo Alto | named snapshots on the firewall (`orig-<date>`, `ccdc-before-policy-*`); exported XML on the workstation that ran `pa_policy.py` (`/root/ccdc/palo-alto/` or `~/ccdc-palo-alto/`) | the workstation's push with `--include /root/ccdc/palo-alto` |
| VyOS router | `/config/ccdc-orig.boot`, `/config/ccdc-before-fw-*.boot`, `/config/ccdc-start-commands.txt` | none (its traffic to the vault would cross the Palo Alto) - **write the key config on the paper checklist** |

## What `backup.sh` saves (Linux)
`etc.tar.gz` (all of /etc - every config, users, cron), `web-N.tar.gz` (each web root), `mysql-all.sql.gz` (every
database incl. users/grants), `postgres-all.sql.gz`, `mail.tar.gz` (spools/Maildirs), `splunk-etc-*.tar.gz` (Splunk
apps/users/inputs - not indexed data), `home-dotfiles.tar.gz` (SSH keys, shell startup files), `cron.tar.gz`,
`firewall.txt`, `state/` (users, packages, services, listeners, SUID files, keys - for diffing) and `SHA256SUMS`.
Root-only. Restores check the checksums first and always save the current state before overwriting anything.

## When to take backups
1. **Before touching anything** - the original state (deploy's first step `backup`; Windows: checklist section 0).
2. **After hardening** - the known-good, hardened state (the checklist's last step). This is the one you usually restore.
3. **After every legitimate change** (an inject changed the site, added users...) - otherwise a restore undoes the inject.
Push each one off the box at the next vault window.

## The vault (off-box copies)
The vault is a **server** (`BACKUP_VAULT` in `ccdc.conf`, default the Splunk box `172.20.240.20`; its own backup goes
to `BACKUP_VAULT_ALT`, the E-com box). Servers may be re-tasked, workstations may not.

**The team backup passphrase** encrypts every off-box copy. Pick it at the start (12+ characters, letters/digits only
so Windows and Linux read it the same), write it **on paper** only, never in a file or chat. Without it nobody - not us,
not the red team, not the vault box - can open the backups.

### Vault person: open a window (on the vault's console)
```bash
sudo bash linux/vault.sh open --minutes 15
```
It prints the vault address, port (`BACKUP_VAULT_PORT`, 2222), a fresh one-time password and its host key
fingerprints. Read the password out to the team. The window runs its **own** SSH server (the scored one is untouched),
accepts only the LAN, only the `ccdc-vault` account, only SFTP, locked in `/srv/ccdc-vault`, with no shell or
tunnels. After 15 minutes - or Enter, or if the console drops - it stops the server, closes the port, locks the
account, checks every upload against its checksum and moves it to `/root/ccdc-vault/<host>/` (root-only). It shows
`received <host>/<file>` with OK or **CHECKSUM MISMATCH** (mismatch = ask that box to push again).

Suggested schedule (the captain announces each): after the first hour's hardening, then every 1-2 hours, and after any big change.
`sudo bash linux/vault.sh list` shows everything stored.

### Every Linux box: push
```bash
sudo bash linux/backup.sh --role <role>        # a fresh backup first (or use the newest one)
sudo bash linux/offbox.sh push                 # passphrase twice, then the window password
```
It opens outbound TCP 2222 to the vault only, uploads, and closes it again. Compare the host key it prints with the
vault's screen (first contact). The outbound-SSH monitor alerts on the upload - expected; the `ccdc-offbox` syslog line
next to it marks it as ours. On the Ubuntu workstation add the Palo Alto exports:
`sudo bash linux/offbox.sh push --include /root/ccdc/palo-alto --include /home/<user>/ccdc-palo-alto`

### Every Windows box: push (Administrator PowerShell)
```powershell
cd C:\CCDC; .\windows\offbox.ps1 push           # add -Include <path> for anything else (e.g. a SQL backup folder)
```
Same format as Linux (`linux/offbox.sh decrypt` opens it too). Never includes password CSVs. Zips over 2 GB fail in
Windows PowerShell 5 - push big SQL backups separately with `-Include` on their own.

---

# Recovery

**Before any restore:** record evidence first (the box's `IR.md` step 1) - a restore overwrites the attacker's traces.
Then: restore → change passwords again (restores bring back old password hashes) → test scored services →
re-baseline the monitors → write it in the incident report.

## Getting a backup back onto the box
- **Still on the box:** `sudo bash linux/backup.sh list` → use the folder name (or `latest`).
- **Only on the vault** (box wiped, or the on-box copy deleted / checksum fails):
  1. vault person: `sudo bash linux/vault.sh list` → `sudo bash linux/vault.sh serve <file> --minutes 10`
  2. on the box: `sudo bash linux/offbox.sh fetch <file>` (window password, then the team passphrase) - it verifies,
     decrypts and unpacks to `/root/ccdc/full-backup-<time>/` and prints the restore commands.
  3. Windows: `.\windows\offbox.ps1 fetch -File <file>` → unpacked to `C:\CCDC-restore-<time>\`.

## Linux restores (`linux/backup.sh` - each one shows the differences and asks first)
| Broken | Command | Then |
|---|---|---|
| Website defaced / files deleted | `sudo bash linux/backup.sh restore-web <backup> /var/www/html` | load the page; `sudo bash ./deploy.sh --role <role> --only webguard` (re-baseline) |
| One config file or folder | `sudo bash linux/backup.sh restore-file <backup> /etc/<path>` | config check + reload (`apachectl -t`, `postfix check`, `sshd -t`...); `sudo bash linux/fim.sh accept /etc/<path>` |
| Database (shop tables wiped, admin users added) | `sudo bash linux/backup.sh restore-db <backup>` | **MySQL passwords go back to backup-time values**: `sudo bash ./deploy.sh --role ecom --only database` right after |
| A user's mailbox | `sudo bash linux/backup.sh restore-file <backup> /var/mail/<user>` (or `/home/<user>/Maildir`) | log in to POP3/IMAP as that user |
| Splunk apps / users / inputs | `sudo bash linux/backup.sh restore-file <backup> /opt/splunk/etc/<path>` | restart Splunk (both checks down 1-2 min); PCR if a Splunk password changed back |
| A user's SSH keys / `.bashrc` | `sudo bash linux/backup.sh restore-file <backup> /home/<user>/.ssh` | |
| Cron jobs | `sudo bash linux/backup.sh restore-file <backup> /var/spool/cron` | |
| What changed since the backup? | `sudo diff -r /root/ccdc/full-backup-<old>/state <dir of a fresh backup>/state` | new users, services, listeners, SUID files, keys |

Restoring `/etc/shadow` or `/etc/passwd` brings back **old passwords** - avoid; if you must, run the passwords step
again immediately and resubmit PCRs for scored users.

## Windows restores
**Domain controller**
- **Deleted AD users/groups/OUs** (if the AD Recycle Bin is on - `../ad-dns/HARDENING.md` 3.1):
  `Get-ADObject -Filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -IncludeDeletedObjects | ft Name, ObjectClass, whenChanged`
  → `Get-ADObject -Filter 'samAccountName -eq "<name>"' -IncludeDeletedObjects | Restore-ADObject`
  (Without the Recycle Bin: recreate the user with the same name; group memberships from `C:\CCDC-backup\users.csv`.)
- **Group membership changed:** compare `Get-ADGroupMember '<group>'` with `C:\CCDC-backup\domain-admins.csv`; `Remove-ADGroupMember` / `Add-ADGroupMember`.
- **A GPO changed or deleted:** `Restore-GPO -Name '<name>' -Path C:\CCDC-backup\gpo` (or `Import-GPO -BackupGpoName '<name>' -TargetName '<name>' -Path C:\CCDC-backup\gpo -CreateIfNeeded`).
- **DNS records changed:** compare with `C:\CCDC-backup\dns-records.csv` (`../ad-dns/HARDENING.md` 3.4) and fix single records with
  `Add-DnsServerResourceRecordA` / `Remove-DnsServerResourceRecord`. A whole zone wrecked (file-backed zones):
  `Remove-DnsServerZone <zone> -Force; Add-DnsServerPrimaryZone -Name <zone> -ZoneFile ccdc-<zone>.bak -LoadExisting`
  (the file must be in `C:\Windows\System32\dns\`). AD-integrated zones: recreate as file-backed from the export, then
  `ConvertTo-DnsServerPrimaryZone -Name <zone> -ReplicationScope Domain`. Test DNS from Kali after each step.

**MSSQL server**
- **SOP files deleted / changed:** compare with the saved hashes (`../mssql/HARDENING.md` 3.2), then copy back:
  `Copy-Item C:\CCDC-backup\share\* <share path> -Recurse -Force` (or from `C:\ProgramData\CCDC\share-backup-<time>\<share>`).
- **Database damaged:** `sqlcmd -S localhost -E -Q "ALTER DATABASE [<db>] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; RESTORE DATABASE [<db>] FROM DISK='C:\CCDC-backup\<db>.bak' WITH REPLACE; ALTER DATABASE [<db>] SET MULTI_USER"`
  (the MSSQL check is down for those seconds; SQL logins are in `master`, not restored by this - their passwords stay).
- **Registry / service settings our scripts changed:** the undo CSVs `C:\ProgramData\CCDC\*-undo.csv` / `harden-*-previous-values.csv` list every old value.

**Any Windows box:** quarantined files from `audit.ps1` are in `C:\ProgramData\CCDC\quarantine-<time>\` (put back with `Move-Item` if one was legitimate).

## Network devices
- **Palo Alto:** Device → Setup → Operations → *Load named configuration snapshot* → `orig-<date>` (or `ccdc-before-policy-<time>`) → Commit.
  Snapshot deleted from the firewall? *Import named configuration snapshot* → the exported XML (workstation, or fetched from the vault) → load → commit.
  Then re-run `python3 palo-alto/pa_policy.py apply` if the restored config predates the policy, and change the admin passwords again.
- **VyOS:** `configure`, `load /config/ccdc-before-fw-<time>.boot` (or `/config/ccdc-orig.boot`), `compare`, `commit-confirm 5`, test, `confirm`, `save`.
  Files gone? Re-type from the paper checklist / `ccdc-start-commands.txt` notes; `bash vyos/vyos_fw.sh --apply` rebuilds the firewall.

## After every restore
- [ ] Passwords again where the restore brought old ones back (Linux shadow, MySQL, Splunk, SQL) → PCRs for scored users
- [ ] Scored services tested (from Kali) and Quotient green
- [ ] Monitors re-baselined: `deploy.sh --role <role> --only webguard,fim` / `deploy.ps1 -Role <role> -Only fim`
- [ ] A fresh backup of the repaired state + push at the next vault window
- [ ] Incident report: what was damaged, from which backup (time) you restored, what was lost in between
