# CCDC 2027 scripts

Set up for the 2026 MWCCDC Invitational topology (10 VMs, one LAN `172.20.240.0/24` behind the Palo Alto) -
check this year's team packet first. Default login on every server/workstation is `sysadmin`; Palo Alto `admin`;
VyOS `vyos` (passwords in the packet - never in this repo).

| VM | IP | Public | Run |
|---|---|---|---|
| Rocky Linux 9 E-com (+ its database) | 172.20.240.10 | .10 | `sudo ./deploy.sh --role ecom` |
| Ubuntu 22.04 Email | 172.20.240.15 | .15 | `sudo ./deploy.sh --role mail` |
| Debian 12 Splunk 10.0.2 | 172.20.240.20 | .20 | `sudo ./deploy.sh --role splunk` |
| Ubuntu workstation | DHCP | - | `sudo ./deploy.sh --role workstation` |
| Server 2022 AD/DNS | 172.20.240.100 | .100 | `.\deploy.ps1 -Role dc` |
| Server 2019 MSSQL | 172.20.240.120 | .120 | `.\deploy.ps1 -Role mssql` |
| Windows 11 workstation | DHCP | - | `.\deploy.ps1 -Role workstation` |
| Kali workstation (behind VyOS only) | 172.17.0.2 | - | `sudo ./deploy.sh --role workstation` |
| Palo Alto 11.0.2 | mgmt 172.20.240.200, inside .254, outside 172.16.0.1 | - | `python3 palo-alto/pa_policy.py apply` |
| VyOS 1.4.0 router | internal 172.16.0.254, wkst 172.17.0.1, external 172.31.(20+N).2 | - | `bash vyos/vyos_fw.sh --apply` on its console |

**Perimeter:** the Palo Alto protects every server, so `palo-alto/pa_policy.py` makes it an allow-list:
only the scored services in (`PA_INBOUND` in `ccdc.conf`), only DNS/NTP/web (+ SMTP from Email) out,
everything else dropped and logged, with automatic rollback unless you confirm. The router and Kali are
outside the Palo Alto: `vyos/vyos_fw.sh` firewalls the router itself and Kali's segment. Traffic between
LAN hosts never crosses the Palo Alto - that's what the host firewalls (`deploy.sh` / `deploy.ps1`) are for.

Every box is managed from its **VM console** - no SSH between our machines. `SSH_SCORED` in `ccdc.conf`
only controls SSH as a scored service (host firewalls, Palo Alto, `secure.sh`).

Public addresses are 172.25.(20 + team number).x. **Scored (2026 pack):** HTTP, HTTPS, SMTP, POP3/IMAP/webmail
(AD usernames), DNS, SSH, ping, Splunk query + management (8089), MSSQL SMB / RDP / 1433, AD WinRM - Quotient
(`quotient.ccdc.events`) shows the exact list. **Competition rules to remember:** keep ICMP up on every device,
router and firewall included; scored-account password changes go in Quotient's **PCR tab** as CSV
`username,password` (applied immediately); inject answers are **PDF** (`injects/README.md`); no USB or other
media (`checklists/GETTING_SCRIPTS.md`); **no VM scrubs or snapshots** - the only reset is a whole new lab
reservation - so break nothing you can't undo; public services must stay open to every source IP.

## Linux boxes - start here
1. Get the scripts (`checklists/GETTING_SCRIPTS.md`), fill in `ccdc.conf` (team number in `EXTERNAL`,
   scored users, firewall level) and set `CONFIG_REVIEWED=yes`.
2. On each box: `sudo ./deploy.sh --role <ecom|mail|splunk|workstation>` (`dns`, `mysql`: older topologies)

`deploy.sh` runs these in order, asking before each one:

| Step | What it does | Script |
|---|---|---|
| backup | Full backup of the box as it is now: /etc, web roots, databases, mail, Splunk config, keys, cron, state snapshot | `linux/backup.sh` |
| passwords | Change **every** password now, apply password policy | `linux/audit.sh passwords` |
| database | DB on this box (2026 E-com): change every MySQL password, then put the new one in the app config | `audit.sh mysql` + `audit.sh app-password` |
| firewall | iptables for the role (scored ports open to everyone, SSH only while `SSH_SCORED=yes`), auto-rollback if you don't confirm in 90 s | `linux/fw.sh` |
| secure | Scored services hardened, each tested and undone if its test fails: HTTP -> HTTPS redirect, SSH, mail TLS (plaintext kept), FTP, Splunk (no lockout) | `linux/secure.sh` |
| cis | CIS Benchmark Level 1 controls not covered elsewhere (modules, sysctl, permissions, banners, auditd, sudo/su...), asks per section | `linux/cis.sh --fix` |
| scan | Backdoor/persistence hunt, asks before each fix | `audit.sh scan --fix` |
| services | Legacy services (telnet, rsh, tftp, FTP, SNMP...) disabled after asking; end-of-life software; pending updates for important services | `linux/services.sh --fix` |
| forwarder | Splunk Universal Forwarder 10.0.2 → `SPLUNK:9997` (auth, syslog/journal, audit, web, mail logs); random local admin password | `linux/forwarder.sh` |
| webguard | Baseline the website (after the scan cleaned it) and watch for defacement | `linux/webguard.sh` |
| beacon | Watch outbound connections for anything calling home on a timer | `linux/beacon.sh` |
| fim | Baseline `/etc`, system binaries, PAM, systemd, cron, SSH keys and watch them for changes | `linux/fim.sh` |

Re-run one step: `sudo ./deploy.sh --role ecom --only database`. Skip some: `--skip scan,webguard`.
The shop is down between the MySQL password change and the config update - the `database` step does both back to back.

Everything it writes (new passwords, logs, backups, quarantined files) is in `/root/ccdc/`, root-only.

**Backups off the box:** the vault (`BACKUP_VAULT`, the Splunk box) opens a short upload window with
`linux/vault.sh open` (its own SFTP-only SSH server on port 2222, LAN only, one-time password - closed again
automatically); every box sends its backup encrypted with the team passphrase: `linux/offbox.sh push` /
`windows\offbox.ps1 push`. Restoring: `checklists/BACKUP_AND_RECOVERY.md` and each box's `IR.md`.
Submit scored users' new passwords (Quotient PCR) as soon as the passwords step prints them.

**File integrity monitors** (`fim`) run on every box once deployed. When you change a watched file on
purpose later (rotate passwords again, edit a config), tell it, or it keeps alerting:
`sudo linux/fim.sh accept /etc/shadow` / `.\windows\fim.ps1 accept -Path <file>`.

## Windows machines - start here
Same `ccdc.conf` (also set `WIN_WEBROOT` / `WIN_EXPECTED_ADMINS`). Get the folder (plus the Splunk
forwarder `.msi` if available), then in an **Administrator** PowerShell:
```powershell
powershell -ExecutionPolicy Bypass -File .\deploy.ps1 -Role <dc|mssql|workstation>      # web, ftp: older topologies
```
On the domain controller (`-Role dc`) the passwords step runs `windows\ad_passwords.ps1`: every **domain**
account password, domain password policy, risky account flags, privileged groups (and optionally krbtgt).
POP3/IMAP/webmail are scored with AD usernames - submit those users' new passwords. WinRM on the DC is scored:
nothing here turns it off, and `harden` allows 5985/5986 before turning the firewall on.
On MSSQL, `harden` allows SMB/RDP/SQL ports first; SQL Server logins (`sa`...) are changed by hand (`checklists/mssql/`).
Steps: passwords → harden → secure (dc: DNS, WinRM; mssql: SMB, RDP, SQL Server) → cis (CIS Level 1 controls) → forwarder (Splunk) → audit → services (legacy + updates) → webguard (web only) → beacon → fim (file integrity). Same `-Only` / `-Skip`
as `deploy.sh`, e.g. `-Only audit`. Output goes to `C:\ProgramData\CCDC\` (Administrators only).
**Not tested on Windows yet** - do a practice run first.

## Per-machine checklists (`checklists/`)
One folder per machine. Print the box's `HARDENING.md` for the first hour; use its `IR.md`
when something looks wrong (record evidence → contain → clean up → check scored services → report).

| Machine | Folder |
|---|---|
| **Start here: who does what, default accounts, minute-by-minute** | `checklists/FIRST_15_MINUTES.md` |
| Rocky 9 E-com (database on the same box) | `checklists/ecomm/` |
| Ubuntu 22.04 Email | `checklists/email/` |
| Debian 12 Splunk | `checklists/splunk/` |
| Ubuntu workstation | `checklists/ubuntu-workstation/` |
| Kali workstation (outside the Palo Alto; also our "scorer's view" test box) | `checklists/kali/` |
| Server 2022 AD / DNS | `checklists/ad-dns/` |
| Server 2019 MSSQL | `checklists/mssql/` (IR: `checklists/windows/IR.md`) |
| Windows 11 workstation | `checklists/windows/WIN11_WORKSTATION_HARDENING.md`, `checklists/windows/IR.md` |
| Palo Alto | `checklists/palo-alto/` |
| VyOS router | `checklists/vyos-router/` |
| Older topologies only: IIS web, FTP, Cisco FTD, Ubuntu DNS | `checklists/windows/SERVER2019_WEB_HARDENING.md`, `checklists/ftp/`, `checklists/cisco-ftd/`, `checklists/ubuntu-dns/` |

Getting scripts onto boxes: `checklists/GETTING_SCRIPTS.md`.
Linux people: `checklists/LINUX_CHEATSHEET.md` - tmux keys, where the logs are, and what to grep for.
Procedures: `checklists/STARTUP_SCRIPTS.md` (monitors at boot + integrity), `TIME_SYNC.md` (NTP/PTP),
`TRAFFIC_CAPTURE.md`, `MALWARE_REMOVAL.md`, `BACKUP_AND_RECOVERY.md` (backups, the vault, restoring every box), `CIS.md` (CIS Benchmark coverage and deliberate deviations), `Docker_instructions.md` (containerizing a service within the rules). Initial injects: `injects/initial injects/PLAYBOOK.md`
(evidence for each one: `linux/evidence.sh` / `windows/evidence.ps1`).
Optional tools: `checklists/wazuh_instructions.md` (needs a box with 4 GB RAM free) and `checklists/clamav_instructions.md`.
Login banner text for injects/hardening: `checklists/motd-banner.txt`

## Folders
| Folder | What's in it |
|---|---|
| `ccdc.conf`, `deploy.sh`, `deploy.ps1` | The one config and the two entry points |
| `linux/` | `backup.sh` (full backup + restores), `offbox.sh` / `vault.sh` (encrypted off-box copies), `cis.sh` (CIS Benchmark controls), `audit.sh` (passwords, DB passwords, backdoor scan), `fw.sh` (firewall), `secure.sh` (scored-service hardening), `webguard.sh` (website), `beacon.sh` (call-home detection), `outbound_ssh.sh` (pivoting), `services.sh` (legacy services + updates), `portscan.sh` (network port scan of our hosts), `privesc.sh` (privilege escalation + reverse shells), `forwarder.sh` (Splunk forwarder), `fim.sh` (system file integrity), `evidence.sh` (inject evidence) - see `linux/README.md` |
| `windows/` | `passwords.ps1`, `harden.ps1`, `secure.ps1`, `cis.ps1` (CIS Benchmark controls), `offbox.ps1` (encrypted off-box copies), `audit.ps1`, `webguard.ps1`, `beacon.ps1`, `fim.ps1`, `evidence.ps1`, `services.ps1`, `portscan.ps1`, `ad_passwords.ps1`, `ad_audit.ps1`, `privesc.ps1`; `tools/` extra hunting scripts; `sysmon/` config - see `windows/README.md` |
| `checklists/` | Per-machine hardening and incident-response checklists |
| `palo-alto/` | `pa_policy.py` (allow-list policy from `ccdc.conf`: plan / apply / verify / block), admin-password tools (`Palt_User_mang.py`, `fdm.py` for Cisco FTD) and reference configs in `configs/` |
| `vyos/` | `vyos_fw.sh` - router + Kali firewall commands from `ccdc.conf` |
| `containers/` | `ccdc-container.sh` - build/switch/rollback containers for the Linux scored services, on their own box, within the rules (`checklists/Docker_instructions.md`) |
| `injects/` | Blank inject/incident report templates and `policies/` |
| `installers/` | Splunk Universal Forwarder 10.0.2 (deb, rpm, Windows msi), Wazuh, ClamAV, Roundcube (only copy what a box needs; `deploy.ps1` uses `installers/splunk/*.msi`). Fill it before competition day with `installers/download.sh` |
| `old/` | Replaced scripts kept for reference: per-box iptables scripts, the 2026 Hamin toolkit, old defacement scripts, Win10/2012 scripts. Don't run these. |

## Getting the scripts onto a box
No USB in the competition: push this folder to a **public** team GitHub repo and download it on each box -
`checklists/GETTING_SCRIPTS.md`. The 2026 invitational pack forbids "any external, private electronic staging
area" and requires resources to be "freely available to all other teams" (Internet Usage rule 4) and has no
repo-URL registration step - **confirm with the White Team before the event that a public repo is allowed.** `.gitignore` keeps out the team
packet (the rules forbid publishing competition details), installers and `old/`. Everything else is about 1.5 MB.
`deploy.sh` and `deploy.ps1` expect `ccdc.conf`, `linux/`, `windows/` next to them. Don't move single scripts out.
