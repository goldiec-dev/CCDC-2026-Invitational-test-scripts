# First 15 minutes - who does what

Print this. Default passwords are in the team packet - **write them in the blank column on the printout
only** (this file is in a public repo: never type the real ones here).

## Before the drop flag (all times CST; 2026 invitational: Oct 24, Nov 7, Nov 14)
Morning section: Zoom + welcome inject 7:00, briefing 7:30, **drop flag 8:00**, scoring 8:00-noon.
Afternoon section: Zoom + welcome inject 12:30, briefing 12:30-1:00, **drop flag 1:00**, scoring 1:00-5:00.
- [ ] Captain: log in to the team portal (NISE, `https://injects.ccdc.events`), answer the **Welcome inject**.
      Log in to Quotient (`https://quotient.ccdc.events`): note the scored services and find the **PCR tab**
      (password changes for scored users, CSV `username,password`, applied immediately).
- [ ] Everyone: has the printouts, knows their machine, knows the repo download command (`GETTING_SCRIPTS.md`).
- [ ] At the drop flag: log in to the stadium (`ccdc.cit.morainevalley.edu`, accounts `v<team>u1`..`u8`),
      change the stadium password when asked, **write it down**, open your VM.

## Assignments (8 people, 10 VMs)
| Person | Machines | First job | Checklist |
|---|---|---|---|
| 1 Captain | Team portal, Quotient, `ccdc.conf`, injects | Fill in `ccdc.conf` (team number, scored users), push it; submit PCRs | `../injects/README.md` |
| 2 | Palo Alto (via the Ubuntu or Windows workstation browser) + Ubuntu workstation | Palo Alto admin password | `palo-alto/`, `ubuntu-workstation/` |
| 3 | VyOS router + Kali workstation | VyOS password, then Kali's | `vyos-router/`, `kali/` |
| 4 | Rocky E-com | passwords step, then database step | `ecomm/` |
| 5 | Ubuntu Email | passwords step; find the AD bind account | `email/` |
| 6 | Splunk + logging for everyone | Splunk OS + Splunk admin passwords (scored - PCR) | `splunk/` |
| 7 | AD / DNS | `ad_passwords.ps1` (via `deploy.ps1 -Role dc`) | `ad-dns/` |
| 8 | MSSQL + Windows 11 | passwords step on each, then SQL logins | `mssql/`, `windows/` |
Whoever finishes first takes the next inject; the captain keeps the inject queue.

## Default accounts to change (from the team packet)
Change **every** password. Any account the scoring engine logs in with (Quotient shows which services, and
the welcome inject / portal says which users) goes in a PCR right away, or that service stops scoring.

| Device | Account(s) | Default password (write in) | Changed by | Done |
|---|---|---|---|---|
| VyOS router | vyos | | 3 | [ ] |
| Palo Alto | admin | | 2 | [ ] |
| Kali | sysadmin | | 3 | [ ] |
| Rocky E-com | sysadmin (+ root, all others via script), MySQL accounts, shop admin | | 4 | [ ] |
| Ubuntu Email | sysadmin (+ all via script), Roundcube DB | | 5 | [ ] |
| Splunk OS | root, sysadmin | | 6 | [ ] |
| Splunk web | admin (+ every Splunk user - scored login, PCR) | | 6 | [ ] |
| Ubuntu workstation | sysadmin | | 2 | [ ] |
| AD / DNS | administrator, sysadmin + **all domain users** (PCR for scored ones) | | 7 | [ ] |
| Server 2019 MSSQL | sysadmin, administrator, local users; SQL logins (`sa`...) - PCR for scored ones | | 8 | [ ] |
| Windows 11 | sysadmin + local users | | 8 | [ ] |
| Team portal / stadium | our own logins | | each | [ ] |

## Minute by minute
| Minute | Network devices (2, 3) | Servers (4-8) | Captain (1) |
|---|---|---|---|
| 0-5 | Change VyOS / Palo Alto admin passwords; save config backups | Download scripts; back up configs (checklist step 0); confirm the service works | `ccdc.conf` done and pushed; read new injects |
| 5-10 | `pa_policy.py plan`, then `apply` - captain watches Quotient while you confirm; then `vyos_fw.sh` on the router | `deploy.ps1` / `deploy.sh` passwords step; **send scored users' new passwords to the captain** | Submit scored-user password changes (Quotient PCR) |
| 10-15 | `pa_policy.py verify`; syslog to Splunk; screenshot the rule bases | Firewall step (test the service before confirming); scan/audit | Check Quotient: every service still up? |
| 15+ | Tighten rules one at a time | Rest of the deploy steps, then the checklist's "Check next" | Injects; assign incident reports |
| ~60 | | Backup of the hardened box (`backup.sh` / section-0 refresh) | **First backup round:** Splunk person opens the vault (`vault.sh open`), everyone runs `offbox.sh push` / `offbox.ps1 push`. Then every 1-2 hours. |

Before the first round the captain picks the **team backup passphrase** (12+ letters/digits) and writes it on everyone's
paper - never in a file or chat. Without it the off-box backups can't be opened (`BACKUP_AND_RECOVERY.md`).

## Rules to keep in mind
- Keep **ICMP** up on every device, router and firewall included
- Don't change system names, IPs, usernames or public IP assignments unless an inject says so
- **No scrubs or snapshots** in the invitational - the only reset is a whole new lab reservation. Break nothing you can't undo
- Public services stay open to **every** source IP (no allow-only-the-scorer rules); blocking one attacking IP is fine
- No contact with the red team; no scanning anything that isn't ours
- Inject answers as **PDF**, signed "Team #", never the school name
