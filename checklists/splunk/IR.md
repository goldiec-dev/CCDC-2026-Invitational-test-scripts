# Splunk - incident response checklist

Two jobs: **(A) use Splunk to investigate attacks on other boxes**, and **(B) respond when the Splunk box itself is attacked.**

## A. Investigating with Splunk
Start broad, then narrow down to one IP or one account. Use the time picker to stay around the incident time.

| Looking for | Search |
|---|---|
| Our own audit-script alerts | `index=* ("ccdc-audit" OR "CCDC-Audit")` |
| Beacon alerts from our scripts | `index=* ("ccdc-beacon" OR "CCDC-Beacon") \| table _time host _raw` |
| File integrity alerts (all boxes) | `index=* ("ccdc-fim" OR "CCDC-FIM") \| table _time host _raw` |
| SSH logins, success and failure | `index=* ("Accepted password" OR "Accepted publickey" OR "Failed password") \| stats count by host, src, user` |
| sudo use | `index=* "sudo:" "COMMAND=" \| table _time host user _raw` |
| New Linux users / password changes | `index=* ("useradd" OR "new user" OR "password changed")` |
| Windows failed / successful logons | `index=* (EventCode=4625 OR EventCode=4624) \| stats count by host, Account_Name, Source_Network_Address, Logon_Type` |
| Windows new user / added to group | `index=* (EventCode=4720 OR EventCode=4732 OR EventCode=4728)` |
| Windows new service / task | `index=* (EventCode=7045 OR EventCode=4698)` |
| Windows log cleared | `index=* (EventCode=1102 OR EventCode=104)` |
| PowerShell commands run | `index=* EventCode=4104 \| table _time host ScriptBlockText` |
| Web attacks | `index=* (sourcetype=access_combined OR sourcetype=iis) ("union" OR "select" OR "cmd=" OR "../" OR ".php?")` |
| One attacker IP everywhere | `index=* "<IP>" \| stats count by host, sourcetype` |
| A box that stopped sending logs | `\| metadata type=hosts index=* \| eval mins=round((now()-lastTime)/60) \| where mins>10` |

**Beaconing across the whole network** (Palo Alto traffic logs; field names depend on the Palo Alto
add-on - if `src_ip`/`dest_ip` are empty, check the field list on one event and rename). Untested -
try it in practice. Low `jitter` + many `conns` = something calling home on a timer:
```
index=* sourcetype=pan:traffic earliest=-2h
| bin _time span=5s | stats count by _time src_ip dest_ip dest_port
| sort 0 src_ip dest_ip dest_port _time
| streamstats current=f last(_time) as prev by src_ip dest_ip dest_port
| eval gap=_time-prev | where gap>=10
| stats count as conns median(gap) as every stdev(gap) as sd by src_ip dest_ip dest_port
| eval jitter=round(sd/every,2) | where conns>=8 AND jitter<0.25 | sort jitter
```
Ignore the scoring engine, Splunk forwarding (9997) and NTP/DNS; everything else is worth a look.

- [ ] When you find it: screenshot the search and its results (time range visible), and note the host, IP, account and time. **That's report evidence.**
- [ ] Tell whoever is on that box, and point them at that box's IR checklist
- [ ] A box going quiet in Splunk is itself a sign: the forwarder may have been stopped or the logs cleared

## B. When the Splunk box is attacked

### Signs
- Log locations and grep one-liners for logins, sudo, new users, cron, web attacks and wiped logs: `../LINUX_CHEATSHEET.md` (part 3)
- Web UI login fails with the current admin password, or there are Splunk users you didn't create
- Forwarders stop reporting all at once (`splunkd` killed, 9997 blocked, receiving disabled)
- New apps, scripted inputs or alert actions (`/opt/splunk/etc/apps/*/bin/`)
- Indexes deleted or emptied; Linux signs as on any box (logins, `audit.sh scan` CRITICAL)

### 1. Record - tell the captain
Get a root shell first, from the `CCDC Scripts` folder: `sudo -s` (the evidence folder is root-only).
```bash
E=/root/ccdc/ir-$(date +%H%M); mkdir -p $E
sudo ss -tupan > $E/connections.txt;  ps auxwwf > $E/processes.txt;  last -Fi | head -50 > $E/last.txt
sudo cp /var/log/secure* /var/log/auth.log* $E/ 2>/dev/null
sudo cp /opt/splunk/var/log/splunk/audit.log* /opt/splunk/var/log/splunk/splunkd.log $E/
sudo find /opt/splunk/etc -newer /opt/splunk/etc/splunk.version -type f > $E/changed-config.txt
```
- Splunk's own audit trail: `index=_audit action=* (user!=splunk-system-user) | table _time user action info`

### 2. Contain
- [ ] Change the Splunk admin password: `sudo /opt/splunk/bin/splunk edit user admin -password '<new>' -auth admin:'<current>'`
      (Locked out? Ask the captain before the `user-seed.conf` reset: it means a Splunk restart.)
- [ ] Delete Splunk users you didn't create (Settings → Users), after a screenshot
- [ ] Linux side: kill attacker sessions, `sudo bash linux/audit.sh passwords`, block their IP on the Palo Alto (**never the scoring engine**)

### 3. Clean up
- [ ] Disable unknown scripted inputs, alert actions or apps (Apps → Manage apps → Disable). Copy the app folder to `$E` first.
- [ ] `sudo CCDC_ROLE=splunk bash linux/audit.sh scan --fix`
- [ ] Receiving still on 9997? Settings → Forwarding and receiving. Firewall back to normal: `sudo bash linux/fw.sh --role splunk --level medium`

### 3b. Recover from a backup
Full procedure: `../BACKUP_AND_RECOVERY.md`. This box is also the **vault** - its own backup is on `BACKUP_VAULT_ALT` (E-com):
fetch with `sudo bash linux/offbox.sh fetch <file>` while the E-com person runs `vault.sh serve <file>` there.
- [ ] **Splunk apps / users / inputs tampered:** `sudo bash linux/backup.sh restore-file latest /opt/splunk/etc/apps/<app>` (or `/opt/splunk/etc/passwd`,
      `/opt/splunk/etc/system/local`) → restart Splunk (both checks down 1-2 min) → restoring `etc/passwd` brings back old Splunk passwords: change them and PCR
- [ ] **OS config:** `sudo bash linux/backup.sh restore-file latest /etc/<path>`
- [ ] **The vault store itself** (`/root/ccdc-vault`) deleted: every box still has its on-box copy and its local encrypted copy in `/root/ccdc/offbox/` - ask each box to push again at the next window
- [ ] Indexed data can't be restored from these backups (too big) - that's why we never delete it

### 4. Check
- [ ] `index=* earliest=-5m | stats count by host`: every box is reporting again

### 5. Incident report (`Blank Inject Template.docx`)
Time detected and contained · box and IP · attacker IP · what they changed (`_audit` results, changed-config list) · actions taken · status · prevention. Splunk screenshots make good evidence for **every** box's reports.
