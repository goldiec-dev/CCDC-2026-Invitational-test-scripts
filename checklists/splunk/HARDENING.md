# Debian 12 Splunk 10.0.2 server - hardening checklist

| | |
|---|---|
| Address | `172.20.240.20`, public `172.25.(20+N).20` |
| OS / software | Debian 12, Splunk Enterprise 10.0.2 in `/opt/splunk` |
| Default login | `sysadmin` for the OS (paper only: ________ ); Splunk's own `admin` (paper only: ________ ) |
| **Scored** | **Splunk Query** (logs in to Splunk and runs a search for specific data), **Splunk Management** (8089 open and authenticating); SSH (while `SSH_SCORED=yes`); ping |
| Script role | `splunk` |
| Ports | 8000 web (scored query may use it), 8089 management (scored), 9997 forwarders, 514 syslog, 8191 KV store (local only) |

Work from the VM console. Assume every password (Linux AND Splunk's own users) is already known to the red team.
Splunk is also how the team sees attacks on every other box - keep it receiving. Incident response: `IR.md`.

`S=/opt/splunk/bin/splunk` in the commands below (run them with `sudo -u $(stat -c %U /opt/splunk) ...` or `sudo`).

---

## 0. Before touching anything (5 min)
- [ ] `tmux new -s ccdc`
- [ ] Save what the box looks like now:
      ```bash
      sudo mkdir -p /root/start && cd /root/start
      sudo bash -c 'ss -tulpn > ss.txt; ps auxwwf > ps.txt; getent passwd > passwd.txt
        systemctl list-units --type=service --state=running > services.txt; last -Fi > last.txt'
      ps -o user= -C splunkd | sort -u       # Splunk runs as: ________ (root = note it, don't change it now)
      ```
- [ ] **Prove both scored checks work now:**
      ```bash
      curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/          # 200 or 303
      curl -sk -u admin:'<current password>' https://127.0.0.1:8089/services/server/info | grep -m1 version
      curl -sk -u admin:'<current password>' https://127.0.0.1:8089/services/search/jobs/export \
           -d search='search index=* earliest=-15m | stats count by host' -d output_mode=csv
      ```
- [ ] Web UI (Ubuntu workstation browser `http://172.20.240.20:8000`): search `index=* earliest=-15m | stats count by host, index`.
      Indexes / sourcetypes the scored query probably looks for: ____________ (**never delete them**)
- [ ] **Backups:** the deploy's first step, `backup` (section 1), saves everything as it is now - /etc, the web root,
      every database, mail, Splunk config, keys, cron, plus a state snapshot - to `/root/ccdc/full-backup-<time>/`.
      Answer **y**. It's the undo button for the rest of the competition (`../BACKUP_AND_RECOVERY.md`).
      Splunk's config (`/opt/splunk/etc`) is in it; indexed data isn't (too big - never delete it instead).

## 1. Passwords - first 5 minutes
- [ ] Scripts (`../GETTING_SCRIPTS.md`), team number in `ccdc.conf`, `CONFIG_REVIEWED=yes`.
- [ ] Debian 12 has no iptables: `sudo apt-get install -y iptables iptables-persistent` (answer the save prompts "yes").
- [ ] `cd ~/ccdc-main && sudo bash ./deploy.sh --role splunk --skip fim`
- [ ] `passwords` step: OS accounts. Scored users printed → captain → PCR.
- [ ] **Splunk's own users (no script does these)** - the scorer logs in to Splunk, so **every change to the account it
      uses goes in a PCR immediately**. Unknown which? Assume `admin` plus every non-default user, PCR them all:
      ```bash
      sudo $S list user -auth admin:'<old>'                                  # write the list down
      sudo $S edit user admin -password '<new>' -auth admin:'<old>'          # → PCR  admin,<new>
      sudo $S edit user <user> -password '<new>' -auth admin:'<new>'         # each user → PCR
      ```
      Users you don't recognise: note their roles, ask the captain, then `sudo $S remove user <name> -auth admin:'<new>'`
      - **never** remove a user the scorer might use.

## 2. The rest of the deploy steps
| Step | What to do |
|---|---|
| firewall | 8000 and 8089 open to everyone (scored), 9997/514 from the LAN, 22 while `SSH_SCORED=yes`. Within 90 s: web UI from another box, the 8089 `curl` above with the new password, forwarders still arriving; then `yes`. |
| secure | Account lockout **off** (the red team could lock the scorer's account by failing logins), stronger password rules, 60-minute sessions. Asks to restart Splunk (both checks down 1-2 min) - answer `n` during busy scoring and restart later. Undoes itself if Splunk doesn't come back. SSH hardening. |
| cis | CIS Level 1 baseline not covered elsewhere: kernel/network parameters, unused modules, `/dev/shm`, core dumps, file permissions, cron, banners, sudo/su, auditd. Asks per section; anything that could hurt scoring is report-only (`../CIS.md`). |
| scan | `splunkd` on 8000/8089/8191/9997 is expected. |
| services | Legacy services off after asking. |
| forwarder | Skipped (this is the server). |
| beacon | Outbound-connection watcher (forwarders connecting **in** are not flagged). |

## 3. Manual hardening
### 3.1 Splunk users, roles and authentication
- [ ] Roles with dangerous capabilities - who has them:
      Settings → Roles: `admin_all_objects`, `edit_user`, `edit_roles`, `change_authentication`, `can_delete`,
      `edit_scripted`, `rest_apps_management`, `run_script_*`. Only the admin role (and the team) should.
      `can_delete` lets a user erase evidence - remove it from every role that isn't yours.
- [ ] Authentication method: `sudo grep -A3 '^\[authentication\]' /opt/splunk/etc/system/local/authentication.conf` -
      `authType = Splunk` expected. LDAP/SAML pointing somewhere unknown = incident.
- [ ] Lockout is off after `secure` (and the restart): `sudo grep -A8 'splunk_auth' /opt/splunk/etc/system/local/authentication.conf | grep lockout`
- [ ] Remote logins on 8089 stay allowed (the management check authenticates): don't set `allowRemoteLogin = never`.

### 3.2 Ways into Splunk that run code (persistence spots)
- [ ] Apps you didn't expect: Apps → Manage Apps, or `ls -lt /opt/splunk/etc/apps/ | head -20` (newest first).
      Default ones: `search`, `launcher`, `learned`, `SplunkForwarder`, `splunk_*`, `alert_*`, `introspection*`... A
      recently modified app with a `bin/` folder = look inside.
- [ ] Scripted inputs: `sudo grep -rn '^\[script://' /opt/splunk/etc/apps/*/local/inputs.conf /opt/splunk/etc/apps/*/default/inputs.conf /opt/splunk/etc/system/local/inputs.conf 2>/dev/null`
      - for each enabled one, read the script. Disable an unknown one: set `disabled = 1` in that app's `local/inputs.conf`.
- [ ] Alert actions that run scripts: Settings → Searches, reports, and alerts → look for actions "Run a script" /
      unknown custom actions; `sudo grep -rn 'action.script' /opt/splunk/etc/apps/*/local/savedsearches.conf /opt/splunk/etc/users 2>/dev/null`
- [ ] **Deployment server** (pushes apps - code - to every forwarder): `sudo find /opt/splunk/etc -name serverclass.conf -o -name deploymentclient.conf`
      - a `serverclass.conf` we didn't create means this server can push code to all our boxes: read it.
      - a `deploymentclient.conf` means this server takes apps from someone else: check `targetUri`.
- [ ] HTTP Event Collector (port 8088, lets anyone with a token inject events): Settings → Data inputs → HTTP Event
      Collector → Global Settings. Not used by us → **Disabled**. Tokens you don't recognise → delete.
- [ ] Other listening inputs: `sudo ss -tulpn | grep splunkd` - anything besides 8000, 8089, 8191, 9997 (and 514) = check
      Settings → Data inputs (TCP/UDP) and Forwarding and receiving.

### 3.3 Receiving logs from every box
- [ ] Receiving on 9997: Settings → Forwarding and receiving → Configure receiving → 9997 enabled.
- [ ] Every box reports: `index=* earliest=-15m | stats count by host` - missing hosts = run their `forwarder` step.
- [ ] Syslog from the Palo Alto / router on 514: `sudo ss -ulpn | grep ':514 '`. Splunk running as a non-root user
      can't listen on 514 - then let rsyslog receive it into a file and monitor that file:
      ```bash
      printf 'module(load="imudp")\ninput(type="imudp" port="514" ruleset="remote")\nruleset(name="remote"){ action(type="omfile" file="/var/log/remote.log") }\n' | sudo tee /etc/rsyslog.d/10-ccdc-remote.conf
      sudo systemctl restart rsyslog && sudo $S add monitor /var/log/remote.log -sourcetype syslog -auth admin:'<new>'
      ```
      (Debian 12 may need `sudo apt-get install -y rsyslog` first.)

### 3.4 Splunk web and management settings
- [ ] Splunk web stays plain HTTP on 8000 (the query check may use it; it can't serve both).
- [ ] 8089 is HTTPS already; leave Splunk's TLS defaults (TLS 1.2 minimum).
- [ ] Splunk version and known issues: `sudo $S version`. Exposed admin pages are the main risk - the strong
      passwords + no unknown users above are the defence.

### 3.5 Accounts, services, kernel (OS)
- [ ] Only root has UID 0: `awk -F: '$3 == 0' /etc/passwd`; login accounts `awk -F: '$7 !~ /(nologin|false)$/' /etc/passwd` vs `/root/start/passwd.txt`
- [ ] The `splunk` service user can't log in: `getent passwd splunk | cut -d: -f7` → `/usr/sbin/nologin` (or no password: `sudo passwd -S splunk` → `L`/`NP`).
- [ ] sudo: `getent group sudo`, `sudo ls -la /etc/sudoers.d/`; SSH keys: `sudo find /root /home /opt/splunk -name authorized_keys -ls`
- [ ] Unneeded services: `systemctl list-unit-files --state=enabled --type=service,socket`; `sudo systemctl disable --now avahi-daemon cups rpcbind 2>/dev/null`
- [ ] Kernel parameters, auditd (with a watch on Splunk's config and users), banners, file permissions: the deploy's
      `cis` step (`linux/cis.sh --fix`). Who changed Splunk's config: `sudo ausearch -k scored_service -ts today -i | tail`
      (Splunk changing its own files shows up too - look for auid values that aren't `splunk`).

### 3.6 Disk and data
- [ ] `df -h /opt` - over 85 %? Splunk stops indexing when the disk is nearly full. Ask before deleting anything; never
      `splunk clean`. A flood of events from one host = check that host.
- [ ] Data is evidence: never delete indexes.

### 3.7 Take the baseline and back up (last)
- [ ] `sudo bash ./deploy.sh --role splunk --only fim`
- [ ] **This box's own backup** goes to the E-com box (`BACKUP_VAULT_ALT`): `sudo bash linux/backup.sh --role splunk`, ask the
      E-com person to open a window (`vault.sh open` there), then `sudo bash linux/offbox.sh push`.

### 3.8 Vault duties (this box is `BACKUP_VAULT`)
- [ ] When the captain calls a backup round: `sudo bash linux/vault.sh open --minutes 15` → read the password and the host
      key fingerprint out → wait for "received <host>/..." lines (or Enter to close early). It closes itself in any case.
- [ ] Each upload says **OK** or **CHECKSUM MISMATCH** (→ that box pushes again). Stored: `sudo bash linux/vault.sh list`.
- [ ] Space: the store is `/root/ccdc-vault` on `/` - `df -h /` before each round; Splunk needs room too. Delete only older
      copies of a box that has newer OK ones, and ask the captain first.
- [ ] A restore: `sudo bash linux/vault.sh serve <file> --minutes 10`, the other box runs `offbox.sh fetch <file>` (`../BACKUP_AND_RECOVERY.md`).
- [ ] While a window is open, a second sshd listens on 2222 (LAN only) - expected; `fim` may alert on `/etc/shadow`
      (the `ccdc-vault` account's password) - check the alert's diff only touches that line.
- [ ] When stable: `sudo bash linux/fw.sh --role splunk --level hard` → web UI + 8089 + forwarders → `yes`.

- [ ] **Containerizing** (only if an inject asks, or to isolate a vulnerable service): `../Docker_instructions.md` -
      `sudo bash containers/ccdc-container.sh plan splunk`, then `build`, then `switch` (tested, rolls itself back).

## 4. Check the scored services (from Kali = like the scorer)
```bash
P=172.25.<20+N>.20
curl -s -o /dev/null -w '%{http_code}\n' http://$P:8000/                                 # 200 / 303
curl -sk -u admin:'<new>' https://$P:8089/services/server/info -o /dev/null -w '%{http_code}\n'   # 200
curl -sk -u admin:'<new>' https://$P:8089/services/search/jobs/export -d search='search index=* earliest=-5m | head 1' -d output_mode=csv
ping -c2 $P
```
Quotient: Splunk query, Splunk management, SSH, ping up.

## 5. Every 30 minutes - Splunk is your watchtower
- [ ] Searches to keep open:
  - `index=* ("ccdc-audit" OR "CCDC-Audit") earliest=-30m` - critical findings from our audit scripts
  - `index=* ("ccdc-fim" OR "CCDC-FIM") earliest=-30m` - changed system files on any box
  - `index=* ("ccdc-beacon" OR "CCDC-Beacon" OR "ccdc-outbound-ssh") earliest=-30m` - call-home / pivoting
  - `index=* (webguard OR WebGuard) earliest=-30m` - defacement
  - `index=* sourcetype=linux_secure ("Failed password" OR "Accepted") earliest=-30m | stats count by host, src` - SSH logins
  - `index=* (EventCode=4625 OR EventCode=4720 OR EventCode=4728 OR EventCode=4732 OR EventCode=4756) earliest=-30m` - Windows failed logons, new users, group adds
  - `index=* earliest=-15m | stats count by host` - a host that went quiet may have had its forwarder killed
- [ ] Splunk audit trail (who logged in to Splunk, who changed what): `index=_audit action=login* earliest=-30m | stats count by user, info, src`
- [ ] Users unchanged: `sudo $S list user -auth admin:'<new>'` vs your list; apps unchanged: `ls -lt /opt/splunk/etc/apps | head`

## Things that lose points - don't
- Don't stop splunkd or change its ports (8000/8089 scored; every forwarder points at 9997)
- Don't restrict 8000/8089 to inside addresses, don't set `allowRemoteLogin = never`, don't turn on Splunk web SSL
- Don't change a Splunk password the scorer uses without a PCR; don't delete users the scorer might use
- Don't delete indexes or data, don't run `splunk clean`
- Don't restart Splunk during busy scoring without telling the captain (both checks go down)
