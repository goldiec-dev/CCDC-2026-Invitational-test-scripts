# Ubuntu DNS (BIND) - incident response checklist

> **Not in the 2026 invitational topology** (no such VM in the team pack) - kept for older topologies.

Use this when something looks wrong on the DNS box. Order: **record → contain → clean up → check DNS → write the report.**
The incident report is worth points, so collect evidence *before* you fix anything.

## Signs of trouble on this box
- Log locations and grep one-liners for logins, sudo, new users, cron, web attacks and wiped logs: `../LINUX_CHEATSHEET.md` (part 3)
- `dig @<this box> <scored name>` returns a different IP, or nothing
- `named` isn't running, or something else is listening on 53 (`ss -tulpn | grep :53`)
- Zones, `include` lines or `allow-transfer`/`allow-recursion` you didn't put there
- Logins you don't recognise (`last -Fi`, `/var/log/auth.log`), new users, new SSH keys
- `audit.sh scan` reports CRITICAL findings, or Splunk shows `ccdc-audit` alerts from this box
- File integrity alerts (`journalctl -u ccdc-fim`, `ccdc-fim` in Splunk): changed system files, new SSH keys, cron, PAM. Evidence and diffs are in `/root/.ccdc-fim/evidence/`
- Beacon alerts (`journalctl -u ccdc-beacon`, `ccdc-beacon` in Splunk) or `sudo bash linux/beacon.sh report`: something connecting out on a timer. `ss -tunap | grep <IP>` finds the process

## 1. Record (before changing anything) - tell the captain right away
Get a root shell first, from the `CCDC Scripts` folder: `sudo -s` (the evidence folder is root-only).
```bash
E=/root/ccdc/ir-$(date +%H%M); mkdir -p $E
date | sudo tee $E/time.txt
sudo ss -tupan > $E/connections.txt;  ps auxwwf > $E/processes.txt
who -a > $E/who.txt;  last -Fi | head -50 > $E/last.txt
sudo cp /var/log/auth.log* /var/log/syslog $E/ 2>/dev/null
sudo journalctl -u named --since -2h > $E/named.log
sudo cp -a /etc/bind $E/bind-now                  # the changed config, for the diff
sudo diff -r /root/bind-orig /etc/bind > $E/bind.diff
```
- [ ] Write down: time noticed, what you saw, the attacker's IP (from `connections.txt`, `last`, or the logs)
- [ ] Screenshot anything you show in the report (wrong dig answer, the diff)

## 2. Contain (without breaking DNS)
- [ ] **Attacker logged in?** `who` → `sudo pkill -KILL -t pts/<N>`. Then change that account's password: `sudo passwd <user>`. If it's a scored user, give the new password to the captain.
- [ ] **Bad process?** Save it first, then stop it:
      `sudo ls -l /proc/<PID>/exe; sudo cp /proc/<PID>/exe $E/pid<PID>.bin; sudo cat /proc/<PID>/cmdline | tr '\0' ' ' > $E/pid<PID>.cmd; sudo kill -9 <PID>`
- [ ] **Block the attacker's IP**: best done on the Palo Alto (see its IR checklist). On this box only: `sudo iptables -I INPUT -s <IP> -j DROP`.
      **Check it isn't the scoring engine's IP first** (team packet). Blocking the scorer = zero points.
- [ ] Change **all** passwords again if any account was used: `sudo bash linux/audit.sh passwords`

## 3. Clean up
- [ ] `sudo CCDC_ROLE=dns bash linux/audit.sh scan --fix`: removes cron/systemd/SSH-key/sudoers persistence; files go to `/root/ccdc/quarantine-*`
- [ ] Restore changed DNS config from your backup. Copy single files, don't overwrite the whole folder blindly:
      `sudo cp /root/bind-orig/<file> /etc/bind/<file>`
- [ ] If a zone file changed: restore it **and raise its serial number**, then
      `sudo named-checkconf && sudo named-checkzone <zone> <file> && sudo rndc reload`
- [ ] If the firewall was changed: rerun `sudo bash linux/fw.sh --role dns --level medium` (previous rules are saved in `/var/tmp/fw-backup-*.v4`)

- [ ] Once a file is back to its good state, fim stops alerting on it by itself. If the good state is a NEW version (you changed passwords again), record it: `sudo bash linux/fim.sh accept <file>`

## 4. Check DNS works
- [ ] `dig @<this box> <every scored name>` from **another** machine; answers match what you saved at the start
- [ ] `sudo rndc status` shows the server is up; `ss -tulpn | grep :53` shows only `named`

## 5. Write the incident report (`Blank Inject Template.docx`)
Include: time detected and time contained · box name and IP · attacker IP(s) · what they did (with log lines) · how you found it · what you did, in order · current status · what stops it happening again.
Attach the files from `$E` and `/root/.ccdc-fim/evidence/` that prove it (the diff, the log lines, `connections.txt`).
