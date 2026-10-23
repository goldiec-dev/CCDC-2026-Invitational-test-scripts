# E-Commerce web server (+ MySQL) - incident response checklist

Order: **record → contain → clean up → check the shop → write the report.**
The incident report is worth points, so collect evidence *before* you fix anything.

## Signs of trouble on this box
- Log locations and grep one-liners for logins, sudo, new users, cron, web attacks and wiped logs: `../LINUX_CHEATSHEET.md` (part 3)
- The shop is defaced, shows a DB error, or redirects somewhere else
- webguard alerts: `journalctl -u ccdc-webguard -f`
- New or changed `.php` files, especially in upload/cache/image folders
- Processes running as the web user (`www-data`/`apache`) that aren't the web server: `ps -u www-data -u apache -o pid,cmd`
- Shop admin accounts you didn't create, products or prices changed
- `audit.sh scan` CRITICAL findings, or `ccdc-audit` alerts in Splunk
- File integrity alerts (`journalctl -u ccdc-fim`, `ccdc-fim` in Splunk): changed system files, new SSH keys, cron, PAM. Evidence and diffs are in `/root/.ccdc-fim/evidence/`
- Beacon alerts (`journalctl -u ccdc-beacon`, `ccdc-beacon` in Splunk) or `sudo bash linux/beacon.sh report`: something connecting out on a timer. `ss -tunap | grep <IP>` finds the process

## 1. Record (before changing anything) - tell the captain right away
Get a root shell first, from the `CCDC Scripts` folder: `sudo -s` (the evidence folder is root-only).
```bash
E=/root/ccdc/ir-$(date +%H%M); mkdir -p $E
date | sudo tee $E/time.txt
sudo ss -tupan > $E/connections.txt;  ps auxwwf > $E/processes.txt
who -a > $E/who.txt;  last -Fi | head -50 > $E/last.txt
sudo cp -r /var/log/apache2 /var/log/httpd $E/ 2>/dev/null
sudo cp /var/log/auth.log* /var/log/secure* $E/ 2>/dev/null
sudo bash linux/webguard.sh check | sudo tee $E/webguard-check.txt   # lists changed files, saves copies
```
- [ ] Screenshot the defaced page / error before restoring
- [ ] Find the attacker's requests in the access log:
      `sudo grep -hiE "union.*select|sleep\(|\.\./|cmd=|eval|base64_|\.php\?.*=http" /var/log/{apache2,httpd}/*access* | tail -50`
      Also look up the webshell's file name: `sudo grep -h "<shell>.php" /var/log/{apache2,httpd}/*access*` (that gives the attacker IP and time)
- [ ] DB tampering: `sudo mysqldump --all-databases > $E/db-now.sql`, then compare the tables you care about with `/root/db-orig.sql`

## 2. Contain (the shop must stay up)
- [ ] **Webshell running?** Kill its processes (`ps -u www-data -u apache`): `sudo cp /proc/<PID>/exe $E/pid<PID>.bin; sudo kill -9 <PID>`
- [ ] **Attacker logged in?** `who` → `sudo pkill -KILL -t pts/<N>`, then `sudo passwd <user>`
- [ ] **New shop admin?** Disable it in the shop's admin panel (screenshot first), then change every admin password
- [ ] **DB credentials stolen** (webshells can read the config): change them again, back to back:
      `sudo bash linux/audit.sh mysql`, then `sudo bash ./deploy.sh --role ecom --only database`
- [ ] **Block the attacker's IP** on the Palo Alto, or here: `sudo iptables -I INPUT -s <IP> -j DROP`. **Never block the scoring engine.**

## 3. Clean up
- [ ] Put the site back: `sudo bash linux/webguard.sh restore`
      (changed files → baseline copy, new files → quarantine; copies in `/root/.webguard/*/evidence`)
- [ ] `sudo CCDC_ROLE=ecom bash linux/audit.sh scan --fix`: other webshells, cron, SSH keys, users
- [ ] Find how they got in: an upload folder that runs PHP, a vulnerable plugin, a reused password. Fix that, or note it in the report if you can't.
- [ ] Changed products/prices/admins: fix them in the shop admin panel. Only restore tables from `/root/db-orig.sql` if you have to, and only the affected table.
- [ ] Any Linux account the attacker used → all passwords again: `sudo bash linux/audit.sh passwords`

- [ ] Once a file is back to its good state, fim stops alerting on it by itself. If the good state is a NEW version (you changed passwords again), record it: `sudo bash linux/fim.sh accept <file>`

## 3b. Recover from a backup (when cleaning up isn't enough)
Full procedure and the vault: `../BACKUP_AND_RECOVERY.md`. Record evidence (step 1) **before** restoring.
- [ ] Backups on this box: `sudo bash linux/backup.sh list` (gone or checksum fails → vault: `vault.sh serve <file>`, here `sudo bash linux/offbox.sh fetch <file>`)
- [ ] **Defaced / deleted site files:** `sudo bash linux/backup.sh restore-web latest /var/www/html` - shows the differences, saves the current state, asks.
      Then load the page from Kali and `sudo bash ./deploy.sh --role ecom --only webguard` (new baseline).
- [ ] **Shop database damaged** (products gone, admin users added): `sudo bash linux/backup.sh restore-db latest` → MySQL passwords are back to
      backup-time values → `sudo bash ./deploy.sh --role ecom --only database` straight away, reload the shop.
      Only the shop's tables wrong? Restore just that database by hand from `mysql-all.sql.gz` instead (ask the captain).
- [ ] **Apache / PHP config changed:** `sudo bash linux/backup.sh restore-file latest /etc/httpd/conf.d/<file>` → `sudo apachectl -t && sudo systemctl reload httpd`
- [ ] SELinux labels after a restore: `sudo restorecon -Rv /var/www` (restore-web does this itself)
- [ ] Afterwards: fresh backup + push at the next vault window; note the backup time used in the report

## 4. Check the shop works
- [ ] Home page, a product page and the admin login all load from another machine
- [ ] `sudo bash linux/webguard.sh check` is clean
- [ ] If you changed site files on purpose, re-baseline: `sudo bash ./deploy.sh --role ecom --only webguard`

## 5. Write the incident report (`Blank Inject Template.docx`)
Include: time detected and contained · box and IP · attacker IP(s) · what they did (access log lines, the webshell path and contents, the changed pages) · how you found it · actions in order · current status · how you closed the way in.
Attach evidence from `$E`, `/root/.ccdc-fim/evidence/` and `/root/.webguard/*/evidence` (it has a diff of every changed file).
