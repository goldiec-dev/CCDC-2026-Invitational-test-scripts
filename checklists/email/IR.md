# Ubuntu 22.04 Email (Postfix / Dovecot / Roundcube) - incident response checklist

Order: **record → contain → clean up → check mail works → write the report.**
The incident report is worth points, so collect evidence *before* you fix anything.

## Signs of trouble on this box
- Log locations and grep one-liners for logins, sudo, new users, cron, web attacks and wiped logs: `../LINUX_CHEATSHEET.md` (part 3)
- Scored users can't log in (someone changed their password), or webmail shows an error or a defaced page
- `mailq | tail -1` shows a big, growing queue (the box is being used to send spam)
- `postconf -n` has forwards/BCCs you didn't add; `/etc/aliases` or `~/.forward` pipes to a command
- New `.php` files under the Roundcube folders (webguard alert, `journalctl -u ccdc-webguard`)
- Logins you don't recognise (`last -Fi`, `/var/log/auth.log`, `/var/log/mail.log`)
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
sudo cp /var/log/auth.log* /var/log/mail.log* /var/log/syslog* $E/ 2>/dev/null
sudo cp /var/log/apache2/access.log* /var/log/apache2/error.log* /var/log/nginx/*.log* $E/ 2>/dev/null
sudo postconf -n > $E/postconf.txt;  sudo doveconf -n > $E/doveconf.txt;  mailq > $E/mailq.txt
sudo diff -r /root/postfix /etc/postfix > $E/postfix.diff;  sudo diff -r /root/dovecot /etc/dovecot > $E/dovecot.diff
```
- [ ] Write down: time noticed, what you saw, the attacker's IP
- [ ] Webmail attacks: find the IP and the URL in the access log:
      `sudo grep -E "\.php\?|cmd=|eval|base64" /var/log/apache2/access.log /var/log/nginx/access.log 2>/dev/null | tail -50`

## 2. Contain (without stopping mail)
- [ ] **Attacker logged in?** `who` → `sudo pkill -KILL -t pts/<N>`, then `sudo passwd <user>` (scored user → new password to the captain)
- [ ] **Mail user's password changed by the red team** → set a new one right away and submit it. Check `/root/ccdc/passwords-*.csv` for what it should be.
- [ ] **Spam going out?** Put the queue on hold instead of deleting it (it's evidence): `sudo postsuper -h ALL`. Find the sending account in `/var/log/maillog` (`sasl_username=`) and change its password.
- [ ] **Bad process?** `sudo cp /proc/<PID>/exe $E/pid<PID>.bin`, save its cmdline, then `sudo kill -9 <PID>`. Processes owned by `apache` usually mean a webshell.
- [ ] **Block the attacker's IP** on the Palo Alto, or on this box: `sudo iptables -I INPUT -s <IP> -j DROP`. **Never block the scoring engine's IP.**

## 3. Clean up
- [ ] Webshells / defacement: `sudo bash linux/webguard.sh restore --webroot <the web root you baselined>` (changed files are saved to `/root/.webguard/*/evidence` first)
- [ ] `sudo CCDC_ROLE=mail bash linux/audit.sh scan --fix`
- [ ] Restore changed Postfix/Dovecot files from `/root/postfix` and `/root/dovecot` one file at a time, then:
      `sudo postfix check && sudo systemctl reload postfix`, `sudo doveconf -n >/dev/null && sudo systemctl reload dovecot`
- [ ] Remove bad aliases/forwards (comment them out), then `sudo newaliases`
- [ ] Held spam: once it's recorded (`mailq > $E/mailq.txt`), delete only the spam: `sudo postsuper -d <queue id>`. Release real mail with `sudo postsuper -H ALL`.
- [ ] Any account the attacker used → all passwords again: `sudo bash linux/audit.sh passwords`

- [ ] Once a file is back to its good state, fim stops alerting on it by itself. If the good state is a NEW version (you changed passwords again), record it: `sudo bash linux/fim.sh accept <file>`

## 3b. Recover from a backup
Full procedure and the vault: `../BACKUP_AND_RECOVERY.md`. Record evidence (step 1) first.
- [ ] Backups here: `sudo bash linux/backup.sh list` (gone → vault `serve` + `sudo bash linux/offbox.sh fetch <file>`)
- [ ] **Postfix / Dovecot config tampered:** `sudo bash linux/backup.sh restore-file latest /etc/postfix/main.cf` (or `/etc/postfix`,
      `/etc/dovecot`, `/etc/aliases`) → `sudo postfix check && sudo doveconf -n > /dev/null` → `sudo systemctl reload postfix dovecot`; `sudo newaliases` after aliases
- [ ] **Mail deleted from a user's mailbox** (rule 8 - pre-existing mail must survive): `sudo bash linux/backup.sh restore-file latest /var/mail/<user>`
      (or `/home/<user>/Maildir` - missing messages come back, newer ones stay) → log in as that user and check
- [ ] **Roundcube defaced / files changed:** `sudo bash linux/backup.sh restore-web latest <webroot>` → re-baseline: `sudo bash ./deploy.sh --role mail --only webguard`
- [ ] **Roundcube database:** `sudo bash linux/backup.sh restore-db latest` → `sudo bash ./deploy.sh --role mail --only database`
- [ ] Afterwards: test every mail port (step 4), fresh backup + push

## 4. Check mail works
- [ ] SMTP banner on 25, POP3/IMAP login as a scored user with the **current** password
- [ ] Webmail: log in, send and receive a message
- [ ] `mailq` isn't growing

## 5. Write the incident report (`Blank Inject Template.docx`)
Include: time detected and contained · box and IP · attacker IP(s) · what they did (log lines, the changed config, the webshell path) · how you found it · actions in order · current status · prevention.
Attach evidence from `$E`, `/root/.ccdc-fim/evidence/` and `/root/.webguard/*/evidence`.
