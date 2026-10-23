# Ubuntu 22.04 Email (Postfix / Dovecot / Roundcube) - hardening checklist

| | |
|---|---|
| Address | `172.20.240.15`, public `172.25.(20+N).15` |
| OS / software | Ubuntu 22.04, Postfix (SMTP), Dovecot (POP3/IMAP), Roundcube webmail on Apache (or nginx) |
| Default login | `sysadmin` (password in the team packet - paper only: ________ ) |
| **Scored** | **SMTP** (mail sent and received through a real account), **POP3 / IMAP / webmail** logins with **Active Directory usernames**; SSH (while `SSH_SCORED=yes`); ping |
| Script role | `mail` |
| Depends on | the DC `172.20.240.100` (AD logins) - an AD outage = mail checks down |

Work from the VM console. Assume every password on this box is already known to the red team.
Incident response: `IR.md`. Linux commands and log locations: `../LINUX_CHEATSHEET.md`.

---

## 0. Before touching anything (5 min)
- [ ] `tmux new -s ccdc` (reattach: `tmux a`).
- [ ] Save what the box looks like now:
      ```bash
      sudo mkdir -p /root/start && cd /root/start
      sudo bash -c 'ss -tulpn > ss.txt; ps auxwwf > ps.txt; getent passwd > passwd.txt; getent group > group.txt
        systemctl list-units --type=service --state=running > services.txt; postconf -n > postconf.txt
        postconf -M > master.txt; doveconf -n > doveconf.txt 2>&1; mailq > mailq.txt; last -Fi > last.txt'
      ```
- [ ] **Prove every scored service works now** (keep the output):
      ```bash
      printf 'EHLO test\r\nQUIT\r\n' | nc -w3 127.0.0.1 25     # 220 banner, then 250 lines
      printf 'QUIT\r\n'              | nc -w3 127.0.0.1 110    # +OK
      printf 'a LOGOUT\r\n'          | nc -w3 127.0.0.1 143    # * OK
      curl -sI http://127.0.0.1/ ; curl -sI http://127.0.0.1/roundcube/ ; curl -skI https://127.0.0.1/
      ```
      Webmail URL: ____________ (`/`, `/roundcube`, `/mail`?). Log in to webmail as a scored user if you know a password.
- [ ] **How do logins work?** (write it down - it decides who changes which password)
      ```bash
      doveconf -n | grep -iE 'passdb|userdb|driver|args|auth_mechanisms|disable_plaintext'
      ls /etc/dovecot/dovecot-ldap.conf.ext /etc/sssd/sssd.conf 2>/dev/null; realm list 2>/dev/null
      ```
      Users come from: [ ] AD via LDAP  [ ] AD via SSSD/realm  [ ] local Linux accounts (pam)  [ ] a passwd-file
      LDAP bind account (`dn =` / `ldap_default_bind_dn`): ____________ → tell the AD person: change it only together with this box.
- [ ] **Backups:** the deploy's first step, `backup` (section 1), saves everything as it is now - /etc, the web root,
      every database, mail, Splunk config, keys, cron, plus a state snapshot - to `/root/ccdc/full-backup-<time>/`.
      Answer **y**. It's the undo button for the rest of the competition (`../BACKUP_AND_RECOVERY.md`).
      Mail spools and Maildirs are included - rule 8: pre-existing mail must survive anything we do.

## 1. Passwords - first 5 minutes
- [ ] Get the scripts (`../GETTING_SCRIPTS.md`), team number in `ccdc.conf`, `CONFIG_REVIEWED=yes`,
      `SCORED_USERS` = the mail users (AD usernames).
- [ ] Deploy without the baseline steps:
      ```bash
      cd ~/ccdc-main && sudo bash ./deploy.sh --role mail --skip webguard,fim
      ```
- [ ] `passwords` step: every **local** account. AD users are changed on the DC (`../ad-dns/`), not here.
      Scored users printed as `username,password` → captain → Quotient PCR now.
- [ ] Users in a Dovecot **passwd-file** (if that's what section 0 found) are NOT changed by any script:
      `doveadm pw -s SHA512-CRYPT` → paste the hash into that file for each user → PCR each one.
- [ ] `database` step: only if Roundcube uses MySQL on this box (it changes every MySQL account, then the Roundcube
      config - Ubuntu keeps the DB password in `/etc/roundcube/debian-db.php`). SQLite = nothing to do.
- [ ] Roundcube has no admin accounts of its own (users are mail users) - nothing else to change there.

## 2. The rest of the deploy steps
| Step | What to do |
|---|---|
| firewall | 25, 110, 143, 80, 443 + 465/587/993/995 open to everyone, 22 while `SSH_SCORED=yes`, ping always. Within 90 s: from another box send a test mail, check POP3/IMAP, load webmail; then `yes`. |
| secure | Webmail HTTP → HTTPS redirect (tested, undoes itself); Postfix STARTTLS + TLS 1.2 minimum, no VRFY, HELO required, open relay closed, 587/465 with login if Dovecot SASL exists; Dovecot TLS on 993/995; Roundcube installer moved away; SSH hardening. **Plaintext SMTP/POP3/IMAP keep working.** |
| cis | CIS Level 1 baseline not covered elsewhere: kernel/network parameters, unused modules, `/dev/shm`, core dumps, file permissions, cron, banners, sudo/su, auditd. Asks per section; anything that could hurt scoring is report-only (`../CIS.md`). |
| scan | Webshells in Roundcube folders, `/etc/aliases` pipes, persistence. |
| services | Legacy services off after asking (never a scored port). |
| forwarder | Splunk forwarder → `172.20.240.20:9997` (auth, mail, web logs). |
| beacon | Outbound-connection watcher. |

## 3. Manual hardening (each item: change → test mail → note it)
Quick mail test after each change (run all four):
`printf 'EHLO t\r\nQUIT\r\n' | nc -w3 127.0.0.1 25; printf 'QUIT\r\n' | nc -w3 127.0.0.1 110; printf 'a LOGOUT\r\n' | nc -w3 127.0.0.1 143; curl -skI https://127.0.0.1/ | head -1`

### 3.1 Accounts and sudo
- [ ] Only root has UID 0: `awk -F: '$3 == 0' /etc/passwd`
- [ ] Accounts that can log in: `awk -F: '$7 !~ /(nologin|false)$/' /etc/passwd` vs `/root/start/passwd.txt`.
      Unknown: `sudo usermod -L -e 1 <user>` (don't delete - mail data and rule 11). **Careful:** if Dovecot uses `pam`, local mail users must stay usable.
- [ ] sudo: `getent group sudo admin`, `sudo grep -v '^#' /etc/sudoers | grep .`, `sudo ls -la /etc/sudoers.d/`
- [ ] SSH keys: `sudo find /root /home -name authorized_keys -exec ls -la {} \; -exec cat {} \;`

### 3.2 Postfix
- [ ] **Open relay?** `postconf mynetworks smtpd_relay_restrictions smtpd_recipient_restrictions`
      - `mynetworks` must not contain `0.0.0.0/0` or the whole internet; LAN/localhost is fine
      - one of the restriction lists must contain `reject_unauth_destination` or `defer_unauth_destination`
      (`secure` fixes both; check it stuck)
- [ ] **Mail copied or piped somewhere** (classic red team persistence / exfil):
      ```bash
      postconf -n | grep -iE 'always_bcc|sender_bcc_maps|recipient_bcc_maps|content_filter|transport_maps|virtual_alias_maps|smtpd_milters|header_checks'
      postconf -M | grep -E 'pipe|spawn'        # pipe services in master.cf: which command do they run?
      grep -v '^#' /etc/aliases | grep -E '\||@'; sudo find /home /root -name .forward -exec grep -H . {} \;
      ```
      Anything you didn't see in `/root/start/postconf.txt` = incident: remove it, `sudo postfix check && sudo systemctl reload postfix`, `sudo newaliases` after editing aliases.
- [ ] Queue: `mailq | tail -3` - hundreds of messages = someone is sending spam through us (find the account in `/var/log/mail.log`).
- [ ] Banner without version: `postconf smtpd_banner` → `$myhostname ESMTP` (`secure` sets it).
- [ ] Postfix only where it should listen: `postconf inet_interfaces` → `all` is normal (SMTP is scored).

### 3.3 Dovecot
- [ ] Config overview: `doveconf -n | grep -E 'protocols|ssl|disable_plaintext_auth|auth_mechanisms|login_trusted_networks'`
      - `login_trusted_networks` must NOT be `0.0.0.0/0` (it makes every client "trusted" and skips protections)
      - leave `disable_plaintext_auth` as it is (the scorer may log in without TLS)
- [ ] Log failed logins (safe; helps incident reports). Use a **separate** file - `secure` rewrites `99-ccdc.conf`:
      ```bash
      printf 'auth_verbose = yes\nauth_verbose_passwords = no\nlog_path = syslog\n' | sudo tee /etc/dovecot/conf.d/98-ccdc-logging.conf
      sudo doveconf -n > /dev/null && sudo systemctl reload dovecot
      ```
- [ ] Mailbox permissions: `sudo ls -ld /var/mail /home/*/Maildir 2>/dev/null` - not world-writable.

### 3.4 AD login path
- [ ] AD logins still work from this box: `id <scored AD user>` (SSSD) or a POP3 login test from section 4.
- [ ] Bind account file permissions: `sudo ls -l /etc/dovecot/dovecot-ldap.conf.ext /etc/sssd/sssd.conf` → `600 root`.
      Fix: `sudo chmod 600 <file>`.
- [ ] LDAP over TLS? `grep -iE 'uris|hosts|tls|ldaps' /etc/dovecot/dovecot-ldap.conf.ext /etc/sssd/sssd.conf 2>/dev/null` -
      note it; switching to LDAPS mid-competition needs a DC certificate - don't, unless you have time to test.
- [ ] After **every** AD password change on the DC: test a POP3 login here.

### 3.5 Roundcube (webmail)
- [ ] Version: `dpkg -l | grep -i roundcube` (package) or `grep -m1 "RCMAIL_VERSION" /usr/share/roundcube/program/include/iniset.php`.
      Roundcube **before 1.5.10 / 1.6.11** has a post-login remote code execution bug (CVE-2025-49113) - any user's
      password = a shell. Update just Roundcube if an update exists: `apt list --upgradable 2>/dev/null | grep -i roundcube`
      → `sudo apt-get install --only-upgrade -y roundcube roundcube-core roundcube-mysql` (back up first, test webmail after).
- [ ] Installer folder gone (`secure` moves it): `ls -d /usr/share/roundcube/installer /var/lib/roundcube/installer 2>/dev/null`
      and `grep -n enable_installer /etc/roundcube/config.inc.php` → absent or `false`.
- [ ] Plugins: `grep -n "plugins" /etc/roundcube/config.inc.php` - unknown plugin names = check `/usr/share/roundcube/plugins/<name>`.
- [ ] Config file not readable by everyone: `sudo ls -l /etc/roundcube/*.php` → `640 root:www-data`.
- [ ] Don't change `des_key` (logs everyone out, breaks stored settings) unless you know it leaked.

### 3.6 Apache (webmail)
- [ ] Ubuntu's security settings file - set and reload:
      ```bash
      sudo sed -i -E 's/^ServerTokens .*/ServerTokens Prod/; s/^ServerSignature .*/ServerSignature Off/; s/^TraceEnable .*/TraceEnable Off/' /etc/apache2/conf-available/security.conf
      sudo apache2ctl -t && sudo systemctl reload apache2 && curl -sI http://127.0.0.1/ | grep -i server
      ```
- [ ] Unknown sites / aliases: `sudo apache2ctl -S`, `ls -la /etc/apache2/sites-enabled /etc/apache2/conf-enabled`.
- [ ] PHP: `php -i | grep -E '^(expose_php|allow_url_include) '` → set in `/etc/php/*/apache2/conf.d/99-ccdc.ini`:
      `expose_php = Off`, `allow_url_include = Off`, then `sudo systemctl reload apache2`.

### 3.7 Unneeded services
- [ ] `systemctl list-unit-files --state=enabled --type=service,socket` vs `/root/start/services.txt`
- [ ] Not needed on a mail server: `sudo systemctl disable --now cups cups-browsed avahi-daemon rpcbind 2>/dev/null`
- [ ] `sudo ss -tulpn`: 25, 110, 143, 993, 995, (465, 587), 80, 443, 22 if scored; MySQL only on `127.0.0.1`.

### 3.8 CIS baseline (deploy step `cis`)
The deploy's `cis` step (`linux/cis.sh --fix`, asks per section) covers what used to be typed here by hand,
and more: kernel/network parameters, unused kernel modules, `/dev/shm` noexec, no core dumps, file permissions,
cron allow lists, login banners, sudo logging, `su` limited to an empty group, persistent journal, and auditd with
the CIS rules (plus watches on this box's scored-service files). Report any time: `sudo bash linux/cis.sh`.
Why some CIS items are skipped on purpose (no lockout, no GRUB password...): `../CIS.md`.
- [ ] `sysctl net.ipv4.icmp_echo_ignore_all` → `0` (ping is scored - `cis.sh` never turns it on)
- [ ] Who changed Postfix / Dovecot / Roundcube / aliases: `sudo ausearch -k scored_service -ts today -i | tail -30`

### 3.9 Logging
- [ ] Mail log: `/var/log/mail.log` - failed logins: `sudo grep -E 'auth failed|authentication failed' /var/log/mail.log | tail`
- [ ] In Splunk: `index=* host=<this hostname> earliest=-10m | stats count by source`

### 3.10 Updates
- [ ] Automatic updates are **on** by default in Ubuntu: `systemctl list-timers apt-daily-upgrade.timer` - they can restart
      Postfix/Dovecot at that time. Tell the captain the time; keep it on unless it breaks something.
- [ ] Exposed software only, one at a time, test after each: `apt list --upgradable 2>/dev/null | grep -E 'postfix|dovecot|roundcube|apache2|openssh|php'`
      → `sudo apt-get install --only-upgrade -y <package>`. Never a full `apt upgrade`.

### 3.11 Take the baselines and back up (last)
- [ ] Webmail loads and looks right, then: `sudo bash ./deploy.sh --role mail --only webguard,fim`
- [ ] **Backup of the hardened box, then off the box:** `sudo bash linux/backup.sh --role mail` → at the next vault
      window (the captain calls it) `sudo bash linux/offbox.sh push` (team backup passphrase, then the window password).
- [ ] When stable: `sudo bash linux/fw.sh --role mail --level hard` → test all mail ports → `yes`.

- [ ] **Containerizing** (only if an inject asks, or to isolate a vulnerable service): `../Docker_instructions.md` -
      `sudo bash containers/ccdc-container.sh plan mail` (and `webmail`), then `build`, then `switch` (tested, rolls itself back).

## 4. Check the scored services (from Kali = like the scorer, or from the Ubuntu workstation)
```bash
P=172.25.<20+N>.15
printf 'EHLO test\r\nQUIT\r\n' | nc -w3 $P 25                       # 220 + 250-STARTTLS
printf 'USER <user>\r\nPASS <new password>\r\nSTAT\r\nQUIT\r\n' | nc -w3 $P 110   # +OK ... STAT +OK n m
printf 'a LOGIN <user> <new password>\r\nb SELECT INBOX\r\nc LOGOUT\r\n' | nc -w3 $P 143   # a OK
curl -skL http://$P/ | grep -i -m1 roundcube                       # webmail page after the redirect
ping -c2 $P
```
Send a mail to a scored user and read it back over POP3 (that's the SMTP check). Quotient: SMTP, POP3, IMAP, webmail, SSH, ping up.

## 5. Every 30 minutes
- [ ] `sudo bash linux/audit.sh scan`; alerts: `sudo journalctl -t webguard -t ccdc-fim -t ccdc-beacon --since -30min`
- [ ] Postfix config unchanged: `postconf -n | diff - /root/start/postconf.txt` (expect only `secure`'s changes)
- [ ] Queue size: `mailq | tail -1`; login failures: `sudo grep -c 'auth failed' /var/log/mail.log`
- [ ] New files in Roundcube folders: `sudo find /usr/share/roundcube /var/lib/roundcube /var/www -mmin -30 -type f -ls`
- [ ] `who; last -Fi | head`; connections out: `sudo ss -tnp state established | grep -v 127.0.0.1`

## Things that lose points - don't
- Don't turn off plaintext POP3/IMAP/SMTP or force TLS (`disable_plaintext_auth = yes`, `smtpd_tls_auth_only = yes`) - the scorer may not use TLS
- Don't change ports, the hostname, `myhostname` / `mydomain` / `mydestination`, or the domain mail is accepted for
- Don't delete or move existing mail (rule 8 - point penalty per user)
- Don't change a mail user's password without a PCR; don't change the LDAP bind account without updating this box
- Don't restart Postfix/Dovecot with a broken config: `sudo postfix check` and `sudo doveconf -n` first
- Don't full `apt upgrade`; don't rate-limit or fail2ban logins (the scorer's logins could get blocked)
