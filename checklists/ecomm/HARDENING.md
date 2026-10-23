# Rocky Linux 9 E-Commerce (web + MySQL/MariaDB) - hardening checklist

| | |
|---|---|
| Address | `172.20.240.10`, public `172.25.(20+N).10` |
| OS / software | Rocky Linux 9, Apache `httpd` + PHP (php-fpm), MariaDB/MySQL on the same box |
| Default login | `sysadmin` (password in the team packet - write it here only on paper: ________ ) |
| **Scored** | **HTTP (80)** and **HTTPS (443)**: a specific page is fetched and compared with the expected content; SSH (while `SSH_SCORED=yes`); ping |
| Script role | `ecom` |
| Rocky specifics | web user `apache`, logs `/var/log/httpd/` and `/var/log/secure`, SELinux Enforcing, `firewalld` + `cockpit` often on |

Work from the VM console. Assume every password (Linux, MySQL, shop admin) is already known to the red team.
Incident response: `IR.md`. Linux commands and log locations: `../LINUX_CHEATSHEET.md`.

---

## 0. Before touching anything (5 min)
- [ ] `tmux new -s ccdc` (reattach after a disconnect: `tmux a`). Run everything below inside it.
- [ ] Save what the box looks like now (evidence and a "known good" to compare with):
      ```bash
      sudo mkdir -p /root/start && cd /root/start
      sudo bash -c 'ss -tulpn > ss.txt; ps auxwwf > ps.txt; getent passwd > passwd.txt; getent group > group.txt
        systemctl list-units --type=service --state=running > services.txt; crontab -l -u root > cron-root.txt 2>&1
        ls -la /etc/cron.* /var/spool/cron > cron-dirs.txt 2>&1; last -Fi > last.txt'
      ```
- [ ] **Prove the shop works and keep the page** - this is what the scorer compares against:
      ```bash
      curl -s  http://127.0.0.1/  -o /root/start/http.html;  curl -sI  http://127.0.0.1/
      curl -sk https://127.0.0.1/ -o /root/start/https.html; curl -skI https://127.0.0.1/
      ```
      Open the shop in a browser (Ubuntu or Windows workstation: `http://172.20.240.10/`), click a product, screenshot it.
      Page path the scorer uses (from Quotient, e.g. `/` or `/index.php`): ____________ → put it in `WEB_CHECK_PATHS` in `ccdc.conf`.
- [ ] Find the app and its config: `ls /var/www/html`, then `wp-config.php` (WordPress), `config.php` + `admin/config.php`
      (OpenCart), `app/config/parameters.php` (PrestaShop 1.7+), `config/settings.inc.php` (PrestaShop 1.6) or `.env`.
      App: ____________  Config file: ____________  DB name / user: ____________
- [ ] **Backups:** the deploy's first step, `backup` (section 1), saves everything as it is now - /etc, the web root,
      every database, mail, Splunk config, keys, cron, plus a state snapshot - to `/root/ccdc/full-backup-<time>/`.
      Answer **y**. It's the undo button for the rest of the competition (`../BACKUP_AND_RECOVERY.md`).
      (`backup` asks for the MySQL root password if root can't log in over the socket - it's in the app config or the packet.)

## 1. Passwords - first 5 minutes
- [ ] Get the scripts (`../GETTING_SCRIPTS.md`), set the team number in `ccdc.conf`, `CONFIG_REVIEWED=yes`.
- [ ] Run the deploy **without** the two baseline steps (they come after the manual hardening in section 3):
      ```bash
      cd ~/ccdc-main && sudo bash ./deploy.sh --role ecom --skip webguard,fim
      ```
- [ ] `passwords` step: type your own new password; every other account gets a random one. **Scored users are printed
      as `username,password` - give them to the captain for Quotient → PCR right now.** CSV: `/root/ccdc/passwords-*.csv`.
- [ ] `database` step, **straight after**: it sees MySQL on this box, changes every MySQL account, then asks which app
      config to update - pick the one the shop really uses (not `-dist`/`sample`). **Reload the shop immediately**; a
      "database connection error" means re-run: `sudo bash ./deploy.sh --role ecom --only database`.
- [ ] **Shop admin accounts** (no script does these): log in to the admin panel (`/wp-admin`, `/admin`, PrestaShop's
      renamed `admin123xyz/` folder) → Users → change every admin's password, remove admins nobody recognises (ask first).
      Write them down for the captain (PCR only if Quotient shows the shop login is checked).

## 2. The rest of the deploy steps (same run)
| Step | What to do |
|---|---|
| firewall | `fw.sh` at `FIREWALL_LEVEL`: 80/443 (+22 while `SSH_SCORED=yes`) open to everyone, ping always. Rocky needs the iptables tools first: `sudo dnf install -y iptables-nft iptables-services`. Within 90 s load the shop from another box, then type `yes`. |
| secure | **HTTP → HTTPS redirect**: refuses if HTTPS doesn't serve the same page as HTTP, undoes itself if HTTP doesn't end on the same page or loops. Then SSH hardening. **Watch Quotient's HTTP check for the next few minutes.** |
| cis | CIS Level 1 baseline not covered elsewhere: kernel/network parameters, unused modules, `/dev/shm`, core dumps, file permissions, cron, banners, sudo/su, auditd. Asks per section; anything that could hurt scoring is report-only (`../CIS.md`). |
| scan | Webshells, odd PHP, persistence. Quarantine moves files to `/root/ccdc/quarantine-*`, nothing is deleted. Read every CRITICAL. |
| services | Legacy services off after asking (never one on a scored port); pending updates listed. |
| forwarder | Splunk forwarder → `172.20.240.20:9997` (auth, audit, web logs). |
| beacon | Outbound-connection watcher (`journalctl -u ccdc-beacon -f`). |

## 3. Manual hardening (each item: change → test the shop → note it)
After each change: `curl -s http://127.0.0.1/ | diff -q - /root/start/http.html` (no output = same page; dynamic pages
always differ - then compare in the browser).

### 3.1 Accounts and sudo
- [ ] Only root has UID 0: `awk -F: '$3 == 0' /etc/passwd`
- [ ] Accounts that can log in: `awk -F: '$7 !~ /(nologin|false)$/' /etc/passwd` - compare with `/root/start/passwd.txt`.
      Unknown one: `sudo usermod -L -e 1 <user>` (locks it, keeps it - don't delete usernames, rule 11).
- [ ] Who has sudo: `getent group wheel`, `sudo grep -v '^#' /etc/sudoers | grep .`, `sudo ls -la /etc/sudoers.d/`.
      Remove unknown members: `sudo gpasswd -d <user> wheel`. `NOPASSWD` lines you didn't expect = incident.
- [ ] Service accounts can't log in: `getent passwd apache mysql nginx | cut -d: -f1,7` → all `/sbin/nologin`.
- [ ] SSH keys: `sudo find /root /home -name authorized_keys -exec ls -la {} \; -exec cat {} \;` - remove keys nobody owns.

### 3.2 Unneeded services (Rocky turns some on)
- [ ] `systemctl list-unit-files --state=enabled --type=service,socket` - compare with `/root/start/services.txt`.
- [ ] **Cockpit** (web admin on port 9090, root login with a password): `sudo systemctl disable --now cockpit.socket`
- [ ] Not needed on a web server: `sudo systemctl disable --now rpcbind.socket rpcbind avahi-daemon cups 2>/dev/null`
- [ ] `sudo ss -tulpn` afterwards: only 22 (if scored), 80, 443 on all addresses; MySQL only on `127.0.0.1:3306`.

### 3.3 Apache
- [ ] Hide versions and disable TRACE - headers only, the page content doesn't change:
      ```bash
      sudo tee /etc/httpd/conf.d/zz-ccdc-hardening.conf > /dev/null <<'EOF'
      ServerTokens Prod
      ServerSignature Off
      TraceEnable Off
      Header always set X-Content-Type-Options "nosniff"
      Header always set X-Frame-Options "SAMEORIGIN"
      EOF
      sudo apachectl -t && sudo systemctl reload httpd && curl -sI http://127.0.0.1/ | grep -i server
      ```
- [ ] Unknown vhosts, aliases, proxies or modules (red team backdoors): `sudo apachectl -S`, then
      `grep -rniE 'Alias|ScriptAlias|ProxyPass|LoadModule|<Location|php_value auto_' /etc/httpd/conf.d /etc/httpd/conf.modules.d`.
      Compare with `/root/start/etc.tgz` (`tar tzf` / extract to `/tmp` and `diff -r`).
- [ ] `server-status` / `server-info` pages open to the world? `curl -s http://127.0.0.1/server-status | head -3` - if it answers, remove that `<Location>` block.
- [ ] Directory listings: `curl -s http://127.0.0.1/images/ | grep -i 'index of'` - if listed, add `Options -Indexes`
      for that directory in the vhost (test the shop after - some apps need `FollowSymLinks`).
- [ ] `.htaccess` files with `auto_prepend_file`, `AddType ... php` on image folders or `SetHandler`: `sudo find /var/www -name .htaccess -exec grep -HniE 'prepend|AddType|SetHandler|php_value' {} \;`

### 3.4 PHP
- [ ] Current values: `php -i | grep -E '^(expose_php|allow_url_include|allow_url_fopen|display_errors|disable_functions) '`
- [ ] Safe settings (don't change the page):
      ```bash
      sudo tee /etc/php.d/99-ccdc.ini > /dev/null <<'EOF'
      expose_php = Off
      allow_url_include = Off
      log_errors = On
      session.cookie_httponly = 1
      EOF
      sudo systemctl restart php-fpm && curl -sI http://127.0.0.1/ | head -1
      ```
- [ ] `display_errors = Off` too - **only if the scored page shows no PHP warnings now** (turning them off changes the
      page the scorer compares). Check: `grep -ci 'warning\|notice\|deprecated' /root/start/http.html` → 0? then add it.
- [ ] `disable_functions = exec,passthru,shell_exec,system,proc_open,popen` stops most webshells, **but** can break
      the shop (and its admin panel). Only with a full test: storefront, product page, cart, admin login.

### 3.5 Web root
- [ ] PHP files changed since the box was built, and PHP in upload folders:
      ```bash
      sudo find /var/www -name '*.php' -newer /etc/hostname -ls | head -30
      sudo find /var/www \( -path '*upload*' -o -path '*cache*' -o -path '*images*' \) -name '*.ph*' -ls
      sudo grep -rlE 'eval\(|base64_decode\(|assert\(|system\(|passthru\(|shell_exec\(' /var/www --include='*.php' | head
      ```
      Real webshells: `scan` quarantines them; by hand `sudo mv <file> /root/ccdc/` - never just delete (evidence).
- [ ] Ownership: code should not be writable by `apache` except upload/cache folders. Writable now:
      `sudo find /var/www -user apache -type f -name '*.php' | head`. Fix only with the app's writable folders known
      (WordPress `wp-content/uploads`, OpenCart `image/` + `system/storage/`, PrestaShop `img/ cache/ var/`):
      `sudo chown -R root:apache /var/www/html && sudo chown -R apache:apache <each writable folder>`, then test the admin panel.
- [ ] Leftover installers: `ls -d /var/www/html/{install,installer,setup}* 2>/dev/null` → `sudo mv` them to `/root/ccdc/`.
- [ ] Backup / dump files reachable over the web: `sudo find /var/www \( -name '*.sql' -o -name '*.bak' -o -name '*.zip' -o -name '*.tgz' \) -ls`

### 3.6 SELinux
- [ ] `getenforce` → keep `Enforcing`. Never `setenforce 0` mid-competition.
- [ ] Denials after a change: `sudo ausearch -m avc -ts recent | tail`. After restoring files: `sudo restorecon -Rv /var/www`.
- [ ] Booleans that open things up: `getsebool -a | grep -E 'httpd_(can_network_connect|enable_cgi|execmem|unified) '` -
      note anything `on` that wasn't the Rocky default (`httpd_can_network_connect` may be needed if the app calls out).

### 3.7 Database (on this box)
Open a root shell: `sudo mysql` (or `sudo mysql -p` with the new root password from `/root/ccdc/mysql-passwords-*.csv`).
- [ ] Accounts: `SELECT user, host, plugin FROM mysql.user;`
      - anonymous users (`user = ''`): `DROP USER ''@'localhost'; DROP USER ''@'%';` (the `mysql` step offers this too)
      - `root` only from `localhost` / `127.0.0.1` / `::1`: `DROP USER 'root'@'%';`
      - the app user only from `localhost`: `SHOW GRANTS FOR '<appuser>'@'localhost';` → only its own database, no `ALL ON *.*`, no `FILE`, no `SUPER`
- [ ] Test database: `DROP DATABASE IF EXISTS test;`
- [ ] Unknown accounts with power: `SELECT user, host FROM mysql.user WHERE Super_priv='Y' OR File_priv='Y' OR Grant_priv='Y';`
- [ ] Listening only locally: `sudo ss -ltnp | grep 3306` → `127.0.0.1:3306`. If `0.0.0.0` / `*`: add under `[mysqld]` in
      `/etc/my.cnf.d/mariadb-server.cnf` (or `mysql-server.cnf`): `bind-address = 127.0.0.1` and `local_infile = 0`,
      then `sudo systemctl restart mariadb` (or `mysqld`) and reload the shop at once.
- [ ] Tables the red team may have touched later: keep `/root/start/db.sql`; `sudo mysql -e "SELECT user_login, user_registered FROM <db>.wp_users"` (WordPress) etc. for new admin users.

### 3.8 CIS baseline (deploy step `cis`)
The deploy's `cis` step (`linux/cis.sh --fix`, asks per section) covers what used to be typed here by hand,
and more: kernel/network parameters, unused kernel modules, `/dev/shm` noexec, no core dumps, file permissions,
cron allow lists, login banners, sudo logging, `su` limited to an empty group, persistent journal, and auditd with
the CIS rules (plus watches on this box's scored-service files). Report any time: `sudo bash linux/cis.sh`.
Why some CIS items are skipped on purpose (no lockout, no GRUB password...): `../CIS.md`.
- [ ] `sysctl net.ipv4.icmp_echo_ignore_all` → `0` (ping is scored - `cis.sh` never turns it on)
- [ ] Who changed the web root or Apache config: `sudo ausearch -k scored_service -ts today -i | tail -30`

### 3.9 Logging (evidence for incident reports)
- [ ] Logs reach Splunk: in Splunk `index=* host=<this hostname> earliest=-10m | stats count by source`

### 3.10 Updates (only for what's exposed)
- [ ] `sudo dnf check-update --security` (or `sudo bash linux/services.sh --refresh`). Update one package at a time,
      only for exposed software (httpd, php*, openssh, mariadb), test the shop after each:
      `sudo dnf upgrade -y httpd mod_ssl` → `curl -sI http://127.0.0.1/`. Never a full `dnf upgrade` (kernel = reboot).

### 3.11 Take the baselines and back up (last)
- [ ] Load the shop in a browser - it must look right - then:
      `sudo bash ./deploy.sh --role ecom --only webguard,fim`
- [ ] **Backup of the hardened box, then off the box:** `sudo bash linux/backup.sh --role ecom` → at the next vault
      window (the captain calls it) `sudo bash linux/offbox.sh push` (team backup passphrase, then the window password).
- [ ] **This box receives the Splunk box's backup** (`BACKUP_VAULT_ALT`): when the Splunk person asks, open a window here:
      `sudo bash linux/vault.sh open --minutes 10` and read out the password (it closes itself).
- [ ] When stable, tighten: `sudo bash linux/fw.sh --role ecom --level hard` → test → `yes`.

- [ ] **Containerizing** (only if an inject asks, or to isolate a vulnerable service): `../Docker_instructions.md` -
      `sudo bash containers/ccdc-container.sh plan ecom-web` (and `ecom-db`), then `build`, then `switch` (tested, rolls itself back).

## 4. Check the scored services (like the scorer: from Kali, through the router and Palo Alto)
```bash
curl -sI  http://172.25.<20+N>.10/          # 302 to https (after secure) or 200
curl -skL http://172.25.<20+N>.10/ | head    # ends on the shop page
curl -skI https://172.25.<20+N>.10/          # 200
ping -c2 172.25.<20+N>.10
```
And Quotient: HTTP, HTTPS, SSH, ping all up.

## 5. Every 30 minutes
- [ ] `sudo bash linux/audit.sh scan` (report only) - new CRITICALs?
- [ ] Webguard / fim / beacon alerts: `sudo journalctl -t webguard -t ccdc-fim -t ccdc-beacon --since -30min`
- [ ] New or changed files in the web root: `sudo find /var/www -mmin -30 -type f -ls`
- [ ] Who's logged in / logged in recently: `who; last -Fi | head`; `sudo grep -E 'Accepted|Failed' /var/log/secure | tail`
- [ ] Connections out: `sudo ss -tnp state established | grep -v '127.0.0.1'`
- [ ] Shop page still the same as the baseline (`curl` diff above); Quotient green

## Things that lose points - don't
- Don't change the MySQL password without updating the app config in the same minute
- Don't change the web ports, vhost names, the hostname, the IP, or the shop's base URL / "force SSL" setting (loops with the redirect)
- Don't add HTTP→HTTPS redirects by hand - `secure.sh web` tests that the HTTP check still gets the same page
- Don't delete product data, customers or "clean up" database tables; don't delete files (move them - evidence)
- Don't `setenforce 0`, don't full `dnf upgrade`, don't reboot without warning the team
- Don't turn on webguard `--auto-restore` until the baseline is known-good
- Don't restore a backup without recording evidence first, and change passwords again after one (old hashes come back)
