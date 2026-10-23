# Linux scripts: passwords, persistence hunt, firewall, defacement guard, file integrity, beacon detection

Usually run through `../deploy.sh`; these are the commands it uses, for running one by hand.

Fill in `../ccdc.conf` first (scored users, web roots, IPs), then on each Linux box, from this folder:

```bash
sudo ./audit.sh passwords        # FIRST, immediately: every password + policy
sudo ./audit.sh scan             # report only
sudo ./audit.sh scan --fix       # asks before each fix
sudo ./audit.sh all              # passwords, then scan --fix
```

## Passwords (`passwords`)
- Changes the password of **every** account that has one, including root, system accounts with
  hashes, and nologin mail/FTP users (they log in to IMAP/POP3/FTP with it).
- You type your own new password; every other account gets a random 16-character one.
  `--one-password` uses a single typed password for all accounts instead.
- New passwords go to `/root/ccdc/passwords-<time>.csv` (root-only). **Scored users from
  `ccdc.conf` are printed separately - submit their password change right away.**
- Locked accounts get a new password but stay locked. Accounts that never had a password are left alone.
- Policy: max age 90 days, min age 0 (so you can change them again any time), SHA-512/yescrypt,
  pwquality 14+ chars and 3 character classes. Account lockout is **not** enabled on purpose:
  the red team could use it to lock out scored users.
- Then offers to kill other login sessions, one at a time (check it isn't a teammate).

## Database passwords
```bash
sudo ./audit.sh mysql                                  # on the DB box: every MySQL account
sudo ./audit.sh app-password /var/www/html/wp-config.php   # on the web box, right after
```
The shop is down between these two commands, so run them back to back. `app-password`
handles WordPress, OpenCart, PrestaShop 1.6/1.7, Roundcube and `.env` files. `scan` lists
the config files it found. **`mysql` has not been tested against a live database yet -
try it on a practice VM first.**

## Scan (`scan`)
Checks: UID 0 accounts, empty passwords, sudoers NOPASSWD, SSH keys and sshd overrides,
cron/at, systemd units, `ld.so.preload`, PAM backdoors and unpackaged PAM modules, trojaned
system binaries (package verify), SUID shell-escape binaries, processes running from temp
dirs, shells with network sockets, listeners, shell startup files, webshells.

- Report-only unless you pass `--fix`. `--fix --yes` auto-fixes **critical** findings only;
  warnings (usually files that came from a package) always need a human.
- Nothing is deleted: files go to `/root/ccdc/quarantine-<time>/`, edited files are backed up
  to `/root/ccdc/backup-<time>/`, and lines are commented out with `# CCDC-DISABLED`.
- Critical findings are also sent to syslog (`ccdc-audit`) so Splunk sees them.

## Backups (`backup.sh`, `offbox.sh`, `vault.sh`)
```bash
sudo ./backup.sh --role ecom          # full backup -> /root/ccdc/full-backup-<time>/ (deploy's first step)
sudo ./backup.sh list
sudo ./backup.sh restore-web  latest /var/www/html     # each restore shows the differences, saves the
sudo ./backup.sh restore-db   latest                   # current state first, and asks
sudo ./backup.sh restore-file latest /etc/postfix/main.cf   # a file or a folder (missing files come back)
sudo ./vault.sh open --minutes 15     # ON THE VAULT: short SFTP-only upload window (port 2222, LAN only,
                                      # one-time password, own sshd - the scored one is untouched)
sudo ./offbox.sh push                 # ON EACH BOX: encrypt (team passphrase) + upload in that window
sudo ./vault.sh serve <file>; sudo ./offbox.sh fetch <file>   # get a backup back for a restore
```
Tested here: the encrypt → upload → checksum → fetch → decrypt → verify round trip against a test SFTP server
(upload into the unlistable folder, download, wrong passphrase refused, no shell or forwarding through the vault
account), and the vault's sshd config with `sshd -t`. **Not yet run as root on a real box** (account, chroot,
firewall and SELinux steps) - practise a full round in the lab. Details: `../checklists/BACKUP_AND_RECOVERY.md`.

## CIS baseline (`cis.sh`)
```bash
sudo ./cis.sh                          # report PASS/FAIL per CIS Level 1 control
sudo ./cis.sh --fix                    # fix, asking per section; --section sysctl --section perms ...
```
Sections: modules, mounts, sysctl, coredump, perms, cron, banner, accounts, sudo, su, logging (auditd + CIS rules),
packages, files and mac (report only). Covers what the other scripts don't; anything that could cost points or lock
the team out is report-only - list and reasons in `../checklists/CIS.md`. Drop-in files (`*-ccdc-cis*`) so undoing
is deleting one file; backups in `/root/ccdc/cis-<time>/`. Tested here: report mode on Ubuntu-based Mint, the `su`
PAM edit on Rocky and Ubuntu files, the audit rules (every syscall name checked with `ausyscall`), the permission logic.

## Firewall (`fw.sh`)
```bash
sudo ./fw.sh --role ecom --level medium            # ecom | mail | splunk | workstation (dns | mysql: older)
sudo ./fw.sh --role ecom --level hard --dry-run    # print the rules only
```
Levels: light (inbound only) → medium (default-deny both ways) → hard → extreme (internal-only ports
restricted to INSIDE, outbound pinned to known hosts; needs the IPs and team range in `ccdc.conf`).
Scored ports accept connections from anywhere and ping is allowed at every level (competition rule).
2026 scored ports per role: ecom 80/443, mail 25/110/143/80/443 (+465/587/993/995), splunk 8000/8089.
SSH (22) is open to everyone on the servers while `SSH_SCORED=yes` (it's a scored service); with `no` it's closed.
Workstations never accept SSH. We manage every box from its VM console.
Needs the `iptables` tools: Debian 12 (Splunk) lacks them - `apt install iptables iptables-persistent`;
Rocky 9 (E-com) - `dnf install iptables-nft iptables-services`. fw.sh stops firewalld/ufw.
Every role may reach the AD server's Kerberos/LDAP ports (domain-joined boxes, webmail logins against AD). **Test the scored service from another machine, then type `yes`
within 90 seconds**; anything else restores the previous rules. Previous rules are kept in
`/var/tmp/fw-backup-<time>.v4/.v6`. Exit codes: 0 kept and saved, 3 rolled back, 4 kept but not saved.

## Scored-service hardening (`secure.sh`)
```bash
sudo ./secure.sh web       # HTTP answers with a 302 to the same URL on HTTPS (Apache / nginx)
sudo ./secure.sh ssh       # scored: no root login, no forwarding/tunnels, modern ciphers; not scored: stop sshd
sudo ./secure.sh mail      # Postfix/Dovecot TLS (plaintext logins kept), no VRFY, no open relay
sudo ./secure.sh ftp       # vsftpd: no anonymous, FTPS offered, passive ports FTP_PASV
sudo ./secure.sh splunk    # no account lockout, password rules, session timeout (asks to restart)
```
Each part backs up, changes, checks the config, reloads, and tests the real service on this box
(banner, TLS handshake, the web page); a failed test puts the old files back. The web redirect is
refused when HTTPS serves a different page than HTTP (the HTTP check compares the page) unless
`--force`, and undone if HTTP doesn't end on the same page or loops. Pages tested: `WEB_CHECK_PATHS`.
Backups: `/root/ccdc/secure-<time>/`. `deploy.sh` runs the parts for the role as step `secure`.
**Not tested against live services yet** (helpers only) - run it on practice VMs first.

## Defacement guard (`webguard.sh`)
1. Check the site in a browser and confirm it looks right.
2. Baseline: `sudo ./webguard.sh init --webroot /var/www/html`
3. Watch: `sudo ./webguard.sh watch` (alert only) or `--auto-restore` (fix automatically).
   `deploy.sh` runs this as the `ccdc-webguard` service: `journalctl -u ccdc-webguard -f`
4. **After any legitimate site change (an inject asks you to edit a page), run `init` again**,
   or auto-restore will revert your change.

`check` compares once, `restore` puts changed files back now. Runtime-writable folders (cache,
uploads, sessions...) are skipped, but new or changed script files there (`.php`...) are still
caught. Changed and new files are copied to `/root/.webguard/<root>/evidence/` with a diff before
anything is touched, for incident reports. Alerts go to syslog so Splunk sees them.

## File integrity monitor (`fim.sh`)
Watches `/etc`, `/bin` `/sbin` `/usr/bin` `/usr/sbin` `/usr/local/{bin,sbin}`, PAM module folders,
systemd unit folders, `/var/spool/cron`, and `.ssh/*` plus shell startup files (`.bashrc`, `.profile`...)
in `/root` and every home directory. Per role it adds: dns - zone folders; ecom/mysql - MySQL plugin
folders (UDF backdoors); splunk - `/opt/splunk/etc/apps` and `system/local`. Add more with
`FIM_EXTRA_PATHS` in `ccdc.conf`.

```bash
sudo ./fim.sh init --role ecom     # AFTER hardening + scan, so the baseline is clean (~3 s)
sudo ./fim.sh watch                # deploy.sh runs this as the ccdc-fim systemd unit
sudo ./fim.sh check                # one full comparison, exit 1 if anything changed
sudo ./fim.sh accept /etc/shadow   # you changed it on purpose: take it into the baseline
sudo ./fim.sh list                 # what's watched
```
- Reports NEW, CHANGED, DELETED and PERMS (mode/owner) once per change; again only if it changes again.
- Fast passes re-hash only files whose size, timestamps or inode changed; every 10th pass re-hashes
  everything (catches faked timestamps).
- **Alert only - it never restores system files.** Changed and new files are copied to
  `/root/.ccdc-fim/evidence/<time>/` with a diff against the baseline copy (text files).
- Alerts go to syslog as `ccdc-fim` (Splunk), `/var/log/ccdc-fim.log` and `journalctl -u ccdc-fim`.
- If the baseline file itself changes, it says so (accept was run, or someone is tampering).
- Expect alerts after your own changes: `audit.sh passwords` (`/etc/shadow`), `fw.sh` saving rules,
  `sshd_config` edits. Check them, then `accept`.

## Beacon detector (`beacon.sh`)
Finds outbound connections that repeat on a timer - an implant calling home every N seconds -
and the program making them.
```bash
sudo ./beacon.sh watch     # deploy.sh runs this as the ccdc-beacon systemd unit
sudo ./beacon.sh report    # table of every repeating destination so far, beacons first
```
- **BEACON**: 8+ connections to the same IP/port/protocol, gaps of 10 s or more, and 80% of the
  gaps within 25% of the typical gap (so a beacon with up to ~25% jitter is still caught).
  **maybe**: 50-80% regular - look at these too. Alerts go to syslog as `ccdc-beacon`.
- Data source, picked automatically: the kernel connection table if present (sees everything),
  else `tcpdump` (TCP and ping, exact times), else `ss` polling (can miss very short connections).
  The first line of `journalctl -u ccdc-beacon` says which one it's using.
- Ignored as expected: NTP, DNS to this box's resolvers, Splunk forwarding (`SPLUNK:9997/8089`).
  Add more in `BEACON_ALLOW` in `ccdc.conf` - e.g. the web box's regular DB connections.
- Report-only. To act on a beacon: `ss -tunap | grep <IP>` and `ls -l /proc/<pid>/exe` to find the
  program, follow the IR checklist, block the IP on the Palo Alto (never the scoring engine).
- Tested with simulated beacons (fixed 10 s and 8-12 s jitter) plus random and chatty traffic:
  both beacons caught with tcpdump and with ss, random traffic only ever reached "maybe".

## Outbound SSH detector (`outbound_ssh.sh`)
Flags SSH connections **from** this box (pivoting, tunnels): remote port in `SSH_DEFAULT_PORTS` (default 22),
or an SSH client process (`ssh`, `autossh`, `dbclient`, `plink`, `sshpass`) on any port. Skips `SSH_ALLOW`
entries (IP, CIDR, `IP:PORT`, `CIDR:PORT`) and inbound sessions to our own sshd. One syslog warning
(`ccdc-outbound-ssh`) per live connection, with time, host, user, PID, program, executable, addresses and
command line; a state file prevents repeats.
```bash
sudo ./outbound_ssh.sh              # check once (exit 1 if any found) - fine for cron
sudo ./outbound_ssh.sh --watch 10   # deploy.sh runs this as the ccdc-outbound-ssh service
sudo ./outbound_ssh.sh --no-state   # list everything live without logging (reports)
```
Tested: port-22 connection and an `ssh` process on port 2222 flagged; an allow-listed `CIDR:22` and the
server side of each connection skipped; one log line per connection; state cleared after disconnect.

## Evidence for injects (`evidence.sh`)
`sudo ./evidence.sh [--section LIST] [--fim-test] [--log-test]` - one report with system info, time sync,
connectivity, firewall policy (incl. deny-by-default + drop logging), startup/monitor integrity, file
integrity proof, logging status and a traffic profile. Saved to `/root/ccdc/evidence-<host>-<time>.txt`.
See `injects/initial injects/PLAYBOOK.md`.

## Where the monitors run
`deploy.sh` copies the scripts and `ccdc.conf` to root-only `/opt/ccdc` (checksums in `/opt/ccdc/SHA256SUMS`)
and runs the monitors as systemd services that start at boot: `ccdc-webguard`, `ccdc-beacon`,
`ccdc-outbound-ssh`, `ccdc-fim`. After editing `ccdc.conf`, re-run the deploy steps to update the copy.
The firewall logs what it drops (`CCDC-DROP-IN/OUT`, rate-limited; `journalctl -k --grep CCDC-DROP`);
turn off with `FW_LOG_DROPS=no`.

## Services: legacy removal and updates (`services.sh`)
```bash
sudo ./services.sh                    # report only
sudo ./services.sh --fix              # disable + mask each legacy service, asking first (--remove also uninstalls)
sudo ./services.sh --refresh          # refresh package lists first (internet) for current update info
sudo ./services.sh --update           # install updates for important services, one package at a time
```
- **Inventory:** every listening port with its process, systemd unit, package and version (flags ports not
  in `EXPECTED_PORTS`), running services.
- **Legacy / insecure (remove right away):** telnet, rsh/rlogin/rexec, TFTP, inetd/xinetd, NIS, talk, finger,
  rpcbind, FTP, SNMP (and default `public`/`private` communities), Avahi, CUPS, VNC/X11, rsync daemon, NFS
  server, DHCP server; Samba allowing SMB1; databases/caches listening on all addresses.
  **A legacy service on a port in `EXPECTED_PORTS` is reported as `SCORED?` and never touched.**
  Undo a fix: `systemctl unmask <unit> && systemctl enable --now <unit>`.
- **End-of-life:** OS release, PHP, MySQL/MariaDB, Apache, OpenSSL, Python 2 (dates as of October 2026),
  and web app versions (WordPress, Roundcube, PrestaShop 1.6, OpenCart) to compare with the vendor.
- **Updates:** pending updates for packages behind listening services and core security packages (OpenSSH,
  OpenSSL, sudo, glibc, systemd, kernel...), with SECURITY marked. `--update` keeps existing config files,
  never installs a kernel (needs a reboot), warns if a listener disappears afterwards, and offers to record
  the updated files in the file integrity baseline.
- Tested on Ubuntu 24.04-based Mint: found Avahi and CUPS, skipped CUPS when 631 was an expected port,
  `--fix --remove` and `--update` issued the right commands (stubbed), 13 important updates listed.
  Rocky/RHEL (dnf) path not tested yet - the 2026 E-com box is Rocky 9.

## Network port scan (`portscan.sh`)
What is actually reachable on each of our hosts from the network - what the scorer and red team see -
as opposed to what is listening locally (`services.sh`).
```bash
./portscan.sh                          # every host in ccdc.conf, ~140 common TCP ports
./portscan.sh 172.20.240.10 --banner   # one host, with service banners (SSH/SMTP versions, HTTP Server)
./portscan.sh 172.20.240.0/24          # a team subnet (live hosts only; up to /22)
sudo ./portscan.sh --udp               # add common UDP ports (nmap + root)
./portscan.sh --ports all              # 1-65535 (use nmap for this)
./portscan.sh --watch 15               # rescan every 15 minutes in tmux, alert on changes
```
- Uses nmap if installed, otherwise a built-in parallel TCP connect scan.
- Labels: `expected` (from `SCAN_EXPECT` in `ccdc.conf`), `UNEXPECTED`, `RISKY` (telnet, SMB, RDP,
  databases, VNC, WinRM, Docker API... reachable from the network), `SUSPICIOUS` (4444, 1337, 31337,
  50050 and other backdoor / C2 ports), and `MISSING expected port` (scored service down or blocked?).
- Compares with the previous scan: **NEW** open ports (possible backdoor) and **GONE** ports (possible
  outage) are reported and logged to syslog (`ccdc-portscan`). Results in `/root/ccdc/portscan/`.
- **Only scans the team's own ranges** (INSIDE, EXTERNAL, SCAN_SCOPE, host IPs in `ccdc.conf`); anything
  else is refused - CCDC rules forbid scanning other teams. `--allow-any` is for practice labs.
- Scanning from outside the firewall (e.g. a laptop on the external side, if allowed) shows what the
  internet sees; from inside it shows what an attacker who got in would see. Both are useful.
- Tested in a sandbox with both engines: expected/RISKY/SUSPICIOUS labels, banners, out-of-scope target
  refused, missing expected port, and NEW/GONE detection between scans.

## Splunk forwarder (`forwarder.sh`)
`sudo ./forwarder.sh` (or the `forwarder` step of `deploy.sh`) installs Universal Forwarder **10.0.2** - the same
version as the 2026 Splunk server (forwarders must be the same or older) - from `../installers/splunk/`, or
downloads it from download.splunk.com and verifies the SHA-512. It sends auth/secure, syslog/messages, kernel,
audit, cron, mail, web server and database logs plus our `ccdc-*` logs to `SPLUNK:9997`, and the systemd journal
on boxes without rsyslog. Runs as `splunkfwd` (given read access via groups/ACLs, login shell removed),
starts at boot, and its local admin gets a random password (`/root/ccdc/splunkforwarder-admin.txt`).
Checked against the real 10.0.2 package (`-group` boot-start flag, journald input, the package's user handling);
not yet run on a real install - try it on a practice VM.

## Privilege escalation and living off the land (`privesc.sh`)
`sudo ./privesc.sh` (report) / `--fix` (asks before each fix). Looks for ways a normal user or a compromised
service account becomes root: sudo rules (NOPASSWD, ALL, shell-escape programs such as vim/less/find/python,
wildcards), dangerous file capabilities, SUID shell-escape programs, files root runs or trusts that others can
write (cron jobs and their programs, systemd units and the programs root services start, init/profile scripts,
root's PATH, library folders, passwd/shadow/sudoers), root-equivalent groups (docker, lxd, disk, shadow),
docker socket, NFS `no_root_squash`, readable secrets (shadow, private keys, app configs with DB passwords,
histories), old sudo / pkexec - and reverse-shell / download-and-run commands in running processes, shell
history, cron and units. Complements `audit.sh scan` (backdoors/persistence).
Tested in a sandbox: planted NOPASSWD vim and NOPASSWD ALL sudo rules, a world-writable root cron script, a
docker-group user, a readable private key, reverse shells in history and in a running process - all found.
