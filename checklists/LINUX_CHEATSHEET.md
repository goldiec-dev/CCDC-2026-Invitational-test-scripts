# Linux cheat sheet: tmux and log files

## Part 1 - tmux (do this first on every box)
tmux keeps your shell running if SSH drops or the console disconnects, and lets you watch logs
in one window while you work in another. **Start it before running `deploy.sh`.**

Not installed? `sudo apt install tmux` (Ubuntu/Debian) or `sudo dnf install tmux` (Fedora/RHEL).
No internet? `screen` works the same way (`screen -S ccdc`, detach `Ctrl-a d`, reattach `screen -r ccdc`).

### Start and come back
| Do this | Type |
|---|---|
| Start a named session | `tmux new -s ccdc` |
| Leave it running (detach) | `Ctrl-b` then `d` |
| List sessions | `tmux ls` |
| Get back in (after SSH drops, too) | `tmux attach -t ccdc` (or just `tmux a`) |
| Teammate watching the same screen | they run `tmux attach -t ccdc` as the same user |

**Every shortcut is `Ctrl-b`, let go, then the key.** Example: `Ctrl-b c` = hold Ctrl, press b, release both, press c.

### Windows (like tabs)
| | |
|---|---|
| New window | `Ctrl-b c` |
| Next / previous window | `Ctrl-b n` / `Ctrl-b p` |
| Jump to window 0-9 | `Ctrl-b 0` ... `Ctrl-b 9` |
| Rename window (shows in the bottom bar) | `Ctrl-b ,` |
| Close window | type `exit` |

### Panes (split the screen)
| | |
|---|---|
| Split side by side | `Ctrl-b %` |
| Split top / bottom | `Ctrl-b "` |
| Move between panes | `Ctrl-b` + arrow key |
| Make a pane full screen / back | `Ctrl-b z` |
| Close pane | type `exit` (or `Ctrl-b x`, then `y`) |

### Scrolling back
- `Ctrl-b [` then arrows / PgUp / PgDn. Press `q` to leave scroll mode.
- Easier: turn on the mouse with `Ctrl-b :` then type `set -g mouse on` and Enter. Now the wheel scrolls
  and clicking picks a pane. (Hold Shift to select text for copying.)

### Suggested layout
```
window 0 "work"     sudo bash ./deploy.sh --role <role>, then your manual checks
window 1 "auth"     sudo tail -f /var/log/auth.log       (Fedora: /var/log/secure)
window 2 "alerts"   sudo journalctl -f -t ccdc-audit -t ccdc-fim -t ccdc-beacon -t ccdc-outbound-ssh -t webguard
           (split it: Ctrl-b " then)  sudo journalctl -kf --grep CCDC-DROP     # packets the firewall dropped
window 3 "web"      sudo tail -f /var/log/apache2/access.log   (web boxes; Fedora: /var/log/httpd/access_log)
```

### The red team uses tmux too
- `ps aux | grep -E '[t]mux|[s]creen'` - sessions that aren't yours?
- `ls -la /tmp/tmux-*/ /run/screen/ 2>/dev/null` - each user's session sockets
- Don't kill a session until you know it isn't a teammate's. If it's the red team: record it (IR checklist), then `kill <pid>`.

---

## Part 2 - log files: where they are
| What | Ubuntu / Debian | Fedora / RHEL / Oracle |
|---|---|---|
| Logins, sudo, su, SSH, user changes | `/var/log/auth.log` | `/var/log/secure` |
| Everything else (services, cron, kernel) | `/var/log/syslog` | `/var/log/messages` |
| Cron | in `syslog` (`grep CRON`) | `/var/log/cron` |
| Web server | `/var/log/apache2/` or `/var/log/nginx/` | `/var/log/httpd/` or `/var/log/nginx/` |
| Mail | `/var/log/mail.log` | `/var/log/maillog` |
| MySQL / MariaDB | `/var/log/mysql/error.log` | `/var/log/mariadb/mariadb.log`, `/var/log/mysqld.log` |
| DNS (BIND) | `journalctl -u named` (or `-u bind9`) | `journalctl -u named`, `/var/named/data/` |
| Who logged in | `last -Fi` (logins), `lastb -i` (failed logins), `who` / `w` (right now) | same |
| Our scripts | `/root/ccdc/`, `/var/log/ccdc-*.log`, `journalctl -t ccdc-audit` / `-t ccdc-fim` / `-t ccdc-beacon` | same |

**journalctl** works on every systemd box, even if the files above are missing:
```bash
journalctl -f                                  # live, everything
journalctl --since "30 min ago" -p warning     # recent warnings and worse
journalctl -u ssh -u sshd --since today        # one service (Ubuntu: ssh, Fedora: sshd)
journalctl _COMM=sudo --since "1 hour ago"     # every sudo
journalctl --list-boots                        # did the box reboot?
```
Old logs are rotated: `auth.log.1`, `secure-20261016`, `*.gz`. Read `.gz` files with `zgrep` / `zcat`.

---

## Part 3 - what to look for
Below, `AUTH` = `/var/log/auth.log` (Ubuntu) or `/var/log/secure` (Fedora). Set it once:
`AUTH=/var/log/auth.log; [ -f /var/log/secure ] && AUTH=/var/log/secure`

### Logins
```bash
sudo grep "Accepted" $AUTH | tail -20                        # successful SSH logins - who, from where
sudo grep "Failed password" $AUTH | grep -oE 'from [0-9a-f.:]+' | sort | uniq -c | sort -rn | head   # brute force by IP
sudo grep -E "Invalid user|invalid user" $AUTH | tail        # guessing usernames
sudo grep "Accepted publickey" $AUTH | tail                  # key logins - did someone plant a key?
```
**Suspicious:** a successful login right after many failures from the same IP · logins as
service accounts (`www-data`, `mysql`, `nobody`) · root logins over SSH · logins from an IP
outside the team subnet · logins at a time nobody on the team was on that box.

### sudo / su / root
```bash
sudo grep "COMMAND=" $AUTH | tail -30                        # every sudo command, with the user
sudo grep -E "su:|su\[" $AUTH | tail                         # su to another user
sudo grep "authentication failure" $AUTH | tail
```
**Suspicious:** sudo from an account that shouldn't have it · commands like `chmod u+s`, `useradd`,
`passwd`, `curl ... | sh`, `nc`, `bash -i`, `base64 -d` · sudo commands nobody on the team ran.

### Accounts and groups
```bash
sudo grep -E "useradd|userdel|usermod|groupadd|gpasswd|new user|new group|add '.*' to group|password changed" $AUTH
```
**Suspicious:** any new user, anyone added to `sudo` / `wheel` / `adm`, a password change you didn't
make. Cross-check with `/root/ccdc/passwords-*.csv` (the changes we made).

### Cron, services, persistence
```bash
sudo grep CRON /var/log/syslog /var/log/cron 2>/dev/null | grep CMD | awk -F'CMD ' '{print $2}' | sort | uniq -c | sort -rn | head
journalctl --since today | grep -E "Started|Created slice|Reloading" | grep -v -E "Session|user@" | tail -30
```
**Suspicious:** a cron command running `curl`, `wget`, `nc`, `bash -c`, `python -c`, or anything in
`/tmp`, `/dev/shm`, `/var/tmp` · a service name you don't recognise starting · `systemctl daemon-reload`
nobody ran. Then run `sudo bash linux/audit.sh scan` - it checks all of these properly.

### Web server (access log)
```bash
L=/var/log/apache2/access.log   # Fedora: /var/log/httpd/access_log, nginx: /var/log/nginx/access.log
sudo awk '{print $1}' $L | sort | uniq -c | sort -rn | head                     # busiest IPs
sudo grep '"POST' $L | awk '{print $1, $7}' | sort | uniq -c | sort -rn | head  # who POSTs to what
sudo grep -iE "sqlmap|nikto|gobuster|dirbuster|wpscan|nmap|masscan|hydra" $L | tail   # scanners
sudo grep -iE "union.*select|sleep\(|\.\./|/etc/passwd|cmd=|exec=|eval\(|base64_|<script" $L | tail -20
sudo grep -E '/(uploads?|images?|img|cache|tmp|files)/[^ ]*\.(php|phtml|phar)' $L | tail   # PHP run from upload folders
```
**Suspicious:** POSTs to a `.php` file that isn't the shop's normal pages (login, cart, checkout) ·
any request to a file under an uploads/images folder ending in `.php` · requests with `cmd=`, `?c=`,
`?x=` and a `200` response · one IP requesting hundreds of different pages (scanner) · `wp-admin` or
`/admin` logins from IPs outside the team. The **error log** next to it shows PHP warnings mentioning
`system()`, `exec()`, `eval()` or `shell_exec()` - a webshell running.

### Mail
```bash
sudo grep -i "authentication failed" /var/log/mail.log /var/log/maillog 2>/dev/null | tail   # password guessing
sudo grep -i "sasl_username" /var/log/mail.log /var/log/maillog 2>/dev/null | awk -F'sasl_username=' '{print $2}' | sort | uniq -c | sort -rn | head
mailq | tail -1                                                       # queue size
```
**Suspicious:** one account sending hundreds of messages (stolen password → spam) · a growing queue ·
"relay access denied" in bulk (someone testing for an open relay).

### Signs someone is hiding their tracks
```bash
ls -la /var/log/ | sort -k5 -n | head                 # important logs at size 0?
ls -la /root/.bash_history /home/*/.bash_history      # missing, size 0, or a link to /dev/null?
sudo grep -rE "HISTFILE|HISTSIZE=0|unset HIST" /etc/profile /etc/profile.d /etc/bash.bashrc /etc/bashrc /root/.bashrc /home/*/.bashrc 2>/dev/null
systemctl status rsyslog systemd-journald --no-pager | grep -E "Active|●"
last -Fi | head                                       # empty or starting very recently = wtmp wiped
```
**Suspicious:** a log that suddenly stops or has a time gap · `rsyslog` stopped · history files
linked to `/dev/null` · `wtmp`/`btmp` emptied. Any of these means someone with root was here:
follow the box's `IR.md`.

### Read the bash history (what did they type?)
```bash
sudo cat /root/.bash_history; sudo tail -50 /home/*/.bash_history
```
Look for `wget`/`curl` downloads, `chmod +x`, things run from `/tmp` or `/dev/shm`, `nc`, edits
to `/etc/passwd`, `/etc/sudoers`, `authorized_keys`, or `crontab -e`.

---

## When you find something
1. **Don't fix it yet.** Copy the log lines into a file (`/root/ccdc/ir-<time>/`) and screenshot them.
2. Note: time, box, attacker IP, account, what happened.
3. Tell the captain, then follow the box's `IR.md` (record → contain → clean up → check → report).
