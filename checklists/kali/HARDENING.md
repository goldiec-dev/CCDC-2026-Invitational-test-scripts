# Kali workstation - hardening checklist

| | |
|---|---|
| Address | `172.17.0.2/24`, gateway `172.17.0.1` (the VyOS router); outbound shows as 172.31.(20+N).2 |
| OS | Kali Linux (Debian-based, rolling) |
| Default login | `sysadmin` (paper only: ________ ) |
| **Scored** | nothing directly - but it's a **user workstation**: keep it usable, don't re-task it |
| Script role | `workstation` |
| **Exposure** | **NOT behind the Palo Alto** - only its own firewall and the router (`vyos/vyos_fw.sh`) protect it |

Work from the VM console. Kali is also the team's only machine that reaches our servers **the way the scorer does**
(through the router and the Palo Alto, to the public addresses) - use it to test scored services (section 4).
Incident response: Linux steps in `../ecomm/IR.md`.

**Rules:** Kali's tools are for **our own** addresses only - scanning or attacking anything else (other teams, the
competition infrastructure) gets the team disqualified (rule 9). `linux/portscan.sh` refuses addresses that aren't ours.

---

## 0. Before touching anything (3 min)
- [ ] `ip -br a; ip route` → `172.17.0.2`, default via `172.17.0.1`. Write down anything different: ____________
- [ ] `tmux new -s ccdc`
- [ ] What runs now (Kali normally runs **no** network services):
      ```bash
      sudo ss -tulpn; systemctl list-unit-files --state=enabled --type=service,socket | grep -v '@'
      sudo mkdir -p /root/start && sudo bash -c 'ss -tulpn > /root/start/ss.txt; ps auxwwf > /root/start/ps.txt; getent passwd > /root/start/passwd.txt'
      ```

## 1. Passwords - first 5 minutes
- [ ] Get the scripts (`../GETTING_SCRIPTS.md` - the Linux commands work on Kali), team number in `ccdc.conf`.
- [ ] `cd ~/ccdc-main && sudo bash ./deploy.sh --role workstation --skip fim`
- [ ] `passwords` step: every account with a password (`sysadmin`, `kali` if it exists, root if it has one).
      Check root: `sudo passwd -S root` → `L` (locked) is the Kali default and fine.

## 2. The rest of the deploy steps
| Step | What to watch for |
|---|---|
| firewall | Only ping in; out: DNS, NTP, web, and Splunk/our servers. Kali ships `iptables` (nft backend). Test `curl -sI https://github.com` before `yes`. |
| secure | Offers to stop `sshd` → yes (console only; nothing should reach Kali). |
| cis | CIS Level 1 baseline not covered elsewhere: kernel/network parameters, unused modules, `/dev/shm`, core dumps, file permissions, cron, banners, sudo/su, auditd. Asks per section; anything that could hurt scoring is report-only (`../CIS.md`). |
| scan / services | **Noisy on Kali** - hacking tools look like attacker tools. Fix only what's clearly not Kali's own (files in `/tmp`, `/dev/shm`, cron jobs, new users, `authorized_keys`). |
| forwarder | Splunk forwarder → `172.20.240.20:9997` (allowed through the router and the Palo Alto `CCDC-in-kali-splunk` rule). First `ping -c1 172.20.240.20`: if the router has no route to the LAN's private addresses, skip this step - don't add routes (rule: no changes to the addressing scheme). |
| beacon | Outbound-connection watcher. |

## 3. Manual hardening
### 3.1 Services that Kali can start (all off)
- [ ] Turn off anything enabled or listening that a workstation doesn't need:
      ```bash
      for s in ssh apache2 nginx postgresql smbd nmbd xrdp vsftpd tftpd-hpa mysql mariadb redis-server; do
        systemctl is-enabled --quiet $s 2>/dev/null || systemctl is-active --quiet $s 2>/dev/null && sudo systemctl disable --now $s && echo "disabled $s"
      done
      sudo ss -tulpn          # expect nothing on 0.0.0.0 / * (except a DHCP client)
      ```
- [ ] Leftover listeners from tools (`nc -l`, `python3 -m http.server`, `msfconsole` handlers, `responder`): `sudo ss -tulpn` → `sudo kill <pid>` for anything nobody on the team started.

### 3.2 Accounts and sudo
- [ ] Only root has UID 0: `awk -F: '$3 == 0' /etc/passwd`
- [ ] Login accounts vs `/root/start/passwd.txt`: `awk -F: '$7 !~ /(nologin|false)$/' /etc/passwd` → unknown: `sudo usermod -L -e 1 <user>`
- [ ] sudo: `getent group sudo`; `sudo ls -la /etc/sudoers.d/` - Kali may ship `kali-grant-root` (passwordless sudo for the `kali-trusted` group): `getent group kali-trusted` → should be empty.
- [ ] SSH keys: `sudo find /root /home -name authorized_keys -ls`

### 3.3 Persistence spots
- [ ] Cron: `sudo crontab -l; ls -la /etc/cron.* /var/spool/cron/crontabs 2>/dev/null`
- [ ] Autostart (Xfce): `ls -la ~/.config/autostart /etc/xdg/autostart 2>/dev/null`
- [ ] systemd units added recently: `ls -lt /etc/systemd/system /lib/systemd/system | head`
- [ ] Shell startup files: `grep -nE 'curl|wget|nc |bash -i|/dev/tcp|base64' ~/.bashrc ~/.zshrc ~/.profile /home/*/.zshrc 2>/dev/null` (Kali uses zsh)

### 3.4 CIS baseline (deploy step `cis`)
Kernel/network parameters, unused modules, core dumps, permissions, banners, sudo/su, auditd: `linux/cis.sh --fix`
(the deploy's `cis` step). Kali needs IP forwarding off too - `sysctl net.ipv4.ip_forward` → `0` (`cis.sh` sets it
unless a container engine runs).

### 3.5 Router side (the second layer for Kali)
- [ ] The router firewall is applied (`../vyos-router/HARDENING.md` step 4): from Kali `ping 172.17.0.1` works; nothing
      from outside reaches Kali (new inbound connections to `172.17.0.0/24` are dropped except ping).

### 3.6 Updates and screen
- [ ] Never `apt upgrade` Kali during the competition (rolling release = thousands of packages).
- [ ] Screen lock on (Xfce: Settings → Light Locker / Screensaver).

### 3.7 Take the baseline and back up (last)
- [ ] `sudo bash ./deploy.sh --role workstation --only fim`
- [ ] Backup: `sudo bash linux/backup.sh --role workstation`. Off-box push won't work from here - Kali is outside the Palo
      Alto, and the vault's port isn't open to the outside (on purpose). The on-box copy is enough for a workstation.

## 4. Test our scored services like the scorer (Kali's main job)
From Kali, the public addresses go through the router and the Palo Alto - exactly the scorer's path. N = team number.
```bash
P=172.25.$((20+N))
curl -sIL http://$P.10/ | grep -E '^HTTP|^Location'       # E-com: 302 -> https -> 200
curl -skI https://$P.10/ | head -1
printf 'EHLO kali\r\nQUIT\r\n' | nc -w3 $P.15 25          # Email SMTP
printf 'QUIT\r\n' | nc -w3 $P.15 110; printf 'a LOGOUT\r\n' | nc -w3 $P.15 143
curl -skL http://$P.15/ | grep -ci roundcube              # webmail
curl -s -o /dev/null -w '%{http_code}\n' http://$P.20:8000/            # Splunk web
curl -sk -o /dev/null -w '%{http_code}\n' https://$P.20:8089/services/server/info   # 401 = up, wants a login
dig @$P.100 <scored name> +short                          # DNS
nc -zv $P.100 5985; nc -zv $P.120 445; nc -zv $P.120 1433; nc -zv $P.120 3389
for h in 10 15 20 100 120; do ping -c1 -W1 $P.$h > /dev/null && echo "$P.$h up" || echo "$P.$h NO PING"; done
```
What else is reachable from outside (should be only the scored ports):
`sudo bash linux/portscan.sh $P.0/24 --ports common` (our range only - the script refuses others).

## 5. Every 30-60 minutes
- [ ] Section 4 again (a quick outside view of every service)
- [ ] `sudo ss -tulpn` - still nothing listening; `who; last -Fi | head`

## Things that lose points - don't
- Don't point any tool at an address that isn't ours (disqualification)
- Don't re-task it (no servers, no relays, no proxies for other boxes)
- Don't change its address, gateway or the router's routes / NAT
