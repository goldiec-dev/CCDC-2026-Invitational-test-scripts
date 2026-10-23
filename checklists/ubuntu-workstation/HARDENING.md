# Ubuntu desktop workstation - hardening checklist

| | |
|---|---|
| Address | DHCP on the LAN (172.20.240.x); no public address of its own (outbound shows as 172.31.(20+N).2) |
| OS | Ubuntu desktop (GNOME) |
| Default login | `sysadmin` (paper only: ________ ) |
| **Scored** | nothing directly (nothing outside can reach it) - but it's a **user workstation**: keep it usable, don't re-task it |
| Script role | `workstation` |
| Also | the recommended console for the **Palo Alto web UI** (`https://172.20.240.200`) and Splunk (`http://172.20.240.20:8000`) |

Work from the VM console. The Kali workstation has its own checklist: `../kali/HARDENING.md`.
Incident response: Linux steps in `../ecomm/IR.md` (record → contain → clean up) and `../LINUX_CHEATSHEET.md`.

---

## 0. Before touching anything (3 min)
- [ ] Terminal: `ip -br a` → DHCP address: ____________ (it can change after a reboot)
- [ ] Firefox: Palo Alto UI and Splunk open (your tools - check before changing anything).
- [ ] `tmux new -s ccdc`
- [ ] What it looks like now:
      ```bash
      sudo mkdir -p /root/start && cd /root/start
      sudo bash -c 'ss -tulpn > ss.txt; ps auxwwf > ps.txt; getent passwd > passwd.txt
        systemctl list-unit-files --state=enabled > enabled.txt; last -Fi > last.txt'
      ```

## 1. Passwords - first 5 minutes
- [ ] Scripts (`../GETTING_SCRIPTS.md` - this box is usually the first to download them), team number in `ccdc.conf`.
- [ ] `cd ~/ccdc-main && sudo bash ./deploy.sh --role workstation --skip fim`
- [ ] `passwords` step: every account including the desktop user (you type yours - you'll need it for the screen lock).

## 2. The rest of the deploy steps
| Step | What to watch for |
|---|---|
| firewall | Nothing inbound but ping (no SSH - workstations can't be scored for it); outbound DNS/NTP/AD, web, Splunk web and the Palo Alto UI. **Open the Palo Alto UI before typing `yes`.** |
| secure | Offers to stop `sshd` (we use the console; nothing outside can reach it anyway) → yes. |
| cis | CIS Level 1 baseline not covered elsewhere: kernel/network parameters, unused modules, `/dev/shm`, core dumps, file permissions, cron, banners, sudo/su, auditd. Asks per section; anything that could hurt scoring is report-only (`../CIS.md`). |
| scan / services | Desktop extras (CUPS, Avahi) get flagged - disabling them is fine here. |
| forwarder | Splunk forwarder → `172.20.240.20:9997`. |
| beacon | Outbound-connection watcher. |

## 3. Manual hardening
### 3.1 Accounts and sudo
- [ ] Only root has UID 0: `awk -F: '$3 == 0' /etc/passwd`
- [ ] Login accounts: `awk -F: '$7 !~ /(nologin|false)$/' /etc/passwd` vs `/root/start/passwd.txt` → unknown: `sudo usermod -L -e 1 <user>`
- [ ] sudo: `getent group sudo admin`; `sudo ls -la /etc/sudoers.d/`; `NOPASSWD` lines you didn't expect = incident
- [ ] Guest / auto-login off: `grep -rE 'AutomaticLoginEnable|TimedLoginEnable' /etc/gdm3/custom.conf` → `false` or absent

### 3.2 Remote access and sharing (GNOME)
- [ ] Settings → Sharing: **Screen Sharing / Remote Desktop / Remote Login / Media Sharing all off**
      (or `gsettings set org.gnome.desktop.remote-desktop.rdp enable false; gsettings set org.gnome.desktop.remote-desktop.vnc enable false`)
- [ ] Remote-desktop services: `systemctl list-units --type=service | grep -Ei 'xrdp|vnc|remote|teamviewer|anydesk'` →
      `sudo systemctl disable --now <unit>`
- [ ] `sshd`: `systemctl is-active ssh` → `inactive` after `secure` (otherwise `sudo systemctl disable --now ssh`)

### 3.3 Unneeded services
- [ ] `systemctl list-unit-files --state=enabled --type=service,socket` vs `/root/start/enabled.txt`
- [ ] Off on this box: `sudo systemctl disable --now cups cups-browsed avahi-daemon 2>/dev/null` (no printing in the competition)
- [ ] `sudo ss -tulpn` afterwards: nothing listening on `0.0.0.0` / `*` except DHCP client and maybe `systemd-resolved` on 127.0.0.53

### 3.4 Persistence spots
- [ ] Desktop autostart: `ls -la ~/.config/autostart /etc/xdg/autostart /home/*/.config/autostart 2>/dev/null` - anything you don't recognise
- [ ] Cron: `sudo crontab -l; crontab -l; ls -la /etc/cron.* /var/spool/cron/crontabs 2>/dev/null`
- [ ] User systemd units: `systemctl --user list-unit-files --state=enabled; ls ~/.config/systemd/user 2>/dev/null`
- [ ] Shell startup files: `grep -nE 'curl|wget|nc |bash -i|/dev/tcp|base64' ~/.bashrc ~/.profile /home/*/.bashrc /etc/profile.d/* 2>/dev/null`
- [ ] Firefox: Add-ons (`about:addons`) - remove unknown ones; don't save firewall / Splunk passwords.

### 3.5 CIS baseline (deploy step `cis`)
Kernel/network parameters, unused modules, core dumps, permissions, banners, sudo/su, auditd: `linux/cis.sh --fix`
(the deploy's `cis` step, asks per section). Report: `sudo bash linux/cis.sh`. Skipped on purpose: `../CIS.md`.

### 3.6 Screen and updates
- [ ] Screen lock on: Settings → Privacy → Screen Lock → blank after 5 min, lock on (team members walk away from it)
- [ ] Automatic updates are on by default (`systemctl list-timers apt-daily-upgrade.timer`) - fine on a workstation.
      Never a full `apt upgrade` by hand during the competition.

### 3.7 Take the baseline and back up (last)
- [ ] `sudo bash ./deploy.sh --role workstation --only fim`
- [ ] **Backup of the hardened box, then off the box:** `sudo bash linux/backup.sh --role workstation` → at the next vault
      window (the captain calls it) `sudo bash linux/offbox.sh push --include /root/ccdc/palo-alto --include /home/<you>/ccdc-palo-alto` (team backup passphrase, then the window password).
      The `--include`s carry the Palo Alto config exports `pa_policy.py` made on this box off-box too.

## 4. Check
- [ ] Palo Alto UI and Splunk still load; `ping 172.20.240.100` works; the internet works (`curl -sI https://github.com | head -1`)

## 5. Every 30-60 minutes
- [ ] `sudo bash linux/audit.sh scan`; alerts: `sudo journalctl -t ccdc-fim -t ccdc-beacon --since -1h`
- [ ] `who; last -Fi | head`; new autostart entries / cron jobs (3.4)

## Things that lose points - don't
- Don't use it as a server (workstations can't be re-tasked)
- Don't change its network settings (DHCP)
- Don't lock the team out of the Palo Alto UI with the host firewall - test before confirming
