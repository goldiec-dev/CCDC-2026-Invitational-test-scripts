# Ubuntu DNS (BIND) - first-hour hardening checklist

> **Not in the 2026 invitational topology** (no such VM in the team pack) - kept for older topologies.

Role in the scripts: **`dns`**. Scored service: **DNS (port 53)**, maybe SSH.
Assume every password on this box is already known to the red team.

## 0. Before touching anything (2 min)
- [ ] **Start tmux first** so nothing dies if SSH drops: `tmux new -s ccdc` (reattach: `tmux a`). Keys and a log-watching layout: `../LINUX_CHEATSHEET.md`
- [ ] Note the box's IP and confirm the role: `ip -br a`, `ss -tulpn` (should show `named` on 53)
- [ ] Prove DNS works *before* you change anything, and save the output to compare later:
      `dig @127.0.0.1 <a scored hostname> +short` (try every record named in the team packet)
- [ ] Back up the DNS config: `sudo cp -a /etc/bind /root/bind-orig` (zone files may also be in `/var/cache/bind` or `/var/lib/bind`)

## 1. Run the scripts
The team captain fills in `ccdc.conf` once (IPs, `SCORED_USERS`, `CONFIG_REVIEWED=yes`) and the same folder goes to every Linux box.

```bash
cd "CCDC Scripts"
sudo bash ./deploy.sh --role dns
```
It asks before each step. On this box the steps are:

| Step | What to do |
|---|---|
| passwords | Type your new password for your own account; everything else gets a random one. **Read the scored users it prints out to the captain right away for the password-change submission.** The CSV is in `/root/ccdc/`. |
| database | Nothing to do on the DNS box (it says so) |
| firewall | Starts at `FIREWALL_LEVEL` (medium). **Within 90 s, from ANOTHER machine, run `dig @<this box> <scored name>`**, then type `yes`. Anything else → it rolls back by itself. |
| scan | Answer each fix. If you're unsure, say **n** and ask; the finding stays in the log. |
| services | Lists what listens and why; disables legacy services (telnet, rsh, tftp, FTP, SNMP, rpcbind...) after asking - never one on a scored port. Shows pending updates for important services; install later with `sudo bash linux/services.sh --update` (one at a time, after testing). |
| webguard | Skipped (not a web box) |
| beacon | Watches outbound connections and alerts on anything calling home on a timer (`journalctl -u ccdc-beacon -f`; table: `sudo bash linux/beacon.sh report`). If a regular connection is legit (e.g. the shop's DB connection), add it to `BEACON_ALLOW` in `ccdc.conf`. |
| fim | Runs last, so the baseline is clean: hashes `/etc`, system binaries, PAM, systemd units, cron and SSH keys, then watches them (`journalctl -u ccdc-fim -f`). **After you change a watched file on purpose** (passwords again, a config edit): `sudo bash linux/fim.sh accept /etc/shadow` (or the file you edited). |

If a step fails, finish the others, then re-run that step alone: `sudo bash ./deploy.sh --role dns --only firewall`

## 2. Check next
- [ ] `dig @<this box> <scored name>` from another machine still answers correctly
- [ ] **Recursion**: in `named.conf.options`, `allow-recursion { 127.0.0.1; <INSIDE subnet>; };`, NOT `any`. Do not turn recursion off if internal boxes use this server as their resolver.
- [ ] **Zone transfers**: `allow-transfer { none; };` (or only the listed secondary). Test: `dig @<this box> <zone> AXFR` from another box should fail.
- [ ] Hide the version: `version "not disclosed";` in options
- [ ] Zone files: compare against `/root/bind-orig`. Look for records you don't recognise or that point at odd IPs; **do not change scored records**.
- [ ] After any BIND edit: `sudo named-checkconf && sudo named-checkzone <zone> <file>`, then `sudo rndc reload` (not restart). Re-test with dig.
- [ ] `sudo grep -r "include" /etc/bind/` - make sure every included file is one you expect
- [ ] SSH: `/etc/ssh/sshd_config` has `PermitRootLogin no` and `PermitEmptyPasswords no`; `sudo sshd -t && sudo systemctl reload ssh`. **Keep your own session open while you test a new one.**
- [ ] Re-run the scan later: `sudo CCDC_ROLE=dns bash linux/audit.sh scan`
- [ ] Once things are stable: `sudo bash linux/fw.sh --role dns --level hard`, test dig again, type `yes`

## Things that lose points - don't
- Don't change the port, the listen address, or any zone record the scorer queries
- Don't `apt upgrade` the whole box during the competition (BIND restarts, config prompts)
- Don't restart `named` while a config is broken; always run `named-checkconf` first
- Don't lock accounts out; change their passwords instead (the scripts already do)
