# VyOS 1.4 router - hardening checklist

| | |
|---|---|
| Interfaces | external `172.31.(20+N).2/29` → competition core (gateway `172.31.(20+N).1`); internal `172.16.0.254/24` → Palo Alto outside `172.16.0.1`; wkst `172.17.0.1/24` → Kali `172.17.0.2` |
| Version | VyOS 1.4.0 |
| Default login | `vyos` (published in the team packet - the red team knows it; paper only: ________ ) |
| Role | **every packet to and from the team passes through it**; it's the first thing the red team reaches; it's Kali's only protection besides Kali itself |
| Scored | ping (keep ICMP up on the router - rule 12); nothing else unless Quotient shows it |

Work from the router's **VM console** (no SSH - step 4 removes the SSH service). VyOS has two modes: operational
(prompt `$`, `show ...`) and configuration (`configure`, prompt `#`, `set` / `delete` / `commit` / `save` / `exit`).
A `set` takes effect only after `commit`, and survives a reboot only after `save`.

**Safety:** for changes typed by hand use `commit-confirm 5`, test, then `confirm` and `save`. If you don't confirm,
VyOS rolls back by **rebooting** into the saved config (the whole team is offline for a minute or two) - test quickly.
The firewall script (step 4) has its own rollback that doesn't reboot. Incident response: `IR.md`.

---

## 0. Before touching anything (3 min)
```
show version
show interfaces
show ip route
show configuration commands | no-more
show configuration commands | no-more > /config/ccdc-start-commands.txt     # text copy, for diffs later
configure
save /config/ccdc-orig.boot          # full copy of the starting config
exit
```
- [ ] Pings from the router: `ping 172.16.0.1 count 2` (Palo Alto), `ping 172.17.0.2 count 2` (Kali), `ping 172.31.<20+N>.1 count 2` (core).
- [ ] The router's backups stay on the router (`/config/*.boot`) - it can't reach the vault through the Palo Alto. Copy the
      lines that matter (interfaces, routes, NAT) onto this paper checklist: that's the off-box copy.
- [ ] NAT and routes now (the team's traffic depends on them - **never change them**):
      `show configuration commands | match nat`, `show configuration commands | match 'protocols static'`
      Write down: source NAT on ________ , destination NAT rules: ________ , default route via ________

## 1. Passwords and users - first 5 minutes
```
configure
set system login user vyos authentication plaintext-password '<new password>'
commit-confirm 5
confirm
save
exit
```
- [ ] Log out and back in on the console with the new password (keep a second console tab open while you do).
- [ ] Other users and keys: `show configuration commands | match 'system login'` - remove anything you didn't add:
      `delete system login user <name>`, `delete system login user vyos authentication public-keys <keyname>`
      (then `commit-confirm 5`, `confirm`, `save`).
- [ ] Password for the captain (not in any CSV). If Quotient shows a router login check, PCR it.

## 2. Services on the router
`show configuration commands | match service`
- [ ] **SSH**: removed by step 4 (we use the console). Keep it only if Quotient shows an SSH check on the router (`--ssh-scored`).
- [ ] REST API / web: `delete service https` (unless the packet uses it).
- [ ] SNMP: `delete service snmp` (community strings are plaintext passwords) unless something documented uses it.
- [ ] LLDP, mDNS repeater, web proxy, monitoring agents, `service ntp allow-client` you didn't see in the starting config → delete.
- [ ] **Keep:** DHCP server, DNS forwarding (`service dns forwarding` - check `allow-from` is only `172.17.0.0/24` and the LAN, not `0.0.0.0/0`), routing, NAT.
- [ ] `commit-confirm 5` → test (ping the Palo Alto, Kali, the core; Quotient green) → `confirm` → `save`.

## 3. Logging and time
```
configure
set system syslog host 172.20.240.20 facility all level info
set service ntp server 172.20.240.100
commit-confirm 5
confirm
save
exit
```
(VyOS 1.4 keeps NTP under `service ntp`; on 1.3 it was `system ntp`. Syslog goes to Splunk's UDP 514 - see `../splunk/HARDENING.md` 3.3.)
- [ ] Login banner (often an inject): `set system login banner pre-login 'Authorized use only. Activity is monitored.'`

## 4. Firewall for the router and Kali (`vyos/vyos_fw.sh`)
They are **not** behind the Palo Alto. On the router console (normal mode), get the scripts (`../GETTING_SCRIPTS.md`,
VyOS section - `curl` and `tar` are there), set the team number in `ccdc.conf`, then:
```bash
bash vyos/vyos_fw.sh            # read what it will do
bash vyos/vyos_fw.sh --apply    # saves the config, applies, commits, 5 minutes to test - no reboot on rollback
```
- [ ] Before: `show configuration commands | match firewall` - existing rules? Our numbers: input 10-50, forward 100-290.
- [ ] Router serves DHCP to Kali (`show configuration commands | match dhcp-server`)? add `--dhcp`.
- [ ] Test before typing `yes`: ping the router from the LAN; from Kali `ping 8.8.8.8`, `curl -I https://github.com`,
      `nslookup github.com`; Quotient all green.
- [ ] Lines listed as `NOT APPLIED` were rejected by this VyOS version - note them; the rest is committed.
- [ ] Undo later: `bash vyos/vyos_fw.sh --undo --apply` (or `configure`, `load /config/ccdc-before-fw-<time>.boot`, `commit`, `save`).
- [ ] No scripts on the router? `bash vyos/vyos_fw.sh` on any Linux box prints the commands to type in configure mode.

| Chain | Allowed | Everything else |
|---|---|---|
| input (to the router) | ping from anywhere; DNS from Kali; BGP/OSPF from the core link; no SSH | dropped, logged |
| forward to Kali | ping | dropped, logged |
| forward from Kali | DNS, NTP, HTTP/HTTPS, our servers (the Palo Alto filters further) | dropped, logged |
| forward, everything else | the LAN's traffic - the Palo Alto's job | accepted |

## 5. Hidden persistence on the router (VyOS is Debian underneath)
Run in normal mode; anything you didn't put there = incident (note it, then remove it).
- [ ] Scheduled commands: `show configuration commands | match task-scheduler`
- [ ] Boot and commit hooks (run as root): `cat /config/scripts/vyos-postconfig-bootup.script`;
      `ls -la /config/scripts/ /config/scripts/commit/pre-hooks.d /config/scripts/commit/post-hooks.d 2>/dev/null`
- [ ] Cron and processes: `sudo crontab -l; ls -la /etc/cron.d`; `ps aux | grep -vE '\[|vyos|frr|systemd'`; `sudo ss -tulpn`
- [ ] Config copied off the box on every commit: `show configuration commands | match commit-archive` → delete unknown locations
- [ ] Fake name resolution: `show configuration commands | match static-host-mapping`; `show configuration commands | match name-server`
- [ ] SSH keys in the shell: `ls -la /home/*/.ssh /root/.ssh 2>/dev/null`

## 6. Check
- [ ] `ping` the Palo Alto, Kali and the core from the router; Kali reaches the internet; Quotient green.
- [ ] `show firewall` - the CCDC rules with packet counters; `show log firewall` (or `sudo journalctl -k | grep -i ipv4-`) for drops.

## 7. Every 30-60 minutes
- [ ] Config unchanged since you saved it:
      `show configuration commands | no-more > /tmp/now.txt; diff /config/ccdc-start-commands.txt /tmp/now.txt`
      (expect only your own changes - new `nat destination` rules, `system login` users, `service` entries = red team)
- [ ] Routes unchanged: `show ip route`
- [ ] Who logged in / committed: `show log | match "login|commit"`
- [ ] Section 5 again

## Things that lose points - don't
- Don't change interface addresses, routes or NAT (it cuts off the whole team; rule: no addressing changes)
- Don't block ICMP to or through the router (rule 12)
- Don't filter the LAN's forwarded traffic here - the Palo Alto does that (a mistake here breaks every service)
- Don't `commit` hand-typed changes without `-confirm`, and don't forget `save`
- Don't reboot the router during scoring without telling the team
