# Cisco FTD 7.2 (Firepower) - first-hour hardening checklist

> **Not in the 2026 invitational topology** (no such VM in the team pack) - kept for older topologies.

2026: management `172.20.240.200` (inside), inside `172.20.240.254/24`, outside `172.16.102.254/24` to the VyOS router.
It protects the **AD/DNS, Web, FTP and Windows 11** machines, so every scored service on that side goes
through it. Rule of thumb: **add and tighten, don't delete; deploy small changes and test after each.**
Outside-to-inside rules and NAT: `../../injects/policies/Firewall_Traffic_Flows.docx` (FTD table).
The default admin password is printed in the team packet - change it first.

## 0. Before touching anything (3 min)
- [ ] Open the web UI (FDM) from the **Windows 11 workstation**: `https://172.20.240.200`
      (the 2026 packet also lists `https://172.20.102.254` - try both). CLI: the FTD console in NETLAB.
- [ ] **Back up the configuration:** Device > Backup and Restore > Manual Backup (back up now), then download it.
- [ ] Screenshot Policies > Access Control and Policies > NAT.
- [ ] Check every scored service on the FTD side works from outside (scoring portal + a manual test).

## 1. Passwords and users
- [ ] Change the admin password: CLI `configure password`, or in FDM the user menu (top right) > Profile > Password.
- [ ] List and update users with `palo-alto/fdm.py` (FDM API) from a machine that can reach the management IP:
      `python3 palo-alto/fdm.py` > list users > change passwords > remove unknown admins > deploy.
- [ ] Log out and back in with the new password **before** closing your working session.

## 2. Management access
- [ ] Device > System Settings > Management Access: allow HTTPS and SSH **only from 172.20.240.0/24**
      (add your own workstation's address first). No management from the outside interface.
- [ ] Check the FTD answers ping on its interfaces (rule: keep ICMP up).

## 3. Access control and NAT (Policies)
- [ ] Default action: **Block all traffic**, logging on.
- [ ] Rules for each scored service (FTD table): DNS to 172.20.240.102, HTTP/HTTPS to 172.20.240.101, FTP to
      172.20.240.104, ICMP to all four hosts. FTD rules match the **real (internal) IP**.
- [ ] Broad "allow any" rules: narrow or move a block rule above them - one change and deploy at a time.
- [ ] Internal flows that must cross both firewalls (traffic-flow document): AD (LDAP/Kerberos/DNS/NTP) for the
      Palo Alto-side boxes, logs to Splunk (TCP 9997, UDP 514) at 172.20.242.20.
- [ ] NAT: static auto-NAT per server to its 172.25.(20+N).x address - **don't change** public addresses.
- [ ] Intrusion policy on the allow rules (e.g. Balanced Security and Connectivity). FTP inspection stays on.
- [ ] Logging: Objects > Syslog Servers > add `172.20.242.20` UDP 514; select it in each rule's logging settings.
- [ ] **Deploy** (top right) after each group of changes, then test the scored services.

## 4. Verify
- [ ] CLI: `show nat`, `show access-list`, `show conn`, `packet-tracer input outside tcp 198.51.100.10 40000 172.25.(20+N).140 80`
- [ ] From the Linux side: `linux/portscan.sh 172.20.240.0/24 --banner` - only the intended ports open

## Things that lose points - don't
- Don't change interface addresses, NAT public addresses or routing
- Don't block ICMP to the hosts or the FTD's interfaces
- Don't deploy a large batch of changes at once; don't put IPS in a blocking mode on scored rules without testing
- Don't block the scoring engine - check the source IP of denied scored traffic before adding blocks
