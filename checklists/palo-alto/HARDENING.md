# Palo Alto firewall (PAN-OS 11.0.2) - hardening checklist

| | |
|---|---|
| Interfaces | inside `172.20.240.254/24` (the LAN), outside `172.16.0.1/24` (to the VyOS router `172.16.0.254`) |
| Management | `https://172.20.240.200` (`PA_MGMT` in `ccdc.conf`) from the Ubuntu or Windows workstation; CLI on the VM console |
| Default login | `admin` (published in the team packet - the red team knows it; paper only: ________ ) |
| Protects | **every server** - all scored services pass through it |
| Not covered by it | traffic between LAN hosts (same subnet - host firewalls do that), the router and Kali (outside it) |

Rule of thumb: **add and tighten, don't delete; commit small changes; test the scored services after every commit.**
Tools: `palo-alto/Palt_User_mang.py` (admin passwords) and `palo-alto/pa_policy.py` (the allow-list). Incident response: `IR.md`.

---

## 0. Before touching anything (5 min)
- [ ] Log in to the web UI; Dashboard → General Information: PAN-OS version ________, serial, uptime.
- [ ] **Save and export the starting config:** Device → Setup → Operations → *Save named configuration snapshot*
      (`orig-<date>`) → *Export named configuration snapshot* (keep the file on the workstation, in `~/ccdc-palo-alto/` -
      the workstation's off-box push includes that folder; `pa_policy.py apply` exports there too).
- [ ] Screenshot **Policies → Security**, **Policies → NAT**, **Network → Interfaces**, **Network → Zones** - you need them if something breaks and for spotting red team changes later.
- [ ] Every scored service works now (Quotient all green, or section 4 from Kali) - so you know any later break is yours.
- [ ] Pending changes nobody committed? Top right "Commit" shows a count → Config → *Revert Changes* unless they're the team's.

## 1. Passwords and administrators - first 5 minutes
- [ ] From the Ubuntu workstation (Python 3 is there; no `pip` needed for the policy tool, `requests` for this one):
      ```bash
      cd ~/ccdc-main/palo-alto && python3 Palt_User_mang.py      # firewall IP 172.20.240.200, admin, current password
      ```
      1 = list users → 2 = new password for `admin` and **every** other admin (14+ characters) → 4 = commit.
      (No Python? Web UI: Device → Administrators → each user → Password.)
- [ ] Log in again with the new password **in a new browser tab before closing the old one**.
- [ ] Admins nobody recognises: Device → Administrators → note them, ask the captain, delete (never the one you're using).
- [ ] **Expire old API keys** (someone with the old password may have generated one): Device → Setup → Management →
      Authentication Settings → *Expire All API Keys* → commit. (`pa_policy.py` asks for the password and gets a fresh key each run.)
- [ ] Other ways in: Device → Local User Database (users/groups), Device → Authentication Profile, Device → Admin Roles -
      anything not in the starting config = incident.
- [ ] Give the new passwords to the captain (they aren't in any CSV).

## 2. The allow-list policy (`pa_policy.py`)
```bash
cd ~/ccdc-main
python3 palo-alto/pa_policy.py plan      # read-only: zones, NAT, current rules, the rules it would add
python3 palo-alto/pa_policy.py apply     # backup + snapshot, rules at the top, commit, 5 min to confirm
python3 palo-alto/pa_policy.py verify    # in a 2nd terminal right after the commit, then every 30 min
```
- [ ] **Read `plan` first.** It finds the inside/outside zones from the interface addresses (stops if `ccdc.conf` doesn't
      match) and lists the NAT rules. No NAT here for the servers = the VyOS router does it - fine, every rule matches the
      private and the public address.
- [ ] `apply`, then within 5 minutes: **Quotient - every service up?** and `verify` - lines marked `SCORER?` are drops to
      one of our servers (probably a check on a port we didn't list). No `yes` = automatic rollback to the snapshot.
- [ ] A check down after confirming → add the port to `PA_INBOUND` in `ccdc.conf` → `apply` again (it replaces its own rules).

What it allows (everything else between outside and inside is dropped and logged):

| Direction | Allowed |
|---|---|
| In → E-com .10 | tcp 80, 443 (+22 while `SSH_SCORED=yes`) |
| In → Email .15 | tcp 25, 80, 110, 143, 443, 465, 587, 993, 995 (+22) |
| In → Splunk .20 | tcp 8000, 8089 (+22) |
| In → AD .100 | tcp/udp 53, tcp 5985, 5986 |
| In → MSSQL .120 | tcp 445, 1433, 3389 |
| In → every server | ping (rule: keep ICMP up; ping is scored) |
| Kali → Splunk / AD | tcp 9997 (forwarder), udp 123 (time) |
| LAN → out | DNS, NTP, HTTP/HTTPS (updates, downloads, Nextcloud), ping; Email also SMTP 25 |

It also: puts a **ping-only** management profile on the outside interface (and the inside one, since you manage through
`.200`), limits management access to the LAN, and turns the management port's SSH / Telnet / HTTP off (HTTPS stays).
Source is always **any** (rule 9: public services stay open to every address).

**API not working?** `python3 palo-alto/pa_policy.py cli` prints the same change as CLI commands to type on the VM
console (`configure`, the lines, `commit`) - save a snapshot first.

## 3. Manual hardening (commit after each group; test the scored services)
### 3.1 Management plane
- [ ] Device → Setup → Interfaces → Management: *Permitted IP Addresses* = `172.20.240.0/24`; services: **HTTPS only**,
      plus ping (`apply` does both - check).
- [ ] CIS PAN-OS items (`../CIS.md`): Device → Setup → Management → **Minimum Password Complexity** on (14+ characters,
      upper/lower/number/special); **Login Banner** = the text of `../motd-banner.txt`; Device → Setup → Services →
      **Verify Update Server Identity** on; SNMP v3 only or off.
- [ ] Device → Setup → Management → Authentication Settings: *Idle Timeout* 15 min. Leave *Failed Attempts* / lockout
      **off** or high - the red team could lock out `admin`.
- [ ] Network → Network Profiles → Interface Mgmt: every profile on the **outside** interface = ping only (`CCDC-ping-only`).
      Profiles allowing HTTPS/SSH/Telnet/SNMP on any data interface: remove those services (you manage through `.200`).
- [ ] Device → Setup → Services: DNS and NTP servers - unknown addresses (red team redirecting lookups/time) → back to the start values.
- [ ] Known PAN-OS 11.0.2 problems - both need access to the firewall's own web/VPN pages, which the steps above take away:
      - **CVE-2024-0012 / CVE-2024-9474** (management web interface login bypass → root): fixed by *Permitted IP
        Addresses* + no web management on data interfaces.
      - **CVE-2024-3400** (GlobalProtect, unauthenticated root command injection): Network → GlobalProtect → Portals /
        Gateways - **configured on the outside interface?** Not part of any scored service → tell the captain; removing the
        portal/gateway from the interface closes it (snapshot first).
      Upgrading PAN-OS during the competition isn't realistic (reboot, downtime).

### 3.2 Security policy beyond the allow-list
- [ ] The old allow-any rules are still there, below the CCDC drop rules (shadowed for outside↔inside). Leave them - fewer surprises.
- [ ] Any rule **above** `CCDC-block-in` that someone adds later = red team or a mistake: check Policies → Security every 30 min.
- [ ] Security profiles (antivirus / anti-spyware / vulnerability protection) if the lab has threat licences (Device →
      Licenses): attach the `default` profiles to the `CCDC-in-*` rules with action **alert** first; switch to block only
      after watching Monitor → Threat for false positives on scored traffic.

### 3.3 Zone protection (outside zone)
- [ ] Network → Network Profiles → Zone Protection → Add `CCDC-outside`:
      - **Packet Based Attack Protection** → IP Drop: *Spoofed IP address*, *Strict IP Address Check*, *Malformed*; TCP Drop: *Mismatched overlapping TCP segment*
      - **Reconnaissance Protection**: TCP/UDP port scan and host sweep → action **alert** (not block - the scorer polls many ports)
      - **Flood Protection**: leave off (could drop the scorer under load)
      Network → Zones → the outside zone → Zone Protection Profile = `CCDC-outside` → commit → test scored services.

### 3.4 Logging to Splunk
- [ ] Device → Server Profiles → Syslog → Add `Splunk`: server `172.20.240.20`, UDP 514, format BSD.
- [ ] Objects → Log Forwarding → Add `CCDC-to-Splunk`: Traffic, Threat → syslog profile `Splunk`.
- [ ] Policies → Security → select the `CCDC-*` rules → Actions → Log Forwarding = `CCDC-to-Splunk`.
- [ ] Device → Log Settings → **System** and **Configuration** → add a match list sending to `Splunk` - every config change
      and admin login then lands in Splunk (catches red team changes).
- [ ] Commit; Splunk: `index=* host=172.20.240.200 OR sourcetype=pan* earliest=-10m` (or whatever the syslog input calls it).

### 3.5 Things the red team changes on firewalls (compare with your screenshots)
- [ ] **NAT rules** - new destination-NAT / port forwards (a backdoor straight in)
- [ ] Security rules - new allow rules above ours, rules with source = an outside IP
- [ ] Administrators, admin roles, authentication profiles, Local User Database
- [ ] Interface management profiles (web/SSH opened on the outside)
- [ ] Device → Certificate Management (rogue CA certificates), Device → Scheduled Log Export (log exfiltration)
- [ ] Monitor → Logs → **Configuration**: every change with admin name, source IP and time - anything not from the team = incident report.
      Device → Config Audit: compare *running config* with the `orig-<date>` snapshot.

## 4. Check the scored services (from Kali - outside the firewall, like the scorer)
See `../kali/HARDENING.md` section 4 (one block tests every service through the router and this firewall).
`python3 palo-alto/pa_policy.py verify` afterwards - nothing marked `SCORER?`.

## 5. Every 30 minutes
- [ ] `python3 palo-alto/pa_policy.py verify`
- [ ] Monitor → Logs → Configuration (new changes?) and System (admin logins from where?)
- [ ] Monitor → Traffic, filter `( action neq allow ) and ( zone.dst eq <inside zone> )`; Monitor → Threat
- [ ] Policies → Security / NAT unchanged; Device → Administrators unchanged
- [ ] An attacking address (never the scorer - check Quotient's source first): `python3 palo-alto/pa_policy.py block <IP>`

## Undo
Device → Setup → Operations → *Load named configuration snapshot* → `orig-<date>` (or `ccdc-before-policy-*`) → Commit.
Uncommitted mistakes: Config → *Revert Changes*.

## Things that lose points - don't
- Don't change or delete **NAT rules**, interface IPs, zones or virtual routers
- Don't restrict scored services to the scorer's address (rule 9 - penalty) or block ICMP (rule 12)
- Don't commit a big batch of changes at once; if something breaks, you won't know which one did it
- Don't turn on flood protection or threat-prevention *block* actions on scored rules without watching the logs first
- Don't factory-reset, upgrade PAN-OS, or load a config from a previous year (`palo-alto/configs/*.xml` are reference only)
