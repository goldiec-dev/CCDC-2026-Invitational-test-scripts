# Cisco FTD - incident response checklist

> **Not in the 2026 invitational topology** (no such VM in the team pack) - kept for older topologies.

## A. Blocking an attacker IP (the common case)
- [ ] **Make sure it isn't the scoring engine** or one of our own addresses.
- [ ] Objects > Networks: add `attacker-<IP>` to a network group `Blocked-IPs`
      (first time: create the group and an access rule at the **top**: source `Blocked-IPs`, action Block, logging on,
      and a second rule with destination `Blocked-IPs` for outbound).
- [ ] Deploy. Check Monitoring > Events / `show conn address <IP>` - no new connections from it.
- [ ] Note the time and IP for the incident report of the attacked host.

## B. When the FTD itself was changed
### Signs
- Scored services on the FTD side drop at the same time; admin login fails; unknown users;
  access rules or NAT you didn't create; changes pending that nobody on the team made.
### Record
- [ ] Screenshot the access control and NAT policies and the user list; note the time.
- [ ] Download a backup of the current (changed) configuration for evidence.
- [ ] CLI: `show running-config` (save the output), `show conn`, `show logging`.
### Contain and fix
- [ ] Change the admin password (CLI `configure password`) and every other user's (`palo-alto/fdm.py`); remove unknown users.
- [ ] Restrict management access to 172.20.240.0/24 (Device > System Settings > Management Access).
- [ ] Undo the rogue rules/NAT by hand and deploy, or restore the backup taken at the start
      (Device > Backup and Restore) - then redo changes made since, starting with passwords.
- [ ] If the change came from an inside address, that machine is compromised - go to its IR checklist.
### Check
- [ ] All FTD-side scored services work from outside; scoring portal is green; `packet-tracer` matches the intended rules.

## Report (`../../injects/README.md`)
Which account and source IP changed what, when (screenshots), what broke, what you restored, how management access is now restricted.
