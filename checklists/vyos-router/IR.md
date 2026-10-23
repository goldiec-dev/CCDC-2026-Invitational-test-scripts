# VyOS router - incident response checklist

## Signs
- Whole team loses scoring at once, or traffic goes somewhere it shouldn't
- Login with our password fails; unknown users/keys; new NAT/port forwards, routes, task-scheduler entries

## Record
- [ ] `show configuration commands | no-more` - photograph/screenshot it; note the time
- [ ] `show log | no-more | match -i "login|sshd|commit"` - who logged in and committed changes, from where
- [ ] `show ip route`, `show nat destination rules`, `show interfaces`

## Contain and fix
- [ ] Change the `vyos` password and delete unknown users/keys (`HARDENING.md` section 1)
- [ ] Restrict or remove SSH (`HARDENING.md` section 2)
- [ ] Undo rogue changes one by one with `delete ...` + `commit-confirm 5` + `confirm`, or restore the
      starting config: `configure`, `load /config/ccdc-orig.boot`, `commit-confirm 5`, test, `confirm`, `save`
      (then redo the password change - the old config has the old password).

## Recover from a backup
- [ ] `configure` → `load /config/ccdc-before-fw-<time>.boot` (before our firewall) or `/config/ccdc-orig.boot` (the starting config) → `compare` →
      `commit-confirm 5` → test → `confirm` → `save`. Then set the `vyos` password again (the old hash came back) and re-run `bash vyos/vyos_fw.sh --apply`.
- [ ] Files in `/config` gone: rebuild from the paper notes / `ccdc-start-commands.txt` printout (interfaces, routes, NAT), then the firewall script.
- [ ] Full procedure: `../BACKUP_AND_RECOVERY.md`

## Check
- [ ] `ping` the Palo Alto (172.16.0.1), Kali (172.17.0.2) and the core; Quotient green for every service

## Report (`../../injects/README.md`)
Source IP and account of the change, timeline, what was changed, impact, how it was undone and how access is now restricted.
