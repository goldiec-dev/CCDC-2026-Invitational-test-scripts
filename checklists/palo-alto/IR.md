# Palo Alto firewall - incident response checklist

Two jobs: **(A) block an attacker the other boxes found**, and **(B) respond when the firewall itself was changed.**
Every scored service goes through this firewall, so **commit small changes and test the scored services after each commit.**

## A. Blocking an attacker IP (the common case)
- [ ] **Check the IP is not the scoring engine** (team packet) and not one of ours. Blocking the scorer = zero points for everything.
- [ ] Objects → Addresses → add `attacker-<IP>`; Objects → Address Groups → add it to a group called `Blocked-IPs`
      (first time only: create the group and two rules at the **top** of Policies → Security:
      `Block-In`: source `Blocked-IPs`, any destination, deny, log at session end;
      `Block-Out`: any source, destination `Blocked-IPs`, deny, log)
- [ ] Commit. Check Monitor → Traffic for the IP: it should show deny.
- [ ] Scored services still OK (check the scoreboard or test from outside)
- [ ] Note the time and the IP for the report of the box that was attacked

## B. When the firewall itself is changed

### Signs
- Admin login fails with the current password, or there are admin accounts you didn't create
- Scored services drop all at once (rules or NAT changed)
- Monitor → Logs → **Configuration** shows changes or commits nobody on the team made
- Monitor → Logs → **System** shows logins from odd IPs (`auth-success` / `auth-fail`)

### 1. Record - tell the captain
- [ ] Screenshot Monitor → Logs → Configuration (who, when, from which IP, what changed) and Monitor → Logs → System (logins)
- [ ] Device → Config Audit: compare **running config** with your `orig-<date>` snapshot, screenshot the differences
- [ ] Save the current (bad) config as a snapshot `compromised-<time>` for evidence

### 2. Contain
- [ ] Change every admin password: `python3 palo-alto/Palt_User_mang.py` → update → commit (or Device → Administrators)
- [ ] Delete admin accounts you didn't create (screenshot first). Never delete the one you're using.
- [ ] Management interface *Permitted IP Addresses* limited to the inside subnet (Device → Setup → Interfaces → Management)
- [ ] Block the IP the change came from (part A), unless it's ours. If it came from *inside*, the box at that IP is compromised: send that box's team to its IR checklist.

### 3. Fix the config
- [ ] Small change (one rule): put it back by hand from the Config Audit diff, commit, test
- [ ] Big change: Device → Setup → Operations → *Load named configuration snapshot* → your latest **good** snapshot → Commit.
      **Then redo any changes made since that snapshot** (passwords, block rules). Loading old configs can bring back old admin passwords.
- [ ] Save a new good snapshot after it works (`good-<time>`)

### 3b. Recover from a backup
- [ ] Device → Setup → Operations → *Load named configuration snapshot* → `orig-<date>` or the newest `ccdc-before-policy-*` → **Commit**
- [ ] Snapshots deleted from the firewall: *Import named configuration snapshot* → the XML exported by `pa_policy.py`
      (`/root/ccdc/palo-alto/running-*.xml` on the workstation, or fetched from the vault) → load → commit
- [ ] Then: admin passwords again (the restored config has the old hashes), *Expire All API Keys*, and `pa_policy.py apply` if the restored config predates the policy
- [ ] Full procedure: `../BACKUP_AND_RECOVERY.md`

### 4. Check
- [ ] Every scored service works from outside; Monitor → Traffic shows no scored traffic being denied
- [ ] You can still log in with the new password from a new browser session

### 5. Incident report (`Blank Inject Template.docx`)
Time detected and contained · which admin account and source IP made the change · what changed (Config Audit diff screenshot) · actions taken · status · prevention (password changed, management access restricted).
