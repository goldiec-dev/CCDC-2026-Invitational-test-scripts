# Initial injects playbook

For each expected initial inject: what to run, what to screenshot, and what the memo should say.
Most "verify" injects are answered by the evidence scripts - run them on **every** box and keep the reports:

```bash
sudo linux/evidence.sh --fim-test --log-test          # Linux, report in /root/ccdc/evidence-<host>-<time>.txt
```
```powershell
.\windows\evidence.ps1 -FimTest -LogTest -Splunk <SPLUNK IP> -Wazuh <WAZUH IP> -Dns <AD IP>   # Windows
```
`--section` / `-Section` runs just one part (system, time, network, firewall, startup, fim, logging, traffic).
Memo templates: `Blank Inject Network Template.docx` (firewall / network items) and `../Blank Inject Template.docx` (the rest).
**Submit as PDF** (Word: Save As PDF; LibreOffice: Export as PDF) - see `../README.md`. Sign as Team #, never the school name.
Every screenshot should show the **hostname and the time** (the evidence report header has both).

---

### 1. Verify startup scripts (integrity checking)
- **Run:** evidence section `startup` on every box. Optional strong proof: reboot one box, run it again.
- **Screenshot:** services/tasks enabled + running; `sha256sum -c` all OK / hash comparison all OK; folder permissions.
- **Memo:** monitors start automatically at boot (systemd services / SYSTEM scheduled tasks), run from
  admin-only folders, their checksums are recorded and verified, and the file integrity monitor alerts on any
  change to them or to how they start. Details and procedure: `checklists/STARTUP_SCRIPTS.md`.

### 2. All devices' firewall policy
- **Run:** evidence section `firewall` on every box; Palo Alto: screenshot Policies → Security and Policies → NAT.
- **Memo (network template):** per device, the default policy (deny inbound / deny outbound on Linux;
  Windows default inbound Block) and the allowed ports with justification (the scored service). Perimeter:
  `../policies/Firewall_Traffic_Flows.docx` has the outside-to-inside table for the Palo Alto and Firepower.
  `linux/fw.sh --role <role> --level <level> --dry-run` prints a box's complete rule set if a full listing is asked for.

**Network view for items 2, 5 and 8:** `linux/portscan.sh --banner` (or `windows\portscan.ps1 -Banner`) from one box
shows which ports are actually reachable on every host - screenshot it next to each host's firewall policy.
Fill in `SCAN_EXPECT` in `ccdc.conf` first so expected ports are labeled and missing ones reported.

### 3. File integrity script - proof it works on every machine
- **Run:** `--fim-test` / `-FimTest` (creates a test file in `/etc` or the hosts-file folder, shows the
  detection, deletes it, shows it clears).
- **Screenshot:** the NEW alert for the test file, then "No changes." Also the `ccdc-fim` / `CCDC-FIM` alert in Splunk.
- **Memo:** what is watched (system configs and binaries, startup locations, SSH keys, our own scripts), how
  often, how alerts reach Splunk, and that evidence copies/diffs are kept for incident reports.

### 4. Profile traffic on Windows and Linux devices
- **Run:** evidence section `traffic` (listening ports with programs, connections grouped by remote address
  and program, beacon report, outbound SSH).
- **Memo:** the expected traffic per box (scored service inbound; DNS, NTP, Splunk/Wazuh, updates outbound) and
  anything unexpected found and what was done about it. Deeper capture: `checklists/TRAFFIC_CAPTURE.md`.

### 5. Verify network connectivity
- **Run:** evidence section `network` (gateway ping, DNS resolution, reachability of DNS/Splunk/Wazuh/internet).
- **Screenshot:** the OK/FAIL lines; also the scored services working from outside (web page, SMTP banner, DNS answer).
- **Memo:** every box reaches its gateway, DNS, log collectors and the scored services are reachable; any FAIL explained.

### 6. Verify centralized logging (Wazuh) - screenshots from every device
- **Run:** evidence section `logging` with `--log-test` / `-LogTest` on every box - it sends a uniquely tagged
  test message and prints the search to use.
- **Screenshot:** Wazuh dashboard → Agents (every box **Active**); the tagged test message found in Wazuh
  (and Splunk) for each box. Setup: `checklists/wazuh_instructions.md`.
- **Time:** see item 7 - servers use NTP, with PTP only where a PTP clock exists (state this explicitly).

### 7. Verify NTP (PTP with NTP as backstop)
- **Run:** evidence section `time` on every box.
- **Screenshot:** "System clock synchronized: yes" + source (`chronyc sources` `^*` line) / `w32tm /query /status` source.
- **Memo:** all boxes sync to the team time server; PTP status (configured where a PTP clock exists, otherwise
  NTP is the source with PTP planned). How-to: `checklists/TIME_SYNC.md`.

### 8. Verify deny-any policy for threat hunting
- **Run:** evidence section `firewall` - shows DROP default policies and the drop-logging rule on each Linux box,
  Block + LogBlocked on Windows, and recent dropped packets. Palo Alto: the bottom deny rule with logging
  (`IN-DENY-LOG` in the traffic-flow document) and Monitor → Traffic filtered on `action eq deny`.
- **Screenshot:** the policy lines, a few logged drops, and Splunk `index=* "CCDC-DROP"` / Palo Alto denied traffic.
- **Memo:** everything not explicitly allowed is denied **and logged**, so blocked attempts can be hunted;
  logs are rate-limited so a flood can't fill the disk.

### 9. Capture traffic - checklist of what to do and on which machine
- **Answer:** `checklists/TRAFFIC_CAPTURE.md` (Palo Alto for north-south and hosts we can't log in to;
  the host itself for process-level detail; ring buffers; hashing for evidence). Attach a short sample capture.

### 10. Detect beaconing
- **Run:** `sudo linux/beacon.sh report` / `.\windows\beacon.ps1 report`; Splunk network-wide search in
  `checklists/splunk/IR.md`.
- **Memo:** method (regular intervals to the same destination, 80% within 25% of the typical gap), coverage
  (every box + Palo Alto logs), results, and actions on anything found.

### 11. How the IT director can detect and remove malware
- **Answer:** `checklists/MALWARE_REMOVAL.md` (detect → record → contain → remove → keep it gone → report).
- **Script asked for:** `linux/outbound_ssh.sh` - lists established TCP connections with their owning process
  (`ss -tnp`), flags outbound SSH by remote port (`SSH_DEFAULT_PORTS`, default 22) or by an `ssh` client process
  on any port, skips allow-listed IPs/CIDRs (optionally with a port), and writes one syslog warning per live
  connection (state file de-duplicates) with timestamp, host, user, PID, program, executable, local and remote
  address and command line. Running at boot as `ccdc-outbound-ssh`. Demo: `ssh` to another box and run
  `sudo linux/outbound_ssh.sh` - screenshot the finding and the `ccdc-outbound-ssh` entry in Splunk.
