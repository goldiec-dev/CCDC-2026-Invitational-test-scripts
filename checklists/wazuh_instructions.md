# Wazuh - install and use

Wazuh = a central **manager** (with a web dashboard) plus an **agent** on every box. Agents send
logs, file-integrity changes and inventory to the manager, which alerts on attacks.
It overlaps with Splunk and our own scripts, so it's **optional** - only do it if the
conditions below are met.

## 0. Decide first (captain)
- [ ] **A box for the manager with 4 GB RAM and 2 CPU cores free.** The installer refuses smaller
      boxes. It runs a search database and uses most of that RAM, so **never put it on a box whose
      scored service would suffer.** If no box qualifies, skip Wazuh.
- [ ] The manager box needs these ports free: 1514, 1515, 443 (dashboard - use another port if 443 is
      taken, see `-p` below), 55000 (API).
- [ ] Internet access for the install, or the files pre-downloaded with `installers/download.sh`.
- [ ] Set `WAZUH="<manager IP>"` in `ccdc.conf` **before** running `fw.sh` / `deploy.sh`, so the
      firewall lets agents reach the manager and the beacon detector doesn't flag them.

Versions: agents must be the **same or older** than the manager. The commands below use manager 4.7
and agent 4.7.3. The old `installers/wazuh/wazuh-agent-4.3.10-1.msi` also works with a 4.7 manager.

## 1. Install the manager (all-in-one, on one Linux box)
```bash
cd /root   # needs about 5 GB free disk
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh      # or copy installers/wazuh/wazuh-install.sh
sudo bash wazuh-install.sh -a                                  # -a = manager + database + dashboard on this box
# 443 already used on this box?   sudo bash wazuh-install.sh -a -p 8443   (and set WAZUH_DASHBOARD_PORT=8443)
```
- Takes 5-15 minutes. At the end it prints **User: admin / Password: ...** - write it down and give it
  to the captain.
- Every generated password is also in `wazuh-install-files.tar` in the same folder. Keep it root-only
  and **don't leave it in a web root**: `chmod 600 wazuh-install-files.tar`
- Dashboard: `https://<manager IP>` (or `:8443`). The certificate warning is expected (self-signed).
- Check: `sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard --no-pager | grep -E "●|Active"`
- `audit.sh scan` will list the new listening ports (1514, 1515, 443, 55000, 9200) as unexpected -
  that's Wazuh, not an attacker.
- Install the manager **before** the box's `fim` step, or afterwards run
  `sudo bash linux/fim.sh accept /etc /usr/lib/systemd/system` (it adds services and users).

## 2. Install agents - Linux
`WAZUH_MANAGER` tells the agent where to connect and enroll; nothing else is needed.

**Ubuntu / Debian**
```bash
curl -so wazuh-agent.deb https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.7.3-1_amd64.deb
#   (or use installers/wazuh/wazuh-agent_4.7.3-1_amd64.deb)
sudo WAZUH_MANAGER="<manager IP>" apt-get install -y ./wazuh-agent.deb
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
```
**Fedora / RHEL / Oracle / CentOS**
```bash
curl -so wazuh-agent.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.7.3-1.x86_64.rpm
sudo WAZUH_MANAGER="<manager IP>" rpm -ihv wazuh-agent.rpm
sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
```
Stop it from being upgraded by accident: `sudo apt-mark hold wazuh-agent` (Ubuntu) /
`echo "exclude=wazuh-agent" | sudo tee -a /etc/dnf/dnf.conf` (Fedora).

## 3. Install agents - Windows
In an **Administrator PowerShell**, in the folder with the installer (one line - no `\` line breaks in PowerShell):
```powershell
msiexec.exe /i wazuh-agent-4.7.3-1.msi /qn WAZUH_MANAGER="<manager IP>"
Start-Sleep 10; NET START WazuhSvc
Get-Service WazuhSvc
```
`WAZUH_REGISTRATION_PASSWORD` is only needed if the manager was set up to require one; the
all-in-one install above doesn't. Use the same value on both sides if you add one.

## 4. Check agents are connected
- On the manager: `sudo /var/ossec/bin/agent_control -l` - every box should say **Active**.
- Or the dashboard: **Agents**.
- Agent not showing up?
  - Linux agent: `sudo tail -20 /var/ossec/logs/ossec.log`
  - Windows agent: `Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log' -Tail 20`
  - Usually the firewall: is `WAZUH` set in `ccdc.conf`, and was `fw.sh` re-run after? Test from the
    agent: `nc -zv <manager IP> 1514` (Linux) / `Test-NetConnection <manager IP> -Port 1514` (Windows).

## 5. Settings for all agents at once (optional)
Defaults already collect logs (on Windows: Application, Security, System event logs) and check
files every 12 hours. To check important folders **in real time** on every agent, edit this file
**on the manager** - agents pick it up by themselves within a few minutes:
`/var/ossec/etc/shared/default/agent.conf`
```xml
<agent_config os="Linux">
  <syscheck>
    <frequency>900</frequency>
    <directories realtime="yes" check_all="yes">/etc,/usr/bin,/usr/sbin,/root/.ssh</directories>
    <directories realtime="yes" check_all="yes" report_changes="yes">/var/www</directories>
  </syscheck>
</agent_config>

<agent_config os="Windows">
  <syscheck>
    <frequency>900</frequency>
    <directories realtime="yes" check_all="yes">C:\inetpub\wwwroot</directories>
    <directories realtime="yes" check_all="yes">C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup</directories>
  </syscheck>
</agent_config>
```
Check the file before agents get it: `sudo /var/ossec/bin/verify-agent-conf`.
(File integrity is `<syscheck>` in Wazuh, not `<fim>`. Windows event logs are added with
`<localfile><location>Security</location><log_format>eventchannel</log_format></localfile>` -
Security, System and Application are already on by default. Only add the
`Microsoft-Windows-Sysmon/Operational` channel if Sysmon is actually installed.)

## 6. Using it during the competition
- Dashboard → **Security events**: filter `rule.level >= 10` for the serious alerts.
- **Integrity monitoring**: changed files per agent (same idea as our `fim.sh`, from a second source).
- **Agents → (box) → Inventory**: processes, ports and packages on that box - quick way to spot a
  new listener or an unknown program.

## Don't
- **Don't enable active response** (automatic blocking). It can block the scoring engine.
- Don't put the manager on a scored box that is short on RAM.
- Don't upgrade the manager during the competition; agents must stay the same version or older.
