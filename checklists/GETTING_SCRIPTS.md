# Getting the scripts onto the competition boxes

USB drives and other media are **not allowed** in the competition. The way in is a **public** team
**GitHub repository**. Printed checklists are allowed.

**Check this first (2026 invitational pack, Internet Usage rule 4):** "Teams may not use any external,
private electronic staging area or FTP site for patches, software, etc. ... All Internet resources used
during the competition must be freely available to all other teams." The pack has no step for registering
a repo URL (older packets had the State Director allow it). A public repo is freely available, but ask the
White Team (captain, before the event, in writing) whether it's allowed. If they say no, use the printed
checklists by hand.

## Before the event (captain)
- [ ] Create the repo with a short name (it has to be typed into VM consoles), e.g. `github.com/<account>/ccdc`.
- [ ] Push this folder. `.gitignore` keeps out: team packets and other PDFs (the rules forbid publishing
      competition details), `installers/` (too big), `old/`, password files and captures.
      **Check nothing secret is in it:** `git ls-files` - no passwords, no team packet, no school name.
- [ ] Make the repo **public** (rule 4: only resources every team could access). The red team can read our
      scripts too - that's acceptable; it must never contain credentials.
- [ ] Get the White Team's OK for using it (see the top of this page) and keep their answer.
- [ ] Print: this page, `README.md`, each machine's `HARDENING.md` / `IR.md`, `LINUX_CHEATSHEET.md`.
- [ ] Practice the download on a VM behind a restrictive proxy.

## On the day - Linux (any box; no git needed)
Type exactly (replace `ACCOUNT`); the console may not support paste:
```bash
cd /root 2>/dev/null || cd ~
curl -L -o c.tgz https://github.com/ACCOUNT/ccdc/archive/refs/heads/main.tar.gz || wget -O c.tgz https://github.com/ACCOUNT/ccdc/archive/refs/heads/main.tar.gz
tar xzf c.tgz && cd ccdc-main
```
If git is installed, `git clone https://github.com/ACCOUNT/ccdc` also works (and only needs github.com).

## On the day - VyOS router (console, logged in as vyos)
VyOS has `curl` and `tar` in its normal (operational) mode:
```bash
cd ~ && curl -L -o c.tgz https://github.com/ACCOUNT/ccdc/archive/refs/heads/main.tar.gz && tar xzf c.tgz && cd ccdc-main
sed -i 's/172\.25\.XX\./172.25.25./' ccdc.conf      # your team number, as below
bash vyos/vyos_fw.sh --apply
```

## On the day - Windows (Administrator PowerShell)
```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
iwr https://github.com/ACCOUNT/ccdc/archive/refs/heads/main.zip -OutFile $env:TEMP\c.zip -UseBasicParsing
Expand-Archive $env:TEMP\c.zip C:\ -Force; Rename-Item C:\ccdc-main C:\CCDC
cd C:\CCDC
```
(`deploy.ps1` unblocks the downloaded scripts itself.)

## If the download fails
- **Proxy needs to be configured explicitly:** check the browser's proxy setting on the workstation, then
  `export https_proxy=http://<proxy>:<port>` (Linux) or add `-Proxy http://<proxy>:<port>` to `iwr`.
- **Archive download blocked but github.com allowed:** use `git clone` on that box.
- **Nothing works:** ask the White Team through the portal (don't waste the first hour) and use the printed
  checklists by hand - every script's key commands are in them.

## Fill in ccdc.conf on each box
The repo copy has `CONFIG_REVIEWED=no` and `EXTERNAL="172.25.XX.0/24"`. With team number N (XX = 20 + N),
e.g. team 5:
```bash
sed -i 's/172\.25\.XX\./172.25.25./; s/^CONFIG_REVIEWED=no/CONFIG_REVIEWED=yes/' ccdc.conf
```
```powershell
(Get-Content ccdc.conf) -replace '172\.25\.XX\.', '172.25.25.' -replace '^CONFIG_REVIEWED=no', 'CONFIG_REVIEWED=yes' | Set-Content ccdc.conf
```
Then add `SCORED_USERS` (from Quotient / the first inject) and check the IPs against this year's packet.
Faster: the captain edits `ccdc.conf` once, commits it, and everyone downloads after that commit.

## Installers (Splunk forwarder, Wazuh, ClamAV)
Not in the repo. On the day, download from the vendor (if the proxy allows it) or install from the OS
package repositories (`apt` / `dnf` - ClamAV, tcpdump, nmap). `installers/download.sh` lists the exact URLs.
