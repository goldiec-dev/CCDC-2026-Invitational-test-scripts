# ClamAV - install and scan

ClamAV is a free antivirus scanner. In CCDC it's a **second opinion**: it knows many webshells,
reverse shells and common malware, so a scan of the web root and temp folders is a quick check.
It does **not** replace `audit.sh` / `audit.ps1`, which catch persistence ClamAV doesn't look for.

**Before you install:**
- **RAM:** scanning loads the signature database into memory: about **1-1.5 GB while a scan runs**.
  On a small box, scan only a few folders and at low priority (commands below). Don't run the
  `clamav-daemon` / `clamd` service on boxes with under 4 GB RAM - it keeps that memory in use all
  the time.
- **Windows** already has Defender scanning in real time (`harden.ps1` turns it on). ClamAV on
  Windows is only for an extra on-demand scan. ClamAV can't scan files as they're opened on
  Windows, so don't plan on "on-access" there.
- **Installers:** the competition VMs are x86-64. Use the `x86_64` / `x64` files - **not**
  `aarch64` / `arm64`, which won't install. `installers/download.sh` gets the right ones.

## Linux - install
**With internet (easiest - distro packages):**
```bash
# Ubuntu / Debian
sudo apt-get update && sudo apt-get install -y clamav
sudo systemctl stop clamav-freshclam      # it locks the database while running
sudo freshclam                            # download signatures (first time takes a minute)
sudo systemctl enable --now clamav-freshclam   # keeps signatures updated

# Fedora / RHEL / Oracle (EPEL needed on RHEL/Oracle: dnf install epel-release)
sudo dnf install -y clamav clamav-update
sudo freshclam
```

**Without internet (our installers):** the official packages install to `/usr/local` and need a
little setup.
```bash
sudo apt-get install -y ./installers/clamav/clamav-1.5.4.linux.x86_64.deb    # Ubuntu/Debian
sudo rpm -ivh installers/clamav/clamav-1.5.4.linux.x86_64.rpm                # Fedora/RHEL
sudo useradd -r -M -s /usr/sbin/nologin clamav 2>/dev/null
sudo mkdir -p /usr/local/share/clamav && sudo chown clamav:clamav /usr/local/share/clamav
sudo sed 's/^Example/#Example/' /usr/local/etc/freshclam.conf.sample | sudo tee /usr/local/etc/freshclam.conf > /dev/null
sudo freshclam          # needs internet - otherwise copy main.cvd, daily.cvd, bytecode.cvd
                        # into /usr/local/share/clamav (get them before the competition with:
                        # pip install cvdupdate && cvd update)
```

Both ways: `freshclam` downloads over HTTPS (443), which `fw.sh` allows.

## Linux - scan
Scan the places attackers drop files, at the lowest priority so scored services aren't slowed:
```bash
sudo mkdir -p /root/ccdc
sudo nice -n 19 ionice -c3 clamscan -r -i \
  --log=/root/ccdc/clamscan-$(date +%H%M).log \
  /var/www /srv /tmp /var/tmp /dev/shm /home /root /etc/cron.d /var/spool/cron
```
- `-r` recurse, `-i` print only infected files. Output lines end in `FOUND`.
- **Never use `--remove`.** Found something? Record it, then quarantine it with
  `sudo bash linux/audit.sh scan --fix` or move it by hand to `/root/ccdc/` - and follow the box's `IR.md`.
- Whole disk (slow, heavy - only on a quiet box):
  `sudo nice -n 19 ionice -c3 clamscan -r -i --exclude-dir='^/(proc|sys|dev|run)' /`

**Scan every 3 hours** and send results to syslog (so Splunk sees `ccdc-clamav`):
```bash
C=$(command -v clamscan)
echo "0 */3 * * * root nice -n 19 ionice -c3 $C -r -i --no-summary /var/www /srv /tmp /var/tmp /dev/shm /home /root 2>/dev/null | logger -t ccdc-clamav" | sudo tee /etc/cron.d/ccdc-clamscan
sudo bash linux/fim.sh accept /etc/cron.d/ccdc-clamscan    # it's ours - stop fim alerting on it
```

## Windows - install (Administrator PowerShell)
```powershell
msiexec.exe /i clamav-1.5.4.win.x64.msi /qn
$C = 'C:\Program Files\ClamAV'
(Get-Content "$C\conf_examples\freshclam.conf.sample") -replace '^Example', '#Example' | Set-Content "$C\freshclam.conf"
& "$C\freshclam.exe"        # download signatures (needs internet)
```
The MSI only installs the programs - there are no services until you add them, and the config file
must be created as above (ClamAV refuses to run while the `Example` line is in it).

## Windows - scan
```powershell
$C = 'C:\Program Files\ClamAV'
& "$C\clamscan.exe" -r -i --log="C:\ProgramData\CCDC\clamscan-$(Get-Date -Format HHmm).log" `
  C:\inetpub C:\Users C:\ProgramData C:\Windows\Temp
```
Results lines end in `FOUND`. Don't use `--remove`; record the finding and follow `checklists/windows/IR.md`.
For real-time protection rely on Defender: `Get-MpComputerStatus | Select RealTimeProtectionEnabled`.

## Check it works (both)
Create the harmless EICAR test file - every antivirus detects it - and scan it:
```bash
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.txt
clamscan /tmp/eicar.txt          # expect: Eicar-Test-Signature FOUND
rm /tmp/eicar.txt
```
On Windows, Defender deletes the test file as soon as it's written. That proves Defender works;
for ClamAV on Windows, just check `freshclam.exe` finished and `clamscan.exe --version` runs.

## Don't
- Don't use `--remove` or `--move` on automatic scans - a false positive on a web app file takes the site down.
- Don't run the `clamd` daemon or on-access scanning (`clamonacc`) on small boxes; it can starve scored services.
- Don't scan the whole disk on a busy box during scoring checks.
