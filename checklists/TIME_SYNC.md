# Time synchronization: NTP (and PTP where available)

Every box must agree on the time, or logs from different machines can't be lined up during an
incident (and Kerberos/AD logins fail when clocks drift more than 5 minutes).
**Plan: NTP from the team's time server on every box. PTP only where a PTP clock actually exists,
with NTP kept as the backstop.**

Time source: the AD/DNS server (`AD` in `ccdc.conf`) unless the team packet names another.
`fw.sh` already allows UDP 123 out to `AD`.

## Linux - check
```bash
timedatectl                       # "System clock synchronized: yes", "NTP service: active"
chronyc tracking                  # chrony: "Leap status: Normal", small "System time" offset
chronyc sources -v                # the line starting with ^* is the server in use
timedatectl timesync-status       # if the box uses systemd-timesyncd instead of chrony
```

## Linux - configure NTP
**chrony** (Fedora/RHEL/Oracle default; Ubuntu if installed). Config: `/etc/chrony.conf` (Fedora)
or `/etc/chrony/chrony.conf` (Ubuntu). Add near the top, keep the existing `pool`/`server` lines as extra backup:
```
server <AD IP> iburst prefer
```
`sudo systemctl restart chronyd` (Fedora) / `sudo systemctl restart chrony` (Ubuntu), then
`chronyc sources` - expect `^*` next to the AD IP within a minute. Force a step if far off: `sudo chronyc makestep`.

**systemd-timesyncd** (Ubuntu default): edit `/etc/systemd/timesyncd.conf`:
```
[Time]
NTP=<AD IP>
FallbackNTP=ntp.ubuntu.com
```
`sudo systemctl restart systemd-timesyncd && timedatectl set-ntp true`

## Linux - PTP with NTP as backstop (only if a PTP clock exists)
PTP needs either a PTP grandmaster on the network plus a NIC with hardware timestamping, or a
virtual PTP clock from the hypervisor. Check first:
```bash
ls /dev/ptp* && cat /sys/class/ptp/ptp*/clock_name     # e.g. "KVM virtual PTP" / "hyperv"
sudo ethtool -T <interface>                             # hardware timestamping support for network PTP
```
- **Virtual PTP clock (KVM: `sudo modprobe ptp_kvm`; Hyper-V provides one automatically):** add to the
  chrony config, keeping the NTP `server` line above as backstop - chrony uses the best working source:
  ```
  refclock PHC /dev/ptp0 poll 2 prefer
  ```
- **Network PTP grandmaster:** `sudo apt install linuxptp` / `sudo dnf install linuxptp`, run `ptp4l`
  (client only) on the interface and `phc2sys` to set the system clock, or feed the NIC clock to chrony
  with the `refclock PHC` line above. UDP 319/320 must be allowed in the firewall.
- If no PTP clock exists (most competition VMs), **say so in the inject**: NTP is the configured source
  and PTP would be added when a grandmaster or virtual PTP clock is available.

## Windows - check
```powershell
w32tm /query /status          # Source, Last Successful Sync Time, Stratum
w32tm /query /source
w32tm /query /configuration   # which providers are enabled (NtpClient, PtpClient)
```

## Windows - configure NTP
- **Domain-joined:** time comes from the domain: `w32tm /config /syncfromflags:domhier /update`
- **Standalone:**
  ```powershell
  w32tm /config /manualpeerlist:"<AD IP>,0x8" /syncfromflags:manual /update
  Restart-Service w32time
  w32tm /resync /force
  ```
- **PTP:** Windows Server 2019 and Windows 10/11 (1809 and later) include a PTP client in the Windows
  Time service, off by default. Enable it only if a PTP grandmaster exists, following Microsoft's
  "Precision Time Protocol" documentation for Windows Time, and leave the NTP client enabled as the
  backstop. Not tested here - try on a practice VM first.

## Evidence for the inject
`sudo linux/evidence.sh --section time` / `.\windows\evidence.ps1 -Section time` on every box;
screenshot the "synchronized" lines and the source in use.
