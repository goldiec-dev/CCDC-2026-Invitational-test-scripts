# Capturing traffic: what, where, how

Capture when you need proof or detail that logs don't give: what a suspicious connection carries,
which host started it, or what an attacker sent. Short, targeted captures beat capturing everything.

## Where to capture
| Question | Capture on | Why |
|---|---|---|
| What is crossing between the internet and our servers? Which inside host talks to an attacker? | **Palo Alto** | Sees every packet between zones and to the internet, including hosts we can't log in to |
| What is one suspicious server or workstation doing? | **That host** (tcpdump / pktmon) | Sees its own traffic, including loopback, and lets you match it to a process (`ss -tunap` / `Get-NetTCPConnection`) |
| Is the scoring engine reaching a service? | **The service's host** | Shows whether packets arrive and whether the service answers |

## Before you start
- [ ] Note the time, box, reason and filter you'll use (for the incident report).
- [ ] Check free disk space: `df -h /root` / `Get-PSDrive C`. Use a ring buffer so a capture can't fill the disk.
- [ ] Exclude your own SSH/RDP session so the capture isn't full of yourself.
- [ ] Run it inside tmux (Linux) so it survives a dropped session.

## Palo Alto (web UI)
1. **Monitor → Packet Capture → Manage Filters**: add a filter (source IP, destination IP, port, protocol). Set *Filtering* ON.
2. **Configure Capturing**: add stages *receive*, *firewall*, *transmit* and *drop* (the drop stage shows
   what the firewall blocks), each with a file name. Set *Packet Capture* ON.
3. Reproduce / wait, then turn *Packet Capture* OFF and download the files from the same page.
Always use a filter - unfiltered captures on a busy firewall affect performance. Turn it off when done.

## Linux (tcpdump)
```bash
sudo mkdir -p /root/ccdc/pcap
# everything except your own SSH session, 10 files x 50 MB that rotate (max 500 MB)
sudo tcpdump -i any -nn -s 0 -C 50 -W 10 -w /root/ccdc/pcap/$(hostname -s).pcap 'not (tcp port 22 and host <your IP>)'
# one suspicious address only
sudo tcpdump -i any -nn -s 0 -w /root/ccdc/pcap/suspect-$(date +%H%M).pcap host <IP>
```
Stop with Ctrl-C. Quick look without Wireshark:
```bash
sudo tcpdump -nn -r FILE.pcap | head -50                                        # first packets
sudo tcpdump -nn -r FILE.pcap 'tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0' | awk '{print $5}' | sort | uniq -c | sort -rn | head   # who we connect to
sudo tcpdump -nn -A -r FILE.pcap port 80 | grep -iE 'GET|POST|Host:|User-Agent' | head   # cleartext HTTP
```
No tcpdump? `sudo apt install tcpdump` / `sudo dnf install tcpdump`.

## Windows
**Windows 11 / Windows 10 2004 and later (pktmon):**
```powershell
pktmon filter remove
pktmon filter add -i <IP>                       # optional: only this address
pktmon start --capture --pkt-size 0 --file-name C:\ProgramData\CCDC\capture.etl
#   ... reproduce ...
pktmon stop
pktmon etl2pcap C:\ProgramData\CCDC\capture.etl --out C:\ProgramData\CCDC\capture.pcapng
```
**Server 2019** (its pktmon is older): `netsh trace start capture=yes tracefile=C:\ProgramData\CCDC\capture.etl maxsize=512`
then `netsh trace stop`. The `.etl` file must be converted to pcapng on another machine with Microsoft's
open-source etl2pcapng tool before Wireshark can open it - if Wireshark is allowed on the server, capturing
with Wireshark directly is simpler.
(Not tested here - try both on a practice VM.)

## After capturing
- [ ] Hash it for the evidence trail: `sha256sum FILE.pcap` / `Get-FileHash FILE.pcapng`
- [ ] Copy it off the box to the team machine for Wireshark analysis; keep the original unchanged.
- [ ] Useful Wireshark filters: `tcp.flags.syn==1 && tcp.flags.ack==0` (new connections),
      `dns` (lookups - odd or random-looking names), `http.request` (URLs, webshell requests),
      `ip.addr==<IP>`, Statistics → Conversations (top talkers), Statistics → I/O Graph (regular spikes = beaconing).
- [ ] Delete captures you no longer need - they can contain passwords and customer data.

## What to look for
- The same destination every N seconds (beaconing - `beacon.sh report` finds these too)
- Connections from servers to the internet on unusual ports, or long-lived connections
- Outbound SSH / RDP from servers (`outbound_ssh.sh`)
- DNS queries for long random-looking names (DNS tunneling)
- Cleartext credentials (HTTP basic auth, FTP, Telnet, POP3/IMAP without TLS)
