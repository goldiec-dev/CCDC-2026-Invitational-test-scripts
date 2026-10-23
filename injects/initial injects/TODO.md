- [x] verify startup scripts (integrity checking)
    - should add to checklists to remind us how to setup startup scripts on windows/linux
- [x] all devices' fire wall policy
- [x] file integrity script proof of it working on every machine
- [x] profile traffic on windows and linux devices
- [x] verify network connectivity
- [x] verify centralized logging infrastructure --> use Wazuh.
    - put screenshots from every device
    - servers should be configured for precision time protocol with NTP as back stop 
- [x] verify NTP 
- [x] verify deny-any policy for threat hunting 
- [x] capture traffic (make checklist of what to do to collect traffic and on what machine)
- [x] detect beaconing 
- [x] how it director can detect and remove malware
    - needs a script too that: 
        1.  Lists established TCP connections and the owning process (ss -pt).
        2. Flags as outbound SSH if:
        3. The remote port is in SSH_DEFAULT_PORTS (default 22), or
        4. The process name is ssh and it has an established TCP connection (catches 
        non-standard ports).
        5. Skips anything in your whitelist (single IPs or CIDR ranges with a port).
        6. Writes a single syslog warning per live connection (de-duplicated with a small 
        state file
        7. Logs include: timestamp, host,
    - then need step-by-step instructions to remove malware (and keep it gone)
