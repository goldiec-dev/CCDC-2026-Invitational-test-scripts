# CIS Benchmarks - what we cover, where, and where we deliberately differ

The CIS Benchmarks (Level 1) for Rocky Linux 9, Ubuntu 22.04, Debian 12, Windows Server 2022 / 2019 and Windows 11,
mapped onto our scripts. `linux/cis.sh` / `windows/cis.ps1` (deploy step `cis`) cover what the other steps don't;
both report PASS/FAIL per control and fix only after asking. Handy for "show us your hardening baseline" injects:
run the report, attach the output.

```bash
sudo bash linux/cis.sh                 # report
sudo bash linux/cis.sh --fix           # fix, asking per section   (--section sysctl --section perms ...)
```
```powershell
.\windows\cis.ps1 -Role dc             # report        .\windows\cis.ps1 -Role mssql -Fix
```

## Linux
| CIS area | Covered by |
|---|---|
| 1.1 unused filesystems, /dev/shm and /tmp mount options | `cis.sh` modules, mounts |
| 1.2 package signatures, 1.9 updates | `cis.sh` packages; `services.sh` (pending updates for exposed services) |
| 1.3 file integrity (AIDE) | `fim.sh` (our equivalent: hashes /etc, binaries, PAM, systemd, cron, keys) + `webguard.sh` |
| 1.4 bootloader config permissions | `cis.sh` perms |
| 1.5 ASLR, ptrace, core dumps | `cis.sh` sysctl, coredump |
| 1.6 SELinux / AppArmor | `cis.sh` mac (report) |
| 1.7 warning banners | `cis.sh` banner (text: `motd-banner.txt`) |
| 2.1-2.2 unneeded services / servers | `services.sh` (telnet, rsh, tftp, FTP, SNMP, NFS, avahi, cups, rpcbind, ...) |
| 2.3 unneeded clients | `cis.sh` packages |
| 3.1-3.3 network parameters | `cis.sh` sysctl |
| 3.4 uncommon network protocols | `cis.sh` modules |
| 3.5 host firewall | `fw.sh` (default-deny both ways, scored ports only) |
| 4.1 auditd and rules | `cis.sh` logging |
| 4.2 journald / rsyslog, logs off the box | `cis.sh` logging; `forwarder.sh` (Splunk) |
| 5.1 cron permissions and allow lists | `cis.sh` perms, cron |
| 5.2 SSH server | `secure.sh ssh` (+ `cis.sh` perms, banner) |
| 5.3 sudo, su, PAM password quality | `cis.sh` sudo, su; `audit.sh passwords` (pwquality 14+ chars, 3 classes) |
| 5.4-5.5 password aging, inactive lock, system accounts, timeout | `audit.sh passwords` (max 90 days); `cis.sh` accounts |
| 6.1 file permissions, world-writable, unowned | `cis.sh` perms, files; `privesc.sh` (SUID, writable cron/services) |
| 6.2 users: UID 0, empty passwords, duplicate IDs, dotfiles | `audit.sh scan`, `privesc.sh`, `fim.sh` |

## Windows
| CIS area | Covered by |
|---|---|
| 1.1 password policy | `passwords.ps1` / `ad_passwords.ps1` (14+ chars, complexity, 90 days, no reversible encryption) |
| 1.2 account lockout | **deviation** - see below |
| 2.2 user rights | `cis.ps1` rights (member servers / workstation; on the DC via GPO) |
| 2.3 security options: accounts, audit, interactive logon, network access/security, UAC | `cis.ps1` lsa, logon, uac, audit; `harden.ps1` (Guest off, WDigest off, LSA protection); `services.ps1` (NTLMv2 only) |
| 5 system services | `services.ps1` (Spooler, Remote Registry, Telnet, SNMP, ...); `cis.ps1` services (Xbox, ICS, ...) |
| 9 Windows Firewall | `harden.ps1` (on for every profile, drop logging, scored ports allowed) |
| 17 advanced audit policy | `cis.ps1` audit |
| 18.4-18.6 MS Security Guide / network: SMB1, SMB signing, LLMNR, NetBIOS, mDNS, source routing | `harden.ps1`; `cis.ps1` smb, network |
| 18.9 administrative templates: AutoPlay, RDP, WinRM client, Defender, PowerShell logging, event log sizes | `cis.ps1` autorun, remote, defender, powershell, audit; `harden.ps1` (script block logging, command lines) |
| SMB / RDP / DNS / WinRM / SQL service hardening | `secure.ps1` |

## Palo Alto (CIS PAN-OS) - by hand, `palo-alto/HARDENING.md`
- [ ] Device → Setup → Management → **Minimum Password Complexity**: on, 14+ characters, upper/lower/number/special
- [ ] Same page → **Login Banner**: the text from `motd-banner.txt`
- [ ] Idle timeout 15 min; management HTTPS only, permitted IPs = LAN (`pa_policy.py apply` does the last two)
- [ ] Device → Setup → Services: **Verify Update Server Identity** on; NTP servers set (the DC)
- [ ] SNMP only v3 (Device → Setup → Operations → SNMP), or off
- [ ] Logging to Splunk for traffic, threat, system and config logs (`palo-alto/HARDENING.md` 3.4)
- [ ] Zone protection on the outside zone (3.3); no web/SSH management profile on data interfaces (`pa_policy.py`)

## Deliberate deviations (each would cost points or lock the team out)
| CIS says | We do | Why |
|---|---|---|
| Account lockout after 5 failures (Linux faillock, Windows 1.2) | **No lockout** | The red team fails logins on purpose to lock out the scored users - every check using them goes down |
| Password minimum age 1 day | **0 days** | We rotate passwords several times (start, after each incident) |
| Password history 24 | 5 | Scripts generate random passwords anyway |
| Rename Administrator / Guest | **Not renamed** | Rule 11: usernames may not change |
| Bootloader (GRUB) password | **None** | A typo at reboot = a box nobody can boot; only we have console access anyway |
| auditd `-e 2` (immutable rules), halt when the audit log is full | **Mutable, no halt** | We need to change rules mid-competition; a halted box scores zero |
| umask 027 | **Default (022)** | Files root creates in web roots would become unreadable for the web server |
| Separate /tmp, /var, /var/log partitions | **Not repartitioned** | Can't repartition a live competition box; /dev/shm and existing mounts get the options |
| `/tmp` noexec | nodev,nosuid only | Installers and package scripts run from /tmp |
| LDAP signing / channel binding required on the DC | **Not forced** | The Email box binds to AD over plain LDAP - mail logins would break |
| WinRM service: no Basic, no unencrypted | **Asked, default no** (`secure.ps1`) | The AD-WinRM scorer may use them |
| Kerberos AES only, Credential Guard, VBS | Report only | Compatibility with the other boxes, reboots |
| Disable IP forwarding | Skipped where Docker/Podman run | Containers need it |
| Shell timeout (TMOUT) | Asked | Closes idle tmux panes too |
| Remove `squashfs` (Ubuntu) | Kept loadable | Ubuntu's snap packages are squashfs images |
| SSH: no password authentication | **Passwords stay on** | The scorer logs in with a password |
| SMB/RDP restricted to admin hosts, IP allow-lists | **Open to every source** | Rule 9: public services must stay available from all source addresses |
