#!/bin/bash
# Find privilege-escalation paths and living-off-the-land abuse on a Linux box.
# (Backdoors and persistence are audit.sh's job; this looks for ways a normal user or a
# compromised service account can become root, and for attack commands already being run.)
#
# Usage: sudo ./privesc.sh [--fix] [--yes] [--config FILE]
#   --fix   offer to fix each finding (remove group/other write, drop capabilities, remove users
#           from root-equivalent groups, tighten shadow/key permissions) - asks each time
#   --yes   with --fix: don't ask
#
# Checks: sudo rules (NOPASSWD, ALL, shell-escape programs, wildcards), file capabilities,
# SUID/SGID shell-escape programs, files/folders root runs or trusts that others can write (cron,
# systemd units and their programs, init scripts, profile scripts, root's PATH, library paths,
# passwd/shadow/sudoers), root-equivalent groups (docker, lxd, disk, shadow...), docker socket,
# NFS no_root_squash, readable secrets (shadow, private keys, app configs, history), old sudo/
# polkit, and LOL / reverse-shell commands in running processes, shell history, cron and units.
# Log: /root/ccdc/privesc-<time>.log; critical findings to syslog (ccdc-privesc).
# Exit 2 = critical, 1 = warnings, 0 = clean.

set -u
FIX=0; YES=0
CONFIG="$(dirname "$0")/../ccdc.conf"
usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 3; }
while [ $# -gt 0 ]; do
  case "$1" in --fix) FIX=1 ;; --yes) YES=1 ;; --config) CONFIG="$2"; shift ;; *) usage ;; esac
  shift
done
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)"; exit 3; }
WEB_ROOTS=(/var/www)
# shellcheck source=../ccdc.conf
[ -f "$CONFIG" ] && . "$CONFIG"
umask 077; mkdir -p /root/ccdc
LOG="/root/ccdc/privesc-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1

if [ -t 0 ]; then R=$'\e[31m'; Y=$'\e[33m'; G=$'\e[32m'; C=$'\e[36m'; N=$'\e[0m'; else R=; Y=; G=; C=; N=; fi
CRIT=0; WARN=0
crit() { CRIT=$((CRIT + 1)); echo "${R}[CRITICAL]${N} $*"; logger -t ccdc-privesc -p auth.warning "CRITICAL: $*" 2>/dev/null; }
warn() { WARN=$((WARN + 1)); echo "${Y}[WARN]${N}     $*"; }
ok()   { echo "${G}[OK]${N}       $*"; }
info() { echo "           $*"; }
h1()   { printf '\n%s==================== %s ====================%s\n' "$C" "$1" "$N"; }
ask()  { [ "$FIX" -eq 1 ] || return 1; [ "$YES" -eq 1 ] && return 0; local a; read -r -p "           $1 [y/N] " a < /dev/tty || a=""; [[ "$a" =~ ^[Yy] ]]; }

# Programs that give a root shell when allowed via sudo / SUID / capabilities (GTFOBins)
GTFO='awk|gawk|mawk|nawk|bash|sh|dash|zsh|ksh|csh|tcsh|fish|busybox|env|find|vi|vim|vim\.basic|view|rvim|nvim|nano|pico|ed|less|more|man|most|pg|python[0-9.]*|perl[0-9.]*|ruby[0-9.]*|lua[0-9.]*|php[0-9.]*|node|nodejs|tclsh|wish|expect|gdb|strace|ltrace|tar|zip|unzip|gzip|cpio|rsync|scp|ssh|sftp|ftp|git|cp|mv|dd|tee|install|chmod|chown|chattr|ln|sed|xargs|time|timeout|nice|ionice|taskset|stdbuf|watch|script|screen|tmux|socat|nc|ncat|netcat|nmap|openssl|curl|wget|tcpdump|mount|umount|systemctl|journalctl|crontab|at|docker|podman|kubectl|apt|apt-get|dpkg|yum|dnf|rpm|pip[0-9.]*|npm|gem|make|cmake|gcc|cc|ld|run-parts|flock|sudo|su|pkexec|doas|start-stop-daemon|setarch|unshare|nsenter|chroot|capsh|ip|ssh-keygen|openvpn|wireshark|tshark|iftop|aria2c|zip|7z|base64|xxd|od|hexdump|diff|cat|head|tail|tac|nl|cut|sort|uniq|file|jq|grep|readelf'
is_gtfo() { [[ "$(basename "$1")" =~ ^($GTFO)$ ]]; }

# writable_by_others PATH -> prints why if someone other than root can modify it
writable_by_others() {
  local p="$1" o g perm
  [ -e "$p" ] || return 1
  read -r o g perm < <(stat -Lc '%U %G %a' "$p" 2>/dev/null) || return 1
  if [ "$o" != root ]; then echo "owned by $o"; return 0; fi
  (( 8#$perm & 2 )) && { echo "world-writable ($perm)"; return 0; }
  (( 8#$perm & 020 )) && [ "$g" != root ] && { echo "group-writable by $g ($perm)"; return 0; }
  return 1
}
# check_root_runs LABEL PATH: a file root executes/trusts - also check its folder
check_root_runs() {
  local label="$1" p="$2" why d
  [ -e "$p" ] || return 0
  if why="$(writable_by_others "$p")"; then
    crit "$label: $p is $why - anyone with that access runs code as root"
    ask "Make $p root-owned and not writable by others?" && { chown root "$p"; chmod go-w "$p"; info "fixed $p"; }
  fi
  d="$(dirname "$p")"
  if why="$(writable_by_others "$d")"; then
    case "$d" in /tmp|/var/tmp|/dev/shm) crit "$label: $p is in $d (anyone can replace it)";; *)
      crit "$label: folder $d of $p is $why - the file can be replaced"
      ask "Make $d root-owned and not writable by others?" && { chown root "$d"; chmod go-w "$d"; info "fixed $d"; } ;;
    esac
  fi
}

echo "Privilege-escalation and LOL check of $(hostname) - $(date)"

# ------------------------------------------------------------------ sudo
h1 "SUDO"
found=0
while IFS= read -r line; do
  file="${line%%:*}"; rule="${line#*:}"
  [[ "$rule" =~ ^[[:space:]]*(Defaults|#|@include|$) ]] && continue
  [[ "$rule" =~ ^[[:space:]]*(User_Alias|Cmnd_Alias|Host_Alias|Runas_Alias) ]] && continue
  who="$(awk '{ print $1 }' <<< "$rule")"
  [[ "$who" =~ ^(root|%admin|%sudo|%wheel)$ ]] && [[ "$rule" =~ ALL[[:space:]]*$ ]] && [[ ! "$rule" =~ NOPASSWD ]] && continue
  found=1
  if [[ "$rule" =~ NOPASSWD ]] && [[ "$rule" =~ (ALL[[:space:]]*$|ALL[[:space:]]*,) ]]; then crit "Passwordless full root via sudo for $who ($file): $rule"
  elif [[ "$rule" =~ NOPASSWD ]]; then warn "Passwordless sudo for $who ($file): $rule"
  else info "sudo rule ($file): $rule"; fi
  for cmd in $(grep -oE '/[^ ,]+' <<< "${rule#*)}"); do
    is_gtfo "$cmd" && crit "  $who may run $cmd via sudo - shell escape to root (GTFOBins)"
    [[ "$cmd" == *'*'* ]] && warn "  wildcard in sudo command $cmd - arguments can be abused"
    [ -e "$cmd" ] && check_root_runs "sudo command" "$cmd"
  done
done < <(grep -sH '' /etc/sudoers /etc/sudoers.d/* | sed 's/\r$//')
[ "$found" -eq 0 ] && ok "Only the standard admin-group sudo rules"
for g in sudo wheel admin; do
  m="$(getent group "$g" | cut -d: -f4)"; [ -n "$m" ] && info "members of $g (can become root with their password): $m"
done
for f in /etc/sudoers /etc/sudoers.d/*; do [ -e "$f" ] && why="$(writable_by_others "$f")" && crit "$f is $why"; done

# ------------------------------------------------------------------ capabilities and SUID
h1 "CAPABILITIES AND SUID"
if command -v getcap > /dev/null; then
  found=0
  while read -r file caps; do
    [ -n "$file" ] || continue
    case "$caps" in *cap_setuid*|*cap_setgid*|*cap_dac_override*|*cap_dac_read_search*|*cap_sys_admin*|*cap_sys_ptrace*|*cap_sys_module*|*cap_chown*|*cap_fowner*)
      found=1; crit "$file has $caps - can become root or read any file"
      ask "Remove the capabilities from $file?" && setcap -r "$file" && info "removed" ;;
    esac
  done < <(getcap -r /usr /bin /sbin /opt /home /root /tmp /var /srv 2>/dev/null | sed 's/ = / /; s/ \(cap_\)/ \1/')
  [ "$found" -eq 0 ] && ok "No dangerous file capabilities"
else info "getcap not installed - capabilities not checked"; fi
found=0
while IFS= read -r f; do
  is_gtfo "$f" || continue
  case "$(basename "$f")" in sudo|su|pkexec|mount|umount|chsh|chfn|passwd|newgrp|gpasswd|at|crontab|fusermount|fusermount3|ssh-keysign) continue ;; esac
  found=1; crit "SUID/SGID shell-escape program: $f ($(stat -c '%A %U' "$f"))"
done < <(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)
[ "$found" -eq 0 ] && ok "No SUID/SGID shell-escape programs (audit.sh scan checks SUID files in detail)"

# ------------------------------------------------------------------ things root runs or trusts
h1 "FILES ROOT RUNS OR TRUSTS"
for f in /etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/crontab /etc/rc.local /etc/profile /etc/bash.bashrc /etc/bashrc \
         /etc/environment /etc/ld.so.preload /etc/ld.so.conf /root/.bashrc /root/.profile /root/.bash_profile; do
  check_root_runs "system file" "$f"
done
for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/profile.d /etc/init.d /etc/ld.so.conf.d \
         /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system; do
  [ -d "$d" ] || continue
  why="$(writable_by_others "$d")" && crit "$d is $why"
  while IFS= read -r f; do check_root_runs "$(basename "$d")" "$f"; done < <(find "$d" -maxdepth 1 -type f 2>/dev/null)
done
# root's own crontab (user crontabs in the spool are owned by their users - that's normal)
for f in /var/spool/cron/root /var/spool/cron/crontabs/root; do check_root_runs "root crontab" "$f"; done
# Programs started by root cron jobs
while IFS= read -r p; do check_root_runs "root cron job" "$p"; done < <(
  { grep -hvE '^\s*(#|$|[A-Z_]+=)' /etc/crontab /etc/cron.d/* 2>/dev/null | awk '$6 == "root" { for (i = 7; i <= NF; i++) print $i }'
    grep -hvE '^\s*(#|$|[A-Z_]+=)' /var/spool/cron/root /var/spool/cron/crontabs/root 2>/dev/null | awk '{ for (i = 6; i <= NF; i++) print $i }'
  } | grep -oE '^/[^;|&>< ]+' | sort -u)
# Programs started by systemd services that run as root
while read -r unit; do
  user="$(systemctl show -p User --value "$unit" 2>/dev/null)"
  [ -z "$user" ] || [ "$user" = root ] || continue
  for p in $(systemctl show -p ExecStart --value "$unit" 2>/dev/null | grep -oE 'path=[^ ;]+' | cut -d= -f2 | sort -u); do
    check_root_runs "service $unit" "$p"
  done
done < <(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null | awk '{ print $1 }')
# root's PATH and library paths
for d in $(tr ':' '\n' <<< "${PATH}:$(grep -oP 'secure_path="?\K[^"]+' /etc/sudoers 2>/dev/null)" | sort -u); do
  [ "$d" = "." ] || [ -z "$d" ] && { crit "root's PATH contains the current directory"; continue; }
  why="$(writable_by_others "$d")" && { crit "PATH folder $d is $why - a planted program runs as root"; ask "Make $d not writable by others?" && { chown root "$d"; chmod go-w "$d"; }; }
done
for d in $(cat /etc/ld.so.conf.d/*.conf /etc/ld.so.conf 2>/dev/null | grep -E '^/' | sort -u); do
  why="$(writable_by_others "$d")" && crit "Library folder $d is $why - a planted library loads into root programs"
done
p="$(stat -c %a /etc/shadow 2>/dev/null)"
if [ -n "$p" ] && (( 8#$p & 4 )); then crit "/etc/shadow is world-readable ($p)"; ask "chmod o-rwx /etc/shadow?" && chmod o-rwx /etc/shadow; fi
awk -F: '$2 != "x" && $2 != "*" && $2 != "!" && $2 != "" { print $1 }' /etc/passwd | while read -r u; do crit "Password hash stored in /etc/passwd for $u"; done

# ------------------------------------------------------------------ groups, docker, NFS
h1 "ROOT-EQUIVALENT GROUPS, DOCKER, NFS"
found=0
for g in docker lxd lxc disk shadow libvirt kvm root; do
  m="$(getent group "$g" | cut -d: -f4)"; [ -n "$m" ] || continue
  for u in ${m//,/ }; do
    [ "$u" = root ] && continue
    found=1; crit "$u is in group '$g' - $(case $g in docker|lxd|lxc|libvirt) echo 'can start a container with the host disk = root';; disk) echo 'can read/write raw disks';; shadow) echo 'can read password hashes';; *) echo 'root-level access';; esac)"
    ask "Remove $u from $g?" && gpasswd -d "$u" "$g" > /dev/null && info "removed"
  done
done
[ "$found" -eq 0 ] && ok "No users in root-equivalent groups"
for s in /var/run/docker.sock /run/docker.sock; do
  [ -S "$s" ] || continue
  p="$(stat -c '%a %G' "$s")"; (( 8#${p%% *} & 2 )) && crit "Docker socket $s is world-writable ($p) - any user is root"
done
grep -sE 'no_root_squash' /etc/exports && crit "NFS export with no_root_squash - root on a client is root on these files"

# ------------------------------------------------------------------ secrets lying around
h1 "READABLE SECRETS"
for k in /root/.ssh/id_* /home/*/.ssh/id_* /etc/ssh/ssh_host_*_key; do
  [ -f "$k" ] || continue; [[ "$k" == *.pub ]] && continue
  p="$(stat -c %a "$k")"; (( 8#$p & 044 )) && { crit "Private key $k is readable by others ($p)"; ask "chmod 600 $k?" && chmod 600 "$k"; }
done
for f in /root/.my.cnf /home/*/.my.cnf /root/.pgpass /home/*/.pgpass /root/.netrc /home/*/.netrc /home/*/.git-credentials /root/.git-credentials; do
  [ -f "$f" ] || continue; p="$(stat -c %a "$f")"
  (( 8#$p & 044 )) && warn "$f (stored credentials) is readable by others ($p)" || info "credentials file: $f"
done
for r in "${WEB_ROOTS[@]}"; do
  [ -d "$r" ] || continue
  while IFS= read -r f; do
    p="$(stat -c %a "$f")"; (( 8#$p & 4 )) && warn "World-readable app config with a password: $f ($p) - any local user can read the DB password (640, group = web server user)"
  done < <(grep -rlsIE --include=*.php --include=.env --include=*.ini --include=*.yml "(DB_PASSWORD|db_pass|_DB_PASSWD_|password'\s*=>|dbpass)" "$r" 2>/dev/null | head -20)
done
for h in /root/.bash_history /home/*/.bash_history /root/.mysql_history /home/*/.mysql_history; do
  [ -f "$h" ] || continue
  grep -qiE 'pass(word)?[= ]|-p[^ ]{4,}|sshpass|PGPASSWORD|mysql .*-p' "$h" && warn "History with possible passwords: $h"
  p="$(stat -c %a "$h")"; (( 8#$p & 044 )) && warn "$h is readable by others ($p)"
done

# ------------------------------------------------------------------ vulnerable versions
h1 "KNOWN LOCAL ROOT BUGS"
info "Kernel $(uname -r) - keep it updated (services.sh --update lists it; needs a reboot)"
if command -v sudo > /dev/null; then
  sv="$(sudo -V 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(p[0-9]+)?')"
  if [ -n "$sv" ] && [ "$(printf '%s\n1.9.5p2\n' "$sv" | sort -V | head -1)" = "$sv" ] && [ "$sv" != 1.9.5p2 ]; then
    warn "sudo $sv is older than 1.9.5p2 (Baron Samedit, CVE-2021-3156) unless the distro patched it - update sudo"
  else ok "sudo $sv"; fi
fi
if [ -u /usr/bin/pkexec ]; then
  info "pkexec is SUID ($(pkexec --version 2>/dev/null | head -1)) - PwnKit (CVE-2021-4034) is fixed by distro polkit updates; if updates aren't possible: chmod 0755 /usr/bin/pkexec"
fi

# ------------------------------------------------------------------ living off the land
h1 "LIVING OFF THE LAND / REVERSE SHELLS"
LOL='(bash|sh)[[:space:]]+-i[[:space:]]*>&?[[:space:]]*/dev/(tcp|udp)/|/dev/tcp/[0-9]|(nc|ncat|netcat)[[:space:]].*-[ec][[:space:]]|socat[[:space:]].*exec|python[0-9.]*[[:space:]]+-c.*socket|perl[[:space:]]+-e.*socket|php[[:space:]]+-r.*fsockopen|ruby[[:space:]]+-rsocket|mkfifo.*(nc|ncat|sh)|(curl|wget)[[:space:]].*\|[[:space:]]*(sudo[[:space:]]+)?(ba)?sh|base64[[:space:]]+-d.*\|[[:space:]]*(ba)?sh|chmod[[:space:]]+[ugo]*\+s[[:space:]]|chmod[[:space:]]+[0-7]?[4-7][0-7]{3}[[:space:]]|>>[[:space:]]*[^ ]*authorized_keys|openssl[[:space:]]+s_client.*\|[[:space:]]*/bin/(ba)?sh|xterm[[:space:]]+-display|busybox[[:space:]]+nc|telnet[[:space:]].*\|[[:space:]]*/bin/(ba)?sh'
OURS='/opt/ccdc|ccdc-|privesc\.sh|audit\.sh'
found=0
while IFS= read -r line; do
  grep -qE "$OURS" <<< "$line" && continue
  found=1; crit "Running now: $line"
done < <(ps -eo pid=,user=,args= | grep -E "$LOL" | grep -v 'grep -E')
for h in /root/.bash_history /home/*/.bash_history /root/.zsh_history /home/*/.zsh_history /root/.ash_history; do
  [ -f "$h" ] || continue
  while IFS= read -r l; do found=1; crit "In $h: ${l:0:200}"; done < <(grep -E "$LOL" "$h" | tail -5)
done
while IFS= read -r l; do found=1; crit "Scheduled: ${l:0:250}"; done < <(grep -rsE "$LOL" /etc/crontab /etc/cron.d /var/spool/cron /var/spool/at* /etc/systemd/system /etc/rc.local /etc/profile.d 2>/dev/null)
[ "$found" -eq 0 ] && ok "No reverse-shell / download-and-run commands in processes, history, cron or units"

h1 "SUMMARY"
echo "Critical: $CRIT   Warnings: $WARN   Log: $LOG"
[ "$CRIT" -gt 0 ] && [ "$FIX" -eq 0 ] && echo "Fix what can be fixed: sudo $0 --fix (asks each time). Backdoors / persistence: sudo linux/audit.sh scan"
[ "$CRIT" -gt 0 ] && exit 2
[ "$WARN" -gt 0 ] && exit 1
exit 0
