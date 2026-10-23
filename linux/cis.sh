#!/bin/bash
# CIS Benchmark Level 1 controls that the other scripts don't already cover, made scoring-safe.
# (Rocky/RHEL 9, Ubuntu 22.04, Debian 12 - the controls are the same in all three benchmarks.)
#
# Usage: sudo linux/cis.sh [--fix] [--yes] [--section NAME]... [--config FILE]
#   (no option)  report PASS / FAIL for every control below
#   --fix        apply the fixes, asking once per section (--yes: don't ask)
#   --section    only these sections (repeatable)
#
# Sections (CIS numbers are from the RHEL 9 / Ubuntu 22.04 benchmarks):
#   modules   unused filesystems and network protocols can't be loaded (1.1.1, 3.4)
#   mounts    /dev/shm nodev,nosuid,noexec; /tmp and /var/tmp nodev,nosuid if separate mounts (1.1.2-1.1.8)
#   sysctl    network and kernel parameters (1.5, 3.2, 3.3) - IP forwarding left on if a container engine runs
#   coredump  no core dumps (1.5.1)
#   perms     owners/modes of passwd, shadow, group, gshadow, sshd_config, host keys, cron, bootloader config (5.1, 5.2, 6.1, 1.4)
#   cron      cron/at only for root and users who already have jobs (5.1.8-9)
#   banner    warning banner on the console, SSH and motd, no OS version in it (1.7, 5.2.x)
#   accounts  root GID 0, inactive-password lock 30 days, system accounts without login shells (5.4, 5.5)
#   sudo      sudo needs a pty and logs to /var/log/sudo.log (5.3)
#   su        only members of the (empty) group sugroup may use su (5.3.7)
#   logging   persistent journal, rsyslog file modes, auditd with CIS rules (4.1, 4.2)
#   packages  repository signature checks on; legacy client tools removed (1.2, 2.3)
#   files     world-writable files, files without an owner (6.1.10-12)        [report only]
#   mac       SELinux / AppArmor enforcing (1.6)                               [report only]
#
# Deliberate deviations (they would cost points or lock the team out): no account lockout, no
# bootloader password, no immutable audit rules, no system halt when the audit log fills up, no
# forced umask 027, password minimum age 0. Full list: checklists/CIS.md
# Changes are backed up to /root/ccdc/cis-<time>/. Log: /root/ccdc/cis-<time>.log
# Exit: 0 every control passes, 1 failures left.

set -u
FIX=0; YES=0; SECTIONS=()
CONFIG="$(dirname "$0")/../ccdc.conf"
HERE="$(cd "$(dirname "$0")" && pwd)"
usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --fix) FIX=1; shift ;;
    --yes) YES=1; shift ;;
    --section) SECTIONS+=("$2"); shift 2 ;;
    --config) CONFIG="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)"; exit 1; }
CCDC_ROLE="${CCDC_ROLE:-}"
# shellcheck source=../ccdc.conf
[ -f "$CONFIG" ] && . "$CONFIG"

TS="$(date +%Y%m%d-%H%M%S)"
BK="/root/ccdc/cis-$TS"
umask 077; mkdir -p /root/ccdc && chmod 700 /root/ccdc
LOG="/root/ccdc/cis-$TS.log"
exec > >(tee -a "$LOG") 2>&1

if [ -t 1 ] || [ -t 0 ]; then R=$'\e[31m'; Y=$'\e[33m'; G=$'\e[32m'; C=$'\e[36m'; N=$'\e[0m'; else R=; Y=; G=; C=; N=; fi
FAILS=0; SEC_FAILS=0
pass() { echo "${G}[PASS]${N} $*"; }
failc() { FAILS=$((FAILS + 1)); SEC_FAILS=$((SEC_FAILS + 1)); echo "${R}[FAIL]${N} $*"; }
note() { echo "${Y}[NOTE]${N} $*"; }
info() { echo "       $*"; }
h1()   { printf '\n%s== %s ==%s\n' "$C" "$1" "$N"; SEC_FAILS=0; }
want() { [ ${#SECTIONS[@]} -eq 0 ] && return 0; local s; for s in "${SECTIONS[@]}"; do [ "$s" = "$1" ] && return 0; done; return 1; }
# fixing "what": --fix on, failures in this section, and the user agrees
fixing() {
  [ "$FIX" -eq 1 ] && [ "$SEC_FAILS" -gt 0 ] || return 1
  [ "$YES" -eq 1 ] && return 0
  local a; read -r -p "    Fix: $1? [y/N] " a < /dev/tty || return 1; [[ "$a" =~ ^[Yy] ]]
}
backup() { local f; for f; do [ -e "$f" ] && mkdir -p "$BK$(dirname "$f")" && cp -a "$f" "$BK$f"; done; }

FAMILY=deb; [ -f /etc/redhat-release ] && FAMILY=rpm
CONTAINERS=0
{ systemctl is-active --quiet docker || systemctl is-active --quiet podman || [ -S /var/run/docker.sock ]; } 2>/dev/null && CONTAINERS=1

# ============================================================================ modules
sec_modules() {
  h1 "modules: unused filesystems and network protocols (CIS 1.1.1, 3.4)"
  local mods=(cramfs freevxfs hfs hfsplus jffs2 udf usb-storage dccp sctp rds tipc) m bad=()
  # squashfs: Ubuntu's snaps are squashfs images - leave it loadable there
  [ "$FAMILY" = rpm ] && mods+=(squashfs)
  for m in "${mods[@]}"; do
    if modprobe -n -v "$m" 2>/dev/null | grep -qE '^install /bin/(true|false)'; then continue; fi
    bad+=("$m")
  done
  if [ ${#bad[@]} -eq 0 ]; then pass "none of ${mods[*]} can be loaded"; return; fi
  failc "loadable: ${bad[*]}"
  if fixing "make ${bad[*]} unloadable (modprobe.d)"; then
    { echo "# CCDC (linux/cis.sh): CIS 1.1.1 / 3.4 - unused filesystems and protocols"
      for m in "${bad[@]}"; do echo "install $m /bin/false"; echo "blacklist $m"; done; } > /etc/modprobe.d/60-ccdc-cis.conf
    for m in "${bad[@]}"; do lsmod | grep -q "^${m//-/_} " && { modprobe -r "$m" 2>/dev/null || info "$m is in use - unloads at the next reboot"; }; done
    pass "written /etc/modprobe.d/60-ccdc-cis.conf"
  fi
}

# ============================================================================ mounts
mount_opts() { findmnt -no OPTIONS "$1" 2>/dev/null; }
sec_mounts() {
  h1 "mounts: temporary file systems (CIS 1.1.2-1.1.8)"
  local o missing
  o="$(mount_opts /dev/shm)"
  missing=""; for x in nodev nosuid noexec; do [[ ",$o," == *",$x,"* ]] || missing+=" $x"; done
  if [ -z "$o" ]; then note "/dev/shm is not mounted"
  elif [ -z "$missing" ]; then pass "/dev/shm nodev,nosuid,noexec"
  else
    failc "/dev/shm missing:$missing (attackers run payloads from /dev/shm)"
    if fixing "remount /dev/shm nodev,nosuid,noexec and keep it in /etc/fstab"; then
      mount -o remount,nodev,nosuid,noexec /dev/shm && pass "remounted"
      backup /etc/fstab
      if grep -qE '^[^#]\S*\s+/dev/shm\s' /etc/fstab; then
        sed -i -E '/^[^#]\S*\s+\/dev\/shm\s/ s/(\S+\s+\S+\s+\S+\s+)(\S+)/\1\2,nodev,nosuid,noexec/' /etc/fstab
      else
        echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0   # CCDC cis.sh" >> /etc/fstab
      fi
      findmnt --verify --tab-file /etc/fstab > /dev/null 2>&1 || note "check /etc/fstab: findmnt --verify"
    fi
  fi
  # /tmp and /var/tmp: only when they are separate mounts; noexec there breaks installers, so nodev,nosuid only
  local m
  for m in /tmp /var/tmp; do
    o="$(mount_opts "$m")"
    if [ -z "$o" ] || [ "$(findmnt -no TARGET "$m" 2>/dev/null)" != "$m" ]; then
      note "$m is not a separate mount (CIS wants one - not changed mid-competition; a new mount would hide what's in it)"
      continue
    fi
    missing=""; for x in nodev nosuid; do [[ ",$o," == *",$x,"* ]] || missing+=" $x"; done
    if [ -z "$missing" ]; then pass "$m nodev,nosuid"
    else
      failc "$m missing:$missing"
      fixing "remount $m with$missing (fstab entry: add them by hand)" && mount -o "remount${missing// /,}" "$m" && pass "remounted $m"
    fi
  done
}

# ============================================================================ sysctl
SYSCTL_FILE=/etc/sysctl.d/60-ccdc-cis.conf
sec_sysctl() {
  h1 "sysctl: network and kernel parameters (CIS 1.5, 3.2, 3.3)"
  local -a want=(
    "kernel.randomize_va_space 2" "kernel.yama.ptrace_scope 1" "kernel.kptr_restrict 2" "kernel.dmesg_restrict 1"
    "fs.suid_dumpable 0" "fs.protected_hardlinks 1" "fs.protected_symlinks 1"
    "net.ipv4.conf.all.send_redirects 0" "net.ipv4.conf.default.send_redirects 0"
    "net.ipv4.conf.all.accept_redirects 0" "net.ipv4.conf.default.accept_redirects 0"
    "net.ipv4.conf.all.secure_redirects 0" "net.ipv4.conf.default.secure_redirects 0"
    "net.ipv4.conf.all.accept_source_route 0" "net.ipv4.conf.default.accept_source_route 0"
    "net.ipv4.conf.all.log_martians 1" "net.ipv4.conf.default.log_martians 1"
    "net.ipv4.conf.all.rp_filter 1" "net.ipv4.conf.default.rp_filter 1"
    "net.ipv4.icmp_echo_ignore_broadcasts 1" "net.ipv4.icmp_ignore_bogus_error_responses 1"
    "net.ipv4.tcp_syncookies 1"
    "net.ipv6.conf.all.accept_redirects 0" "net.ipv6.conf.default.accept_redirects 0"
    "net.ipv6.conf.all.accept_source_route 0" "net.ipv6.conf.all.accept_ra 0" "net.ipv6.conf.default.accept_ra 0"
  )
  if [ "$CONTAINERS" -eq 0 ]; then want+=("net.ipv4.ip_forward 0" "net.ipv6.conf.all.forwarding 0")
  else note "container engine present: IP forwarding left as it is (Docker/Podman need it)"; fi
  local kv k v cur bad=()
  for kv in "${want[@]}"; do
    k="${kv% *}"; v="${kv#* }"
    cur="$(sysctl -n "$k" 2>/dev/null)" || continue          # key doesn't exist on this kernel
    [ "$cur" = "$v" ] || bad+=("$k=$v (now $cur)")
  done
  # never this one - ping is scored
  [ "$(sysctl -n net.ipv4.icmp_echo_ignore_all 2>/dev/null)" = 1 ] && { failc "net.ipv4.icmp_echo_ignore_all=1 - ping is OFF (scored!)"; bad+=("net.ipv4.icmp_echo_ignore_all=0 (now 1)"); }
  if [ ${#bad[@]} -eq 0 ]; then pass "all ${#want[@]} parameters set"; return; fi
  failc "${#bad[@]} parameter(s) wrong:"; printf '         %s\n' "${bad[@]}"
  if fixing "write $SYSCTL_FILE and load it"; then
    backup "$SYSCTL_FILE"
    { echo "# CCDC (linux/cis.sh): CIS 1.5 / 3.2 / 3.3. ICMP echo stays on (ping is scored)."
      for kv in "${want[@]}"; do k="${kv% *}"; sysctl -n "$k" > /dev/null 2>&1 && echo "$k = ${kv#* }"; done
      echo "net.ipv4.icmp_echo_ignore_all = 0"; } > "$SYSCTL_FILE"
    sysctl -q -p "$SYSCTL_FILE" && pass "loaded $SYSCTL_FILE"
    ip route show default > /dev/null 2>&1 && ping -c1 -W2 "$(ip route show default | awk '{ print $3; exit }')" > /dev/null 2>&1 &&
      info "default gateway still answers ping"
  fi
}

# ============================================================================ coredump
sec_coredump() {
  h1 "coredump: no core dumps (CIS 1.5.1)"
  local ok=1
  grep -hsE '^\s*\*\s+hard\s+core\s+0' /etc/security/limits.conf /etc/security/limits.d/*.conf > /dev/null || { failc "no '* hard core 0' limit"; ok=0; }
  if [ -d /etc/systemd ] && command -v coredumpctl > /dev/null; then
    systemd-analyze cat-config systemd/coredump.conf 2>/dev/null | grep -qE '^\s*Storage\s*=\s*none' || { failc "systemd-coredump still stores dumps"; ok=0; }
  fi
  [ "$ok" -eq 1 ] && { pass "core dumps off"; return; }
  if fixing "turn core dumps off"; then
    echo "* hard core 0   # CCDC cis.sh, CIS 1.5.1" > /etc/security/limits.d/60-ccdc-cis.conf
    if command -v coredumpctl > /dev/null; then
      mkdir -p /etc/systemd/coredump.conf.d
      printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' > /etc/systemd/coredump.conf.d/60-ccdc-cis.conf
    fi
    pass "core dumps off (new sessions)"
  fi
}

# ============================================================================ perms
# want PATH MODE OWNER:GROUP - a file not more permissive than MODE, owned as given
want_perm() {
  local f="$1" mode="$2" own="$3" cur curown
  [ -e "$f" ] || return 0
  cur="$(stat -Lc %a "$f")"; curown="$(stat -Lc %U:%G "$f")"
  if (( (8#$cur & ~8#$mode) != 0 )) || { [ "$own" != "-" ] && [ "$curown" != "$own" ] && [[ "$own" != *:\* || "${curown%%:*}" != "${own%%:*}" ]]; }; then
    PERM_BAD+=("$f|$mode|$own|$cur $curown")
  fi
}
sec_perms() {
  h1 "perms: sensitive files (CIS 6.1, 5.1, 5.2, 1.4)"
  PERM_BAD=()
  local shg=root; getent group shadow > /dev/null && shg=shadow
  want_perm /etc/passwd 644 root:root;   want_perm /etc/passwd- 644 root:root
  want_perm /etc/group 644 root:root;    want_perm /etc/group- 644 root:root
  want_perm /etc/shadow 640 "root:$shg"; want_perm /etc/shadow- 640 "root:$shg"
  want_perm /etc/gshadow 640 "root:$shg"; want_perm /etc/gshadow- 640 "root:$shg"
  want_perm /etc/ssh/sshd_config 600 root:root
  local k; for k in /etc/ssh/ssh_host_*_key; do want_perm "$k" 640 "root:*"; done
  for k in /etc/ssh/ssh_host_*_key.pub; do want_perm "$k" 644 root:root; done
  for k in /etc/ssh/sshd_config.d/*.conf; do want_perm "$k" 600 root:root; done
  want_perm /etc/crontab 600 root:root
  for k in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do want_perm "$k" 700 root:root; done
  for k in /boot/grub2/grub.cfg /boot/grub2/user.cfg /boot/grub2/grubenv /boot/grub/grub.cfg; do want_perm "$k" 600 root:root; done
  if [ ${#PERM_BAD[@]} -eq 0 ]; then pass "owners and modes OK"; return; fi
  local e f mode own
  for e in "${PERM_BAD[@]}"; do IFS='|' read -r f mode own cur <<< "$e"; failc "$f is $cur (want at most $mode ${own/\*/<any>})"; done
  if fixing "chmod/chown these ${#PERM_BAD[@]} file(s)"; then
    for e in "${PERM_BAD[@]}"; do
      IFS='|' read -r f mode own cur <<< "$e"
      echo "$f $cur" >> "$BK.perms-before"
      chmod "$(printf '%o' $(( 8#$(stat -Lc %a "$f") & 8#$mode )))" "$f"
      [[ "$own" == *\* ]] && own="${own%%:*}"
      [ "$own" != "-" ] && chown "$own" "$f"
    done
    pass "fixed (previous modes: $BK.perms-before)"
    command -v sshd > /dev/null && { sshd -t 2>/dev/null && info "sshd config check still OK" || failc "sshd -t fails now - check $BK.perms-before"; }
  fi
}

# ============================================================================ cron
sec_cron() {
  h1 "cron: who may schedule jobs (CIS 5.1.8, 5.1.9)"
  local users=(root) u f
  # users who already have crontabs / at jobs keep working
  for f in /var/spool/cron/* /var/spool/cron/crontabs/*; do [ -f "$f" ] && users+=("$(basename "$f")"); done
  mapfile -t users < <(printf '%s\n' "${users[@]}" | sort -u)
  local bad=0
  for f in cron at; do
    if [ ! -f "/etc/$f.allow" ]; then failc "/etc/$f.allow missing (any user may use $f)"; bad=1
    elif [ -e "/etc/$f.deny" ]; then failc "/etc/$f.deny exists next to $f.allow"; bad=1
    else pass "/etc/$f.allow: $(tr '\n' ' ' < "/etc/$f.allow")"; fi
  done
  [ "$bad" -eq 1 ] || return
  if fixing "allow cron/at for ${users[*]} only (users with existing jobs are kept)"; then
    for f in cron at; do
      backup "/etc/$f.allow" "/etc/$f.deny"
      printf '%s\n' "${users[@]}" > "/etc/$f.allow"; chmod 640 "/etc/$f.allow"; chown root:root "/etc/$f.allow"
      rm -f "/etc/$f.deny"
    done
    pass "cron.allow / at.allow written"
  fi
}

# ============================================================================ banner
BANNER_SRC="$HERE/../checklists/motd-banner.txt"
sec_banner() {
  h1 "banner: login warning banners (CIS 1.7, 5.2.x)"
  local f bad=0
  for f in /etc/issue /etc/issue.net; do
    if [ ! -s "$f" ] || grep -qiE '\\[mrsv]|linux|ubuntu|debian|rocky|red hat|centos|alma|fedora|mint|kali|kernel' "$f"; then failc "$f shows OS details"; bad=1
    elif ! grep -qiE 'authori[sz]' "$f"; then failc "$f has no authorized-use warning"; bad=1
    else pass "$f has a warning and no OS details"; fi
  done
  local sb; sb="$(sshd -T 2>/dev/null | awk '$1 == "banner" { print $2 }')"
  if command -v sshd > /dev/null && { [ -z "$sb" ] || [ "$sb" = none ]; }; then failc "SSH shows no banner"; bad=1; fi
  [ "$bad" -eq 1 ] || return
  [ -f "$BANNER_SRC" ] || { note "banner text $BANNER_SRC missing"; return; }
  if fixing "set the team banner on the console (/etc/issue), SSH (/etc/issue.net) and motd"; then
    backup /etc/issue /etc/issue.net /etc/motd
    for f in /etc/issue /etc/issue.net /etc/motd; do cp "$BANNER_SRC" "$f"; chmod 644 "$f"; chown root:root "$f"; done
    if command -v sshd > /dev/null && [ -d /etc/ssh/sshd_config.d ] && grep -qiE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config; then
      echo "Banner /etc/issue.net" > /etc/ssh/sshd_config.d/01-ccdc-banner.conf; chmod 600 /etc/ssh/sshd_config.d/01-ccdc-banner.conf
      if sshd -t 2>/dev/null; then systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; pass "SSH banner on"
      else rm -f /etc/ssh/sshd_config.d/01-ccdc-banner.conf; failc "sshd -t failed - SSH banner not set"; fi
    fi
    # Ubuntu's dynamic motd prints the OS version: stop the info scripts (the static banner stays)
    [ -d /etc/update-motd.d ] && chmod -x /etc/update-motd.d/10-help-text /etc/update-motd.d/50-motd-news /etc/update-motd.d/00-header 2>/dev/null
    pass "banners set (text: checklists/motd-banner.txt)"
  fi
}

# ============================================================================ accounts
sec_accounts() {
  h1 "accounts: account settings (CIS 5.4, 5.5)"
  local gid; gid="$(getent passwd root | cut -d: -f4)"
  [ "$gid" = 0 ] && pass "root's group is GID 0" || failc "root's primary group is $gid, not 0"
  local inact; inact="$(useradd -D | awk -F= '$1 == "INACTIVE" { print $2 }')"
  local inact_bad=0
  if [ -n "$inact" ] && [ "$inact" -ge 0 ] 2>/dev/null && [ "$inact" -le 30 ]; then pass "accounts lock $inact days after their password expires"
  else failc "inactive-password lock off (INACTIVE=${inact:-unset})"; inact_bad=1; fi
  # system accounts (UID < UID_MIN) with a login shell - services that need one keep it
  local umin; umin="$(awk '$1 == "UID_MIN" { print $2 }' /etc/login.defs)"; umin="${umin:-1000}"
  local keep='^(root|sync|shutdown|halt|splunk|splunkfwd|postgres|ccdc-vault)$' shellusers=() u uid sh
  while IFS=: read -r u _ uid _ _ _ sh; do
    [ "$uid" -lt "$umin" ] || continue
    [[ "$u" =~ $keep ]] && continue
    case "$sh" in */nologin|*/false|"") ;; *) shellusers+=("$u:$sh") ;; esac
  done < /etc/passwd
  if [ ${#shellusers[@]} -eq 0 ]; then pass "system accounts have no login shell"
  else failc "system accounts with a login shell: ${shellusers[*]}"; fi
  local um; um="$(awk '$1 == "UMASK" { print $2 }' /etc/login.defs)"
  note "default umask ${um:-?} - CIS wants 027; not changed (root-created web files would become unreadable for the web server)"
  if grep -qsE '^\s*(readonly\s+)?TMOUT=' /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc /etc/bashrc; then pass "shell idle timeout set"
  else failc "no shell idle timeout (TMOUT)"; fi
  [ "$SEC_FAILS" -gt 0 ] || return
  if [ "$inact_bad" -eq 1 ] && fixing "lock accounts 30 days after password expiry (new accounts: useradd -D -f 30)"; then
    useradd -D -f 30 && pass "useradd -D -f 30"
  fi
  if [ ${#shellusers[@]} -gt 0 ] && fixing "give ${#shellusers[@]} system account(s) nologin, one by one"; then
    local nl; nl="$(command -v nologin || echo /usr/sbin/nologin)"
    for u in "${shellusers[@]}"; do
      read -r -p "    ${u%%:*} (shell ${u#*:}) -> $nl? Services that su to it would break [y/N] " a < /dev/tty
      [[ "${a:-}" =~ ^[Yy] ]] && { backup /etc/passwd; usermod -s "$nl" "${u%%:*}" && info "changed ${u%%:*}"; }
    done
  fi
  if ! grep -qsE '^\s*(readonly\s+)?TMOUT=' /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc /etc/bashrc &&
     fixing "log out idle shells after 15 minutes (TMOUT=900 - idle tmux panes close too; running commands are not affected)"; then
    printf '# CCDC cis.sh, CIS 5.5.x\nTMOUT=900\nreadonly TMOUT\nexport TMOUT\n' > /etc/profile.d/60-ccdc-tmout.sh
    chmod 644 /etc/profile.d/60-ccdc-tmout.sh; pass "TMOUT=900 for new shells"
  fi
}

# ============================================================================ sudo
SUDO_FILE=/etc/sudoers.d/60-ccdc-cis
sec_sudo() {
  h1 "sudo: pty and log (CIS 5.3.2, 5.3.3)"
  command -v sudo > /dev/null || { note "sudo not installed"; return; }
  local cfg; cfg="$(cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -v '^\s*#')"
  grep -qE '^\s*Defaults\s+([^#]*,)?\s*use_pty' <<< "$cfg" && pass "Defaults use_pty" || failc "sudo doesn't force a pty (use_pty)"
  grep -qE '^\s*Defaults\s+([^#]*,)?\s*logfile\s*=' <<< "$cfg" && pass "sudo logfile set" || failc "sudo has no logfile"
  grep -qE '^\s*Defaults\s+([^#]*,)?\s*!authenticate|NOPASSWD' <<< "$cfg" && note "NOPASSWD / !authenticate rules exist - check them (linux/privesc.sh lists them)"
  if fixing "add Defaults use_pty and logfile=/var/log/sudo.log"; then
    printf '# CCDC cis.sh, CIS 5.3.x\nDefaults use_pty\nDefaults logfile="/var/log/sudo.log"\nDefaults timestamp_timeout=15\n' > "$SUDO_FILE.tmp"
    chmod 440 "$SUDO_FILE.tmp"
    if visudo -cf "$SUDO_FILE.tmp" > /dev/null; then mv "$SUDO_FILE.tmp" "$SUDO_FILE"; pass "written $SUDO_FILE"
    else rm -f "$SUDO_FILE.tmp"; failc "visudo rejected it - nothing changed"; fi
  fi
}

# ============================================================================ su
sec_su() {
  h1 "su: restricted to an empty group (CIS 5.3.7)"
  if grep -qE '^\s*auth\s+required\s+pam_wheel\.so.*use_uid' /etc/pam.d/su 2>/dev/null; then
    pass "su restricted ($(grep -E 'pam_wheel' /etc/pam.d/su | grep -oE 'group=\S+' || echo 'group=wheel'))"; return
  fi
  failc "anyone with a password may su (one stolen password + su = root's shell if root has a password)"
  if fixing "only members of the empty group 'sugroup' may su (use sudo instead)"; then
    getent group sugroup > /dev/null || groupadd sugroup
    backup /etc/pam.d/su
    # after pam_rootok, as CIS shows it: root's own su (logrotate, init scripts) must keep working
    if grep -qE '^\s*auth\s+sufficient\s+pam_rootok\.so' /etc/pam.d/su; then
      sed -i -E '0,/^\s*auth\s+sufficient\s+pam_rootok\.so.*/s//&\nauth required pam_wheel.so use_uid group=sugroup/' /etc/pam.d/su
    else
      failc "no pam_rootok line in /etc/pam.d/su - not changing it (root's own su could break)"; return
    fi
    grep -q 'group=sugroup' /etc/pam.d/su && pass "su needs membership of sugroup (empty) - sudo still works" || failc "edit failed - restored"
    grep -q 'group=sugroup' /etc/pam.d/su || cp -a "$BK/etc/pam.d/su" /etc/pam.d/su
  fi
}

# ============================================================================ logging
AUDIT_RULES=/etc/audit/rules.d/60-ccdc-cis.rules
sec_logging() {
  h1 "logging: journal, rsyslog, auditd (CIS 4.1, 4.2)"
  local jc; jc="$(systemd-analyze cat-config systemd/journald.conf 2>/dev/null | grep -v '^#')"
  local jbad=0
  grep -qE '^\s*Storage\s*=\s*persistent' <<< "$jc" || [ -d /var/log/journal ] || { failc "journal not persistent (lost on reboot)"; jbad=1; }
  [ "$jbad" -eq 0 ] && pass "journal persistent"
  if command -v rsyslogd > /dev/null; then
    grep -hqsE '^\s*\$FileCreateMode\s+0[0-6][0-4]0' /etc/rsyslog.conf /etc/rsyslog.d/*.conf && pass "rsyslog creates log files 0640 or stricter" ||
      failc "rsyslog file mode not set to 0640"
  fi
  local abad=0
  if ! command -v auditctl > /dev/null; then failc "auditd not installed"; abad=1
  elif ! systemctl is-active --quiet auditd; then failc "auditd not running"; abad=1
  elif [ ! -f "$AUDIT_RULES" ]; then failc "CIS audit rules not loaded"; abad=1
  else pass "auditd running with $(auditctl -l 2>/dev/null | wc -l) rules"; fi
  if fixing "persistent journal, rsyslog 0640, auditd + CIS rules"; then
    mkdir -p /etc/systemd/journald.conf.d /var/log/journal
    printf '[Journal]\nStorage=persistent\nCompress=yes\n' > /etc/systemd/journald.conf.d/60-ccdc-cis.conf
    systemctl restart systemd-journald && pass "journal persistent"
    if command -v rsyslogd > /dev/null; then
      echo '$FileCreateMode 0640' > /etc/rsyslog.d/00-ccdc-cis.conf
      rsyslogd -N1 > /dev/null 2>&1 && systemctl restart rsyslog && pass "rsyslog 0640" || { rm -f /etc/rsyslog.d/00-ccdc-cis.conf; failc "rsyslog config check failed - not changed"; }
    fi
    if [ "$abad" -eq 1 ]; then
      if ! command -v auditctl > /dev/null; then
        case "$FAMILY" in rpm) dnf -y install audit < /dev/null > /dev/null 2>&1 ;; deb) apt-get install -y auditd < /dev/null > /dev/null 2>&1 ;; esac
      fi
      command -v auditctl > /dev/null || { failc "couldn't install auditd (no internet?)"; return; }
      write_audit_rules
      systemctl enable --now auditd > /dev/null 2>&1
      augenrules --load > /dev/null 2>&1 || service auditd reload > /dev/null 2>&1
      pass "auditd running with $(auditctl -l 2>/dev/null | wc -l) rules ($AUDIT_RULES; search: ausearch -k <key> -i)"
    fi
  fi
}
write_audit_rules() {
  local arch=b64; [ "$(uname -m)" = x86_64 ] || arch=b32
  local umin; umin="$(awk '$1 == "UID_MIN" { print $2 }' /etc/login.defs)"; umin="${umin:-1000}"
  # auditctl stops at the first rule it rejects: watch only paths that exist, and no duplicates
  # of the rules the checklists used to add by hand
  [ -f /etc/audit/rules.d/ccdc.rules ] && { backup /etc/audit/rules.d/ccdc.rules; rm -f /etc/audit/rules.d/ccdc.rules; info "replaced the older /etc/audit/rules.d/ccdc.rules"; }
  [ -e /var/log/sudo.log ] || { touch /var/log/sudo.log; chmod 600 /var/log/sudo.log; }
  w() { [ -e "$1" ] && echo "-w $1 -p $2 -k $3"; }
  {
    echo "# CCDC (linux/cis.sh): CIS 4.1.3.x audit rules. Not immutable (-e 2): we may need to change them mid-competition."
    w /etc/passwd wa identity; w /etc/shadow wa identity; w /etc/group wa identity
    w /etc/gshadow wa identity; w /etc/security/opasswd wa identity
    w /etc/sudoers wa scope; w /etc/sudoers.d/ wa scope
    w /var/log/sudo.log wa sudo_log
    w /var/log/lastlog wa logins; w /var/run/faillock/ wa logins
    w /var/run/utmp wa session; w /var/log/wtmp wa session; w /var/log/btmp wa session
    echo "-a always,exit -F arch=$arch -S adjtimex,settimeofday,clock_settime -k time-change"; w /etc/localtime wa time-change
    echo "-a always,exit -F arch=$arch -S sethostname,setdomainname -k system-locale"
    w /etc/issue wa system-locale; w /etc/issue.net wa system-locale; w /etc/hosts wa system-locale
    w /etc/selinux/ wa MAC-policy; w /etc/apparmor/ wa MAC-policy; w /etc/apparmor.d/ wa MAC-policy
    echo "-a always,exit -F arch=$arch -S chmod,fchmod,fchmodat -F auid>=$umin -F auid!=unset -k perm_mod"
    echo "-a always,exit -F arch=$arch -S chown,fchown,fchownat,lchown -F auid>=$umin -F auid!=unset -k perm_mod"
    echo "-a always,exit -F arch=$arch -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=$umin -F auid!=unset -k perm_mod"
    echo "-a always,exit -F arch=$arch -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=$umin -F auid!=unset -k access"
    echo "-a always,exit -F arch=$arch -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=$umin -F auid!=unset -k access"
    echo "-a always,exit -F arch=$arch -S mount -F auid>=$umin -F auid!=unset -k mounts"
    echo "-a always,exit -F arch=$arch -S unlink,unlinkat,rename,renameat -F auid>=$umin -F auid!=unset -k delete"
    echo "-a always,exit -F arch=$arch -S init_module,finit_module,delete_module -k modules"
    w /usr/bin/kmod x modules
    echo "-a always,exit -F arch=$arch -S execve -C uid!=euid -F euid=0 -k user_emulation"
    w /etc/crontab wa cron; w /etc/cron.d/ wa cron; w /var/spool/cron/ wa cron
    w /etc/ssh/sshd_config wa sshd; w /etc/systemd/system/ wa systemd
    # scored services' content and config - who changed it, and when (incident reports)
    local p
    for p in /var/www /etc/httpd /etc/apache2 /etc/nginx /etc/postfix /etc/dovecot /etc/aliases /etc/roundcube /etc/vsftpd.conf /etc/vsftpd /opt/splunk/etc/system/local /opt/splunk/etc/passwd; do
      w "$p" wa scored_service
    done
  } > "$AUDIT_RULES"
  chmod 640 "$AUDIT_RULES"
  # The SUID/SGID programs (CIS 4.1.3.6): every run is logged
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort | while read -r p; do
    echo "-a always,exit -F path=$p -F perm=x -F auid>=$umin -F auid!=unset -k privileged"
  done >> "$AUDIT_RULES"
}

# ============================================================================ packages
sec_packages() {
  h1 "packages: signed repositories, legacy clients (CIS 1.2, 2.3)"
  local bad=() f
  if [ "$FAMILY" = rpm ]; then
    grep -qsE '^\s*gpgcheck\s*=\s*(1|True|yes)' /etc/dnf/dnf.conf || bad+=("/etc/dnf/dnf.conf: gpgcheck not 1")
    for f in /etc/yum.repos.d/*.repo; do grep -qE '^\s*gpgcheck\s*=\s*0' "$f" && bad+=("$f: gpgcheck=0"); done
  else
    while IFS= read -r f; do bad+=("$f"); done < <(grep -rnsE 'trusted=yes|AllowUnauthenticated|AllowInsecureRepositories|AllowDowngradeToInsecureRepositories' /etc/apt/sources.list /etc/apt/sources.list.d /etc/apt/apt.conf.d 2>/dev/null)
  fi
  if [ ${#bad[@]} -eq 0 ]; then pass "package signatures are checked"
  else failc "unsigned packages accepted (a red team repo could push 'updates'):"; printf '         %s\n' "${bad[@]}"; fi
  local recent; recent="$(find /etc/yum.repos.d /etc/apt/sources.list.d -type f -newer /etc/hostname 2>/dev/null)"
  [ -n "$recent" ] && note "repo files changed since the box was set up: $(echo "$recent" | tr '\n' ' ') - check them"
  local legacy=(telnet inetutils-telnet rsh rsh-client rsh-redone-client talk ntalk nis yp-tools ypbind tftp tftp-hpa) have=() p
  for p in "${legacy[@]}"; do
    if [ "$FAMILY" = rpm ]; then rpm -q "$p" > /dev/null 2>&1 && have+=("$p")
    else dpkg-query -W -f '${db:Status-Abbrev}' "$p" 2>/dev/null | grep -q '^ii' && have+=("$p"); fi
  done
  if [ ${#have[@]} -eq 0 ]; then pass "no legacy cleartext client tools"
  else failc "legacy client tools installed: ${have[*]} (attackers use them; we don't)"; fi
  [ "$SEC_FAILS" -gt 0 ] || return
  if [ ${#bad[@]} -gt 0 ] && fixing "turn signature checks back on"; then
    if [ "$FAMILY" = rpm ]; then
      backup /etc/dnf/dnf.conf /etc/yum.repos.d/*.repo
      grep -qE '^\s*gpgcheck' /etc/dnf/dnf.conf && sed -i -E 's/^\s*gpgcheck\s*=.*/gpgcheck=1/' /etc/dnf/dnf.conf || sed -i '/^\[main\]/a gpgcheck=1' /etc/dnf/dnf.conf
      sed -i -E 's/^\s*gpgcheck\s*=\s*0/gpgcheck=1/' /etc/yum.repos.d/*.repo
    else
      for f in "${bad[@]}"; do f="${f%%:*}"; backup "$f"; sed -i -E 's/\[trusted=yes\]\s*//; s/^(\s*APT::Get::AllowUnauthenticated|\s*Acquire::AllowInsecureRepositories|\s*Acquire::AllowDowngradeToInsecureRepositories)/# CCDC-DISABLED \1/' "$f"; done
    fi
    pass "signature checks on (a repo without a valid key now fails instead of installing unsigned packages)"
  fi
  if [ ${#have[@]} -gt 0 ] && fixing "remove ${have[*]}"; then
    if [ "$FAMILY" = rpm ]; then dnf -y remove "${have[@]}" < /dev/null > /dev/null 2>&1; else apt-get purge -y "${have[@]}" < /dev/null > /dev/null 2>&1; fi && pass "removed"
  fi
}

# ============================================================================ files (report only)
sec_files() {
  h1 "files: world-writable and unowned files (CIS 6.1.10-12) - report only"
  local ww nouser
  local skip=(\( -path /opt/splunk/var -o -path /var/lib/docker -o -path /var/lib/containers -o -path /root/ccdc-vault \) -prune -o)
  ww="$(find / -xdev "${skip[@]}" -type f -perm -0002 -print 2>/dev/null | head -20)"
  [ -z "$ww" ] && pass "no world-writable files" || { failc "world-writable files (first 20):"; echo "$ww" | sed 's/^/         /'; info "fix each: chmod o-w <file> (check what uses it first)"; }
  local wd; wd="$(find / -xdev "${skip[@]}" -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | head -10)"
  [ -z "$wd" ] && pass "world-writable folders all have the sticky bit" || { failc "world-writable folders without sticky bit:"; echo "$wd" | sed 's/^/         /'; info "fix: chmod +t <folder>"; }
  nouser="$(find / -xdev "${skip[@]}" \( -nouser -o -nogroup \) -print 2>/dev/null | head -20)"
  [ -z "$nouser" ] && pass "every file has an owner" || { failc "files without an existing owner/group (deleted attacker account?):"; echo "$nouser" | sed 's/^/         /'; }
}

# ============================================================================ mac (report only)
sec_mac() {
  h1 "mac: mandatory access control (CIS 1.6) - report only"
  if command -v getenforce > /dev/null; then
    local m; m="$(getenforce)"
    [ "$m" = Enforcing ] && pass "SELinux Enforcing" || failc "SELinux $m - don't switch mid-competition without testing every scored service (setenforce 1, then test)"
    grep -qsE 'selinux=0|enforcing=0' /proc/cmdline && failc "SELinux disabled on the kernel command line"
  elif command -v aa-status > /dev/null; then
    aa-status --enabled 2>/dev/null && pass "AppArmor enabled ($(aa-status 2>/dev/null | grep -m1 'profiles are in enforce mode' | awk '{ print $1 }') profiles enforcing)" || failc "AppArmor not enabled"
    local c; c="$(aa-status 2>/dev/null | awk '/processes are unconfined but have a profile/ { print $1 }')"
    [ "${c:-0}" -gt 0 ] && note "$c process(es) unconfined but have a profile (restart them to confine)"
  else
    failc "no SELinux or AppArmor"
  fi
}

# ------------------------------------------------------------------ run
echo "cis.sh on $(hostname) - ${PRETTY_NAME:-$(. /etc/os-release 2>/dev/null; echo "$PRETTY_NAME")} - $(date) - $([ "$FIX" -eq 1 ] && echo fix || echo report)"
for s in modules mounts sysctl coredump perms cron banner accounts sudo su logging packages files mac; do
  want "$s" && "sec_$s"
done
echo
if [ "$FAILS" -eq 0 ]; then pass "every control passes"; else echo "${Y}$FAILS control(s) not passing$([ "$FIX" -eq 0 ] && echo ' - run with --fix to apply the safe fixes')${N}"; fi
[ -d "$BK" ] && info "backups of changed files: $BK"
info "Deliberate deviations and why: checklists/CIS.md. After fixes, if fim.sh runs: sudo bash linux/fim.sh accept /etc"
[ "$FAILS" -eq 0 ]
