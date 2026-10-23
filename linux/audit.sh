#!/bin/bash
# Linux password reset, password policy and persistence audit for CCDC.
#
# Usage: audit.sh COMMAND [options]
#   passwords          Change EVERY account password now and apply the password
#                      policy. Run this first. New passwords go to a root-only CSV
#                      in /root/ccdc for the password-change submission.
#   scan               Hunt for backdoors and persistence. Report-only by default.
#   all                passwords, then scan --fix
#   mysql              Change every MySQL/MariaDB account password (on the DB box)
#   app-password FILE  Put a new DB password into a web app config (on the web box,
#                      right after running mysql). Supports WordPress, OpenCart,
#                      PrestaShop, Roundcube and .env files.
#
# Options:
#   --one-password   passwords: one password you type for every account
#                    (default: you type yours, every other account gets a random one)
#   --fix            scan: offer to fix each finding, asking per item
#   --yes            scan --fix: apply every fix without asking
#   --config FILE    default: ../ccdc.conf
#
# Fixes never delete: files are moved to /root/ccdc/quarantine-*, edited files are
# backed up to /root/ccdc/backup-*, and disabled lines are commented, not removed.

set -u

CMD="${1:-}"; [ $# -gt 0 ] && shift
APP_FILE=""
[ "$CMD" = app-password ] && { APP_FILE="${1:-}"; [ $# -gt 0 ] && shift; }
ONE_PASSWORD=0
FIX=0
YES=0
CONFIG="$(dirname "$0")/../ccdc.conf"

usage() { sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --one-password) ONE_PASSWORD=1; shift ;;
    --fix)          FIX=1; shift ;;
    --yes)          YES=1; shift ;;
    --config)       CONFIG="$2"; shift 2 ;;
    *) usage ;;
  esac
done
case "$CMD" in passwords|scan|all|mysql|app-password) ;; *) usage ;; esac

SCORED_USERS=(); WEB_ROOTS=(/var/www); EXPECTED_PORTS=()
# shellcheck source=../ccdc.conf
[ -f "$CONFIG" ] && . "$CONFIG"

[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }

TS="$(date +%Y%m%d-%H%M%S)"
OUT=/root/ccdc
QDIR="$OUT/quarantine-$TS"
BDIR="$OUT/backup-$TS"
REPORT="$OUT/audit-$TS.txt"
umask 077
mkdir -p "$OUT" && chmod 700 "$OUT"

if [ -t 1 ]; then R='\e[31m'; Y='\e[33m'; G='\e[32m'; B='\e[1m'; N='\e[0m'; else R=; Y=; G=; B=; N=; fi
CRIT=0; WARN=0; LAST=""

say()     { echo -e "$*"; echo -e "$*" | sed 's/\x1b\[[0-9;]*m//g' >> "$REPORT"; }
section() { say "\n${B}== $* ==${N}"; }
crit()    { LAST=crit; CRIT=$((CRIT + 1)); say "${R}[CRITICAL]${N} $*"; logger -t ccdc-audit -p auth.crit "$*" 2>/dev/null; }
warn()    { LAST=warn; WARN=$((WARN + 1)); say "${Y}[WARN]${N} $*"; }
ok()      { say "${G}[OK]${N} $*"; }
info()    { say "    $*"; }

# ask_fix "description" -> 0 if the fix should be applied.
# --yes applies fixes for CRITICAL findings only; warnings always need a human.
ask_fix() {
  [ "$FIX" -eq 1 ] || return 1
  if [ "$YES" -eq 1 ]; then
    [ "$LAST" = crit ] && { info "fixing: $1"; return 0; }
    [ -t 0 ] || { info "not auto-fixed (warning - review by hand)"; return 1; }
  fi
  local a
  read -r -p "    Fix - $1? [y/N] " a < /dev/tty || return 1
  [[ "$a" =~ ^[Yy] ]]
}

backup()     { mkdir -p "$BDIR" && cp -a --parents "$1" "$BDIR/"; }
quarantine() { mkdir -p "$QDIR$(dirname "$1")" && mv -- "$1" "$QDIR$1" && info "moved to $QDIR$1"; }
comment_line() {
  backup "$1"
  sed -i "${2}s/^/# CCDC-DISABLED $TS: /" "$1" && info "commented out $1:$2 (backup in $BDIR)"
}

# Prints the given files that no installed package owns
unowned_raw() {
  [ $# -eq 0 ] && return
  if command -v dpkg-query > /dev/null; then
    dpkg-query -S "$@" 2>&1 >/dev/null | sed -n 's/^dpkg-query: no path found matching pattern //p'
  elif command -v rpm > /dev/null; then
    rpm -qf "$@" 2>/dev/null | sed -n 's/^file \(.*\) is not owned by any package$/\1/p'
  fi
}
# Merged-/usr systems: the package database may list /bin/x for /usr/bin/x and vice versa
unowned() {
  local f alt
  unowned_raw "$@" | while IFS= read -r f; do
    case "$f" in
      /usr/bin/*|/usr/sbin/*|/usr/lib/*|/usr/lib64/*) alt="${f#/usr}" ;;
      /bin/*|/sbin/*|/lib/*|/lib64/*) alt="/usr$f" ;;
      *) alt="" ;;
    esac
    { [ -n "$alt" ] && [ -z "$(unowned_raw "$alt")" ]; } || echo "$f"
  done
}

# flag FILE MESSAGE - CRITICAL for files no package owns, WARN for package files
# (packages legitimately use base64, /tmp, PROMPT_COMMAND...; still worth a look)
flag() {
  if [ -z "$(unowned "$1")" ]; then warn "$2 (file from a package - check it is expected)"; else crit "$2"; fi
}

# Commands, pipes and paths that show up in reverse shells and droppers
SUS='(/dev/(tcp|udp)/|bash -i|sh -i|(^|[^[:alnum:]_.-])(nc|ncat|netcat)([[:space:]]|$)|socat|mkfifo|(curl|wget)[^|;]*\|[[:space:]]*(ba|da|z)?sh|python[0-9.]* -c|perl -e|php -r|ruby -e|base64 (-d|--decode)|/dev/shm/|/tmp/|/var/tmp/|chmod [+ugo]*s|LD_PRELOAD)'

# ============================================================================
# PASSWORDS AND POLICY
# ============================================================================

gen_pass() {
  local p
  while :; do
    p="$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 16)"
    [[ "$p" =~ [A-Z] && "$p" =~ [a-z] && "$p" =~ [0-9] ]] && break
  done
  echo "$p"
}

# Letters, digits, - and _ only, so it is safe in chpasswd, SQL, PHP configs and DSNs
read_pass() {
  local p1 p2
  while :; do
    read -r -s -p "$1: " p1 < /dev/tty; echo > /dev/tty
    read -r -s -p "Again: " p2 < /dev/tty; echo > /dev/tty
    if [ "$p1" != "$p2" ]; then echo "Did not match." > /dev/tty
    elif [ ${#p1} -lt 12 ]; then echo "Use at least 12 characters." > /dev/tty
    elif [[ ! "$p1" =~ ^[A-Za-z0-9_-]+$ ]]; then echo "Letters, digits, - and _ only." > /dev/tty
    else echo "$p1"; return; fi
  done
}

is_scored() { local u; for u in "${SCORED_USERS[@]}"; do [ "$u" = "$1" ] && return 0; done; return 1; }

# set_kv FILE KEY VALUE SEPARATOR - replace every active "KEY ..." line, or append one.
# Comments are left alone (login.defs comments mention the keys too).
set_kv() {
  local f="$1" k="$2" v="$3" sep="$4"
  if grep -qE "^[[:space:]]*$k([[:space:]]|=|$)" "$f"; then
    sed -i -E "s/^[[:space:]]*$k([[:space:]]|=|$).*/$k$sep$v/" "$f"
  else
    echo "$k$sep$v" >> "$f"
  fi
}

change_passwords() {
  section "Changing every password"
  local admin="${SUDO_USER:-root}" one="" mine="" csv="$OUT/passwords-$TS.csv"
  local user hash pw note locked changed=0 failed=()

  cp /etc/shadow "$OUT/shadow.before-$TS" && chmod 600 "$OUT/shadow.before-$TS"
  if [ "$ONE_PASSWORD" -eq 1 ]; then
    one="$(read_pass "New password for ALL accounts")"
  else
    mine="$(read_pass "New password for $admin (you)")"
  fi
  echo "user,password,scored,note" > "$csv"

  while IFS=: read -r user hash _; do
    case "$hash" in '*'*|'!'|'!!'|'!*') continue ;; esac   # never had a password
    locked=0; note=""
    [[ "$hash" == '!'* ]] && { locked=1; note="locked - kept locked"; }
    [ -z "$hash" ] && note="had NO password"
    if [ -n "$one" ]; then pw="$one"
    elif [ "$user" = "$admin" ]; then pw="$mine"
    else pw="$(gen_pass)"; fi

    if echo "$user:$pw" | chpasswd 2>/dev/null; then
      [ "$locked" -eq 1 ] && usermod -L "$user"
      chage -m 0 -M 90 -W 7 "$user"
      echo "$user,$pw,$(is_scored "$user" && echo yes || echo no),$note" >> "$csv"
      changed=$((changed + 1))
    else
      failed+=("$user")
    fi
  done < "$OUT/shadow.before-$TS"

  ok "Changed $changed passwords. Record: $csv (root-only)"
  [ ${#failed[@]} -gt 0 ] && crit "Could not change: ${failed[*]}"
  local u
  for u in "${SCORED_USERS[@]}"; do
    grep -q "^$u," "$csv" || warn "Scored user '$u' has no password on this box - check the name"
  done
  if [ ${#SCORED_USERS[@]} -gt 0 ]; then
    say "\n${B}Submit these password changes for scored accounts NOW (Quotient > PCR tab, paste as-is):${N}"
    grep ',yes,' "$csv" | cut -d, -f1,2
  else
    warn "SCORED_USERS is empty in $CONFIG - make sure scored accounts' new passwords get submitted"
  fi
}

kick_sessions() {
  section "Other login sessions"
  local me u t rest
  me="$(tty 2>/dev/null | sed 's|^/dev/||')"
  local found=0
  while read -r u t rest; do
    [ "$t" = "$me" ] && continue
    found=1
    warn "Session: $u on $t $rest"
    local a
    read -r -p "    Kill it? (teammates too - ask first) [y/N] " a < /dev/tty
    [[ "$a" =~ ^[Yy] ]] && pkill -KILL -t "$t" && info "killed $t"
  done < <(who)
  if [ "$found" -eq 0 ]; then ok "No other sessions"; fi
}

apply_policy() {
  section "Password policy"
  local defs=/etc/login.defs method
  if [ -f "$defs" ]; then
    backup "$defs"
    set_kv "$defs" PASS_MAX_DAYS 90 " "
    set_kv "$defs" PASS_MIN_DAYS 0 " "      # 0 so you can change passwords again any time
    set_kv "$defs" PASS_WARN_AGE 7 " "
    method="$(awk '$1 == "ENCRYPT_METHOD" {print $2}' "$defs")"
    case "$method" in SHA512|YESCRYPT) ;; *) set_kv "$defs" ENCRYPT_METHOD SHA512 " " ;; esac
    ok "login.defs: max age 90 days, min age 0, warn 7 days, hashing ${method:-SHA512}"
  fi

  local pwq=/etc/security/pwquality.conf
  if [ -f "$pwq" ] || [ -d /etc/security ]; then
    [ -f "$pwq" ] && backup "$pwq"
    touch "$pwq"
    set_kv "$pwq" minlen 14 " = "
    set_kv "$pwq" minclass 3 " = "
    set_kv "$pwq" maxrepeat 3 " = "
    set_kv "$pwq" dictcheck 1 " = "
    set_kv "$pwq" usercheck 1 " = "
    grep -q '^enforce_for_root' "$pwq" || echo enforce_for_root >> "$pwq"
    ok "pwquality: 14+ chars, 3 character classes, dictionary check, applies to root"
  fi
  if grep -qs pam_pwquality /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth; then
    ok "pam_pwquality is active"
  else
    warn "pam_pwquality is NOT in the PAM password stack - install libpam-pwquality (Debian/Ubuntu) to enforce the rules above"
  fi
  if grep -qsE '^[^#].*pam_unix\.so.*nullok' /etc/pam.d/common-auth /etc/pam.d/system-auth /etc/pam.d/password-auth; then
    warn "PAM allows empty passwords (nullok). Every account has a password now, but remove nullok if you have time"
  fi
  if command -v sshd > /dev/null && sshd -T 2>/dev/null | grep -qi '^permitemptypasswords yes'; then
    crit "sshd allows empty passwords (PermitEmptyPasswords yes)"
  fi
  info "Account lockout is deliberately NOT enabled: the red team could use it to lock out scored users."

  say "\n${B}Passwords this script does NOT change - do these too:${N}"
  info "- MySQL/MariaDB accounts: audit.sh mysql on the DB box, then audit.sh app-password on the web box"
  info "- Web app admin logins (shop admin panel, Roundcube/Splunk admin users)"
  info "- Splunk admin: \$SPLUNK_HOME/bin/splunk edit user admin -password ... -auth admin:OLD (Splunk logins are scored: submit via PCR)"
  command -v pdbedit > /dev/null && info "- Samba: has its own password database (smbpasswd <user>)"
  info "- Firewall / router / Windows / AD accounts, SQL Server logins"
}

cmd_passwords() {
  REPORT="$OUT/passwords-$TS.log"
  change_passwords
  apply_policy
  kick_sessions
}

# ============================================================================
# SCAN
# ============================================================================

check_accounts() {
  section "Accounts"
  local u uid_min shell
  uid_min="$(awk '$1 == "UID_MIN" {print $2}' /etc/login.defs 2>/dev/null)"; uid_min="${uid_min:-1000}"
  shell="$(command -v nologin || echo /sbin/nologin)"

  for u in $(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd); do
    if [[ "$(getent shadow "$u" | cut -d: -f2)" == '!'* ]] && [[ "$(getent passwd "$u" | cut -d: -f7)" == */nologin ]]; then
      warn "UID 0 account besides root: $u (locked, nologin - delete it once you have checked it: userdel $u)"
      continue
    fi
    crit "UID 0 account besides root: $u"
    ask_fix "lock $u and set its shell to nologin" && { backup /etc/passwd; backup /etc/shadow; usermod -L -s "$shell" "$u"; }
  done
  for u in $(awk -F: '$2 == "" {print $1}' /etc/shadow); do
    crit "Account with NO password: $u"
    ask_fix "lock $u" && usermod -L "$u"
  done
  while read -r line; do warn "System account with a login shell: $line"; done < <(
    awk -F: -v min="$uid_min" '$3 < min && $3 != 0 && $7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1 " (uid " $3 ", " $7 ")"}' /etc/passwd)
  info "Regular accounts (compare with the competition's user list):"
  awk -F: -v min="$uid_min" '$3 >= min && $3 < 60000 {print "      " $1 " uid=" $3 " shell=" $7}' /etc/passwd | tee -a "$REPORT"
  for g in sudo wheel admin; do
    getent group "$g" > /dev/null && info "Group $g: $(getent group "$g" | cut -d: -f4)"
  done
}

check_sudoers() {
  section "Sudoers"
  local f line n
  for f in /etc/sudoers /etc/sudoers.d/*; do
    [ -f "$f" ] || continue
    while IFS=: read -r n line; do
      crit "$f:$n: $line"
      if ask_fix "comment out this sudoers line"; then
        comment_line "$f" "$n"
        if ! visudo -c > /dev/null 2>&1; then
          cp -a "$BDIR$f" "$f"; crit "visudo check failed - restored $f"
        fi
      fi
    done < <(grep -nE '^[^#]*(NOPASSWD|!authenticate)' "$f")
  done
  visudo -c > /dev/null 2>&1 && ok "sudoers syntax OK" || crit "sudoers has syntax errors (visudo -c)"
}

check_ssh() {
  section "SSH keys and config"
  local user home f n
  declare -A seen=()
  while IFS=: read -r user _ _ _ _ home _; do
    for f in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
      [ -f "$f" ] && [ -z "${seen[$f]:-}" ] || continue
      seen[$f]=1
      n="$(grep -cvE '^\s*(#|$)' "$f")"
      crit "$f: $n key(s): $(awk '!/^[[:space:]]*(#|$)/ {print $NF}' "$f" | tr '\n' ' ')"
      ask_fix "quarantine $f (keys count as compromised too)" && quarantine "$f"
    done
  done < /etc/passwd
  if command -v sshd > /dev/null; then
    local akf
    akf="$(sshd -T 2>/dev/null | awk '$1 == "authorizedkeysfile" {$1 = ""; print}')"
    [[ "$akf" =~ ^\ *\.ssh/authorized_keys(\ \.ssh/authorized_keys2)?\ *$ ]] || crit "sshd AuthorizedKeysFile is non-default:$akf"
    sshd -T 2>/dev/null | grep -qi '^permitrootlogin yes' && warn "sshd allows root login with a password"
    sshd -T 2>/dev/null | grep -qi '^authorizedkeyscommand ' && crit "sshd has an AuthorizedKeysCommand: $(sshd -T 2>/dev/null | grep -i '^authorizedkeyscommand ')"
  fi
}

check_cron() {
  section "Cron, at and timers"
  local f n line
  for f in /etc/crontab /etc/anacrontab /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* \
           /etc/cron.weekly/* /etc/cron.monthly/* /var/spool/cron/* /var/spool/cron/crontabs/*; do
    [ -f "$f" ] || continue
    case "$f" in
      /var/spool/cron/*)
        grep -vqE '^\s*(#|$)' "$f" && warn "User crontab $f:" &&
          grep -nvE '^\s*(#|$)' "$f" | sed 's/^/      /' | tee -a "$REPORT" ;;
    esac
    while IFS=: read -r n line; do
      flag "$f" "$f:$n: $line"
      ask_fix "comment out this line" && comment_line "$f" "$n"
    done < <(grep -nE "$SUS" "$f" | grep -vE '^[0-9]+:\s*#')
  done
  if command -v atq > /dev/null && [ -n "$(atq 2>/dev/null)" ]; then
    warn "Pending at jobs (inspect with: at -c <id>):"
    atq | sed 's/^/      /' | tee -a "$REPORT"
  fi
}

check_systemd() {
  section "Systemd units"
  command -v systemctl > /dev/null || { info "no systemd"; return; }
  local f unit n line files=()
  for f in /etc/systemd/system/*.service /etc/systemd/system/*.timer; do
    [ -f "$f" ] && [ ! -L "$f" ] && info "Admin-created unit: $f"
  done
  while IFS= read -r f; do files+=("$f"); done < <(
    find /etc/systemd /lib/systemd/system /usr/lib/systemd/system /run/systemd/system \
         /home/*/.config/systemd /root/.config/systemd -type f \( -name '*.service' -o -name '*.timer' \) 2>/dev/null)
  for f in "${files[@]}"; do
    while IFS=: read -r n line; do
      unit="$(basename "$f")"
      crit "$f:$n: $line"
      if ask_fix "stop and disable $unit, quarantine its file"; then
        systemctl disable --now "$unit" 2>/dev/null
        quarantine "$f"; systemctl daemon-reload
      fi
    done < <(grep -nE '^\s*Exec' "$f" | grep -E "$SUS")
  done
  while IFS= read -r f; do
    warn "Unit file not owned by any package: $f"
  done < <(unowned $(printf '%s\n' "${files[@]}" | grep -E '^/(usr/)?lib/systemd/system/'))
}

check_preload_pam() {
  section "Preload and PAM"
  if [ -s /etc/ld.so.preload ]; then
    crit "/etc/ld.so.preload is set (classic rootkit): $(tr '\n' ' ' < /etc/ld.so.preload)"
    ask_fix "quarantine /etc/ld.so.preload" && quarantine /etc/ld.so.preload
  else
    ok "/etc/ld.so.preload empty"
  fi
  grep -qs LD_PRELOAD /etc/environment && crit "LD_PRELOAD set in /etc/environment"

  local f n line
  while IFS=: read -r f n line; do
    crit "$f:$n: $line"
    ask_fix "comment out this PAM line" && comment_line "$f" "$n"
  done < <(grep -rnE '^[^#]*(sufficient|optional)?[[:space:]]+pam_permit\.so' /etc/pam.d 2>/dev/null | grep -E 'sufficient' ;
           grep -rnE '^[^#]*pam_exec\.so' /etc/pam.d 2>/dev/null)
  local mods=()
  while IFS= read -r f; do mods+=("$f"); done < <(find /lib /lib64 /usr/lib /usr/lib64 -path '*security/*.so' -type f 2>/dev/null)
  while IFS= read -r f; do crit "PAM module not owned by any package: $f"; done < <(unowned "${mods[@]}")
}

check_integrity() {
  section "Package integrity (trojaned binaries)"
  local out
  if command -v dpkg > /dev/null; then
    out="$(dpkg -V openssh-server openssh-client sudo passwd login libpam-modules libpam-runtime coreutils \
             procps iproute2 net-tools util-linux bash findutils grep cron systemd 2>/dev/null)"
  elif command -v rpm > /dev/null; then
    out="$(rpm -V openssh-server openssh-clients sudo shadow-utils pam coreutils procps-ng iproute \
             net-tools util-linux bash findutils grep cronie systemd 2>/dev/null)"
  fi
  # 3rd column '5' = content changed; ' c ' = config file (changes there are normal)
  out="$(printf '%s\n' "$out" | awk 'substr($1, 3, 1) == "5" && $2 != "c"')"
  if [ -n "$out" ]; then
    while read -r line; do crit "Modified system binary: $line"; done <<< "$out"
    info "Reinstall the owning package to fix (apt install --reinstall / dnf reinstall)"
  else
    ok "Core packages verify clean"
  fi
}

check_suid() {
  section "SUID/SGID files"
  local f name gtfo='^(bash|sh|dash|zsh|ksh|csh|find|vim?|nano|less|more|cp|mv|python[0-9.]*|perl|ruby|php[0-9.]*|node|nmap|awk|gawk|mawk|env|tar|zip|gdb|strace|tee|dd|base64|xxd|socat|nc|ncat|wget|curl|chmod|chown|rsync|git|make|ed|busybox|docker)$'
  local all=()
  while IFS= read -r f; do all+=("$f"); done < <(
    find / \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /snap -o -path "$OUT" -o -path /timeshift \
       -o -path /var/lib/docker -o -path /var/lib/containers -o -path /var/lib/lxc \) -prune -o \
         -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null)
  for f in "${all[@]}"; do
    name="$(basename "$f")"
    if [[ "$name" =~ $gtfo ]] || [[ "$f" =~ ^/(tmp|var/tmp|dev/shm|home|var/www|srv)/ ]]; then
      crit "SUID/SGID shell-escape binary or odd location: $(ls -l "$f")"
      ask_fix "remove the SUID/SGID bits from $f" && chmod u-s,g-s "$f"
    fi
  done
  while IFS= read -r f; do
    warn "SUID/SGID file not owned by any package: $(ls -l "$f")"
    ask_fix "remove the SUID/SGID bits from $f" && chmod u-s,g-s "$f"
  done < <(unowned "${all[@]}")
  info "${#all[@]} SUID/SGID files total; package-owned ones are left alone"
}

check_processes() {
  section "Processes and connections"
  local p pid exe cmd
  for p in /proc/[0-9]*; do
    pid="${p#/proc/}"
    exe="$(readlink "$p/exe" 2>/dev/null)" || continue
    cmd="$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null | cut -c1-120)"
    if [[ "$exe" =~ ^/(tmp|var/tmp|dev/shm)/ ]]; then
      crit "Process running from a temp dir: pid $pid $exe ($cmd)"
    elif [[ "$exe" == *' (deleted)' ]]; then
      warn "Process whose binary was deleted (malware, or just a package upgrade): pid $pid $exe ($cmd)"
      continue
    else
      continue
    fi
    if ask_fix "save a copy of pid $pid's binary and kill it"; then
      mkdir -p "$QDIR/proc"; cp "$p/exe" "$QDIR/proc/$pid.bin" 2>/dev/null; kill -9 "$pid"
    fi
  done

  # Shells and interpreters holding network sockets = reverse/bind shells
  local line
  while IFS= read -r line; do
    crit "Shell/interpreter with a network socket: $line"
    for pid in $(grep -oE 'pid=[0-9]+' <<< "$line" | cut -d= -f2 | sort -u); do
      ask_fix "kill pid $pid ($(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | cut -c1-80))" && kill -9 "$pid"
    done
  done < <(ss -tunapH 2>/dev/null | grep -E 'users:\(\("(bash|sh|dash|zsh|ksh|python[0-9.]*|perl|php[0-9.]*|ruby|nc|ncat|netcat|socat|telnet)"')

  # A reverse shell can exec into another program name, so list every outside connection
  info "Established connections to other hosts (check anything you don't recognise):"
  ss -tnpH state established 2>/dev/null | awk '$4 !~ /^(127\.|\[::1\])/ {print "      " $3 " -> " $4 "  " $5}' | tee -a "$REPORT"

  section "Listening ports"
  local port expected
  while IFS= read -r line; do
    [[ "$line" =~ \ (127\.[0-9.]+|\[::1\]|[^ ]*%lo): ]] && continue   # loopback only
    port="$(awk '{print $2}' <<< "$line" | awk -F: '{print $NF}')"
    # UDP sockets in the ephemeral range are clients (DNS lookups etc.); multicast is mDNS
    [[ "$line" == udp* ]] && { [ "$port" -ge 32768 ] 2>/dev/null || [[ "$line" =~ \ 224\. ]]; } && continue
    expected=1
    if [ ${#EXPECTED_PORTS[@]} -gt 0 ]; then
      expected=0
      for p in "${EXPECTED_PORTS[@]}"; do [ "$p" = "$port" ] && expected=1; done
    fi
    if [ "$expected" -eq 1 ]; then info "$line"; else warn "Unexpected listener: $line"; fi
  done < <(ss -tulnpH 2>/dev/null | awk '{print $1, $5, $7}')
}

check_shell_startup() {
  section "Shell startup files"
  local f n line home
  local files=(/etc/profile /etc/profile.d/*.sh /etc/bash.bashrc /etc/bashrc /etc/environment /etc/rc.local /etc/rc.d/rc.local)
  while IFS=: read -r _ _ _ _ _ home _; do
    files+=("$home/.bashrc" "$home/.bash_profile" "$home/.profile" "$home/.bash_login" "$home/.bash_logout" "$home/.zshrc")
  done < /etc/passwd
  for f in $(printf '%s\n' "${files[@]}" | sort -u); do
    [ -f "$f" ] || continue
    while IFS=: read -r n line; do
      flag "$f" "$f:$n: $line"
      ask_fix "comment out this line" && comment_line "$f" "$n"
    done < <(grep -nE "$SUS|alias[[:space:]]+[a-z]+=.*([;|&\`]|\\$\(|/tmp|/dev/shm)|PROMPT_COMMAND|trap[[:space:]].*(DEBUG|EXIT)" "$f" | grep -vE '^[0-9]+:\s*#')
  done
  for f in /etc/rc.local /etc/rc.d/rc.local; do
    [ -f "$f" ] && grep -vqE '^\s*(#|$|exit 0)' "$f" && warn "$f has commands - review it"
  done
}

check_web() {
  section "Webshells and web app credentials"
  local roots=() r f
  for r in "${WEB_ROOTS[@]}"; do [ -d "$r" ] && roots+=("$r"); done
  [ ${#roots[@]} -eq 0 ] && { info "No web roots found"; return; }
  local shellpat='eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_(GET|POST|REQUEST|COOKIE))|(system|exec|shell_exec|passthru|popen|proc_open|assert|pcntl_exec)[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST|COOKIE)|\$_(GET|POST|REQUEST|COOKIE)\[[^]]{1,30}\][[:space:]]*\(|preg_replace[[:space:]]*\(.*/e[^/]*,'
  while IFS= read -r f; do
    crit "Possible webshell: $f"
    grep -nE "$shellpat" "$f" | head -n 3 | cut -c1-160 | sed 's/^/      /' | tee -a "$REPORT"
    ask_fix "quarantine $f (check the site still works after)" && quarantine "$f"
  done < <(grep -rlIE --include='*.php' --include='*.php[0-9]' --include='*.phtml' --include='*.inc' \
             --include='*.jsp' "$shellpat" "${roots[@]}" 2>/dev/null)
  while IFS= read -r f; do
    info "Web app config with a DB password (change it with app-password after mysql): $f"
  done < <(grep -rlIE --include='*.php' --include='.env' "DB_PASSWORD|database_password|_DB_PASSWD_|db_dsnw" "${roots[@]}" 2>/dev/null)
}

cmd_scan() {
  say "CCDC audit of $(hostname) at $(date)"
  [ "$FIX" -eq 1 ] && say "Fix mode: $([ "$YES" -eq 1 ] && echo 'applying ALL fixes' || echo 'asking per finding')"
  check_accounts
  check_sudoers
  check_ssh
  check_cron
  check_systemd
  check_preload_pam
  check_integrity
  check_suid
  check_processes
  check_shell_startup
  check_web
  section "Summary"
  say "${R}Critical: $CRIT${N}   ${Y}Warnings: $WARN${N}"
  say "Report: $REPORT"
  [ -d "$QDIR" ] && say "Quarantined files: $QDIR"
  [ -d "$BDIR" ] && say "Backups of edited files: $BDIR"
  [ "$CRIT" -gt 0 ] && return 2
  [ "$WARN" -gt 0 ] && return 1
  return 0
}

# ============================================================================
# DATABASE PASSWORDS
# ============================================================================

cmd_mysql() {
  REPORT="$OUT/mysql-$TS.log"
  local client
  client="$(command -v mysql || command -v mariadb)" || { echo "No mysql client here - run this on the DB box"; exit 1; }
  local cnf="$OUT/.my.cnf-$TS" csv="$OUT/mysql-passwords-$TS.csv"
  trap "rm -f '$cnf'" EXIT     # expanded now: $cnf is local and gone by the time the script exits
  : > "$cnf"
  # Root over the local socket first (Ubuntu default), else ask for the current password
  if ! "$client" --defaults-extra-file="$cnf" -uroot -e 'SELECT 1' > /dev/null 2>&1; then
    local cur
    read -r -s -p "Current MySQL root password: " cur < /dev/tty; echo
    printf '[client]\npassword="%s"\n' "$cur" > "$cnf"
  fi
  sql() { "$client" --defaults-extra-file="$cnf" -uroot -N -B -e "$1"; }
  sql 'SELECT 1' > /dev/null || { echo "Cannot log in to MySQL as root"; exit 1; }

  section "MySQL accounts"
  local accounts
  # MariaDB lists roles (PUBLIC, ...) in mysql.user too - they have no password; MySQL has no is_role column
  accounts="$(sql "SELECT CONCAT(User, '|', Host, '|', IFNULL(plugin, '')) FROM mysql.user WHERE is_role <> 'Y'" 2>/dev/null ||
              sql "SELECT CONCAT(User, '|', Host, '|', IFNULL(plugin, '')) FROM mysql.user")"
  local root_pw new user host plugin
  root_pw="$(read_pass "New MySQL root password")"
  echo "user,host,password" > "$csv"
  declare -A newpw=()
  while IFS='|' read -r user host plugin; do
    if [ -z "$user" ]; then
      crit "Anonymous MySQL account @'$host'"
      FIX=1; ask_fix "drop it" && sql "DROP USER ''@'$host'"
      continue
    fi
    case "$user" in mysql.sys|mysql.session|mysql.infoschema|mariadb.sys) continue ;; esac
    case "$plugin" in auth_socket|unix_socket)
      info "$user@$host logs in by OS user only (no password to steal) - skipped"; continue ;; esac
    if [ "$user" = root ]; then new="$root_pw"
    else new="${newpw[$user]:-$(gen_pass)}"; fi   # same user on several hosts gets one password
    newpw[$user]="$new"
    if sql "ALTER USER '$user'@'$host' IDENTIFIED BY '$new'" 2>/dev/null ||
       sql "SET PASSWORD FOR '$user'@'$host' = PASSWORD('$new')"; then   # MySQL < 5.7.6
      echo "$user,$host,$new" >> "$csv"; ok "changed $user@$host"
      [ "$user" = root ] && printf '[client]\npassword="%s"\n' "$new" > "$cnf"
    else
      crit "could not change $user@$host"
    fi
    [ "$user" = debian-sys-maint ] && [ -f /etc/mysql/debian.cnf ] && {
      backup /etc/mysql/debian.cnf
      sed -i -E "s/^(password[[:space:]]*=[[:space:]]*).*/\1$new/" /etc/mysql/debian.cnf
      info "updated /etc/mysql/debian.cnf to match"
    }
  done <<< "$accounts"
  sql 'FLUSH PRIVILEGES'
  ok "New MySQL passwords: $csv (root-only)"
  say "\n${B}The web app's DB user just changed - the site is down until you run, on the web box:${N}"
  info "sudo ./audit.sh app-password /path/to/app/config.php"
  info "and paste that user's new password from $csv"
}

cmd_app_password() {
  REPORT="$OUT/app-password-$TS.log"
  local f="$APP_FILE"
  [ -f "$f" ] || { echo "Usage: audit.sh app-password /path/to/config.php"; exit 1; }
  f="$(realpath "$f")"
  # Line number and current value of the DB password, per app format
  local found
  found="$(awk '
    match($0, /define\([[:space:]]*["'\''](DB_PASSWORD|_DB_PASSWD_)["'\''][[:space:]]*,[[:space:]]*["'\'']/) {
      rest = substr($0, RSTART + RLENGTH); q = substr($0, RSTART + RLENGTH - 1, 1)
      print NR "\t" substr(rest, 1, index(rest, q) - 1); exit }
    match($0, /["'\'']database_password["'\''][[:space:]]*=>[[:space:]]*["'\'']/) {
      rest = substr($0, RSTART + RLENGTH); q = substr($0, RSTART + RLENGTH - 1, 1)
      print NR "\t" substr(rest, 1, index(rest, q) - 1); exit }
    match($0, /db_dsnw.*:\/\/[^:\/@]+:/) {
      rest = substr($0, RSTART + RLENGTH); print NR "\t" substr(rest, 1, index(rest, "@") - 1); exit }
    match($0, /^[[:space:]]*\$dbpass[[:space:]]*=[[:space:]]*["'\'']/) {      # Debian/Ubuntu roundcube: debian-db.php
      rest = substr($0, RSTART + RLENGTH); q = substr($0, RSTART + RLENGTH - 1, 1)
      print NR "\t" substr(rest, 1, index(rest, q) - 1); exit }
    match($0, /^DB_PASSWORD=/) {
      v = substr($0, RLENGTH + 1); gsub(/^["'\'']|["'\'']$/, "", v); print NR "\t" v; exit }
  ' "$f")"
  [ -n "$found" ] || { echo "Could not find a DB password in $f (supported: WordPress, OpenCart, PrestaShop, Roundcube incl. debian-db.php, .env)"; exit 1; }
  local n old new
  n="${found%%$'\t'*}"; old="${found#*$'\t'}"
  echo "Found the DB password on line $n of $f"
  new="$(read_pass "New DB password (paste it from the mysql CSV)")"
  backup "$f"
  # Replace the old value on that line only, literally (no regex surprises)
  awk -v n="$n" -v old="$old" -v new="$new" 'NR == n { i = index($0, old); if (old != "" && i) $0 = substr($0, 1, i - 1) new substr($0, i + length(old)) } { print }' \
    "$BDIR$f" > "$f"   # writes in place: owner and permissions stay
  if grep -qF -- "$new" "$f"; then
    ok "Updated $f (backup in $BDIR). Load the site now to confirm it works."
  else
    cp -a "$BDIR$f" "$f"; crit "Update failed - original restored"
  fi
}

case "$CMD" in
  passwords)    cmd_passwords; [ "$CRIT" -eq 0 ] ;;
  scan)         cmd_scan; exit $? ;;
  all)          cmd_passwords; FIX=1; REPORT="$OUT/audit-$TS.txt"; cmd_scan; exit $? ;;
  mysql)        cmd_mysql; [ "$CRIT" -eq 0 ] ;;
  app-password) cmd_app_password; [ "$CRIT" -eq 0 ] ;;
esac
