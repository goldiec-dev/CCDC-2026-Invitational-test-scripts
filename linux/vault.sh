#!/bin/bash
# Off-box backup vault: a short, locked-down window for the other boxes to upload their
# (encrypted) backups to this box, closed again automatically.
#
# Usage (on the vault box - BACKUP_VAULT in ccdc.conf - as root, from its console):
#   sudo linux/vault.sh open  [--minutes N]          upload window, default 15 minutes
#   sudo linux/vault.sh serve FILE [--minutes N]     window that hands a stored backup back (restore)
#   sudo linux/vault.sh list                         stored backups and their checksum status
#   sudo linux/vault.sh close                        close the window now (also happens by itself)
#
# While a window is open:
#   - its own SSH server (not the scored one, which is left alone) on BACKUP_VAULT_PORT, on the
#     LAN address only, firewall hole from INSIDE only
#   - one account, ccdc-vault, with a fresh random password shown here; SFTP only, locked in
#     /srv/ccdc-vault, no shell, no forwarding, no tunnels; uploads go to a folder it can't list
# When the time is up, you press Enter, or the console drops: the server stops, the firewall hole
# closes, the account is locked, and each upload is checked against its .sha256 and moved to
# /root/ccdc-vault/<host>/ (root-only). Uploads are encrypted by offbox.sh - this box can't read them.

set -u
CMD="${1:-}"; [ $# -gt 0 ] && shift
SERVE_FILE=""
[ "$CMD" = serve ] && { SERVE_FILE="${1:-}"; [ $# -gt 0 ] && shift; }
MINUTES=15; AUTO=0
CONFIG="$(dirname "$0")/../ccdc.conf"
usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --minutes) MINUTES="$2"; shift 2 ;;
    --config)  CONFIG="$2"; shift 2 ;;
    --auto)    AUTO=1; shift ;;
    *) usage ;;
  esac
done
case "$CMD" in open|serve|list|close) ;; *) usage ;; esac
[[ "$MINUTES" =~ ^[0-9]+$ ]] && [ "$MINUTES" -ge 1 ] && [ "$MINUTES" -le 120 ] || { echo "--minutes: 1-120"; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)"; exit 1; }
INSIDE=""; BACKUP_VAULT_PORT=2222
# shellcheck source=../ccdc.conf
[ -f "$CONFIG" ] && . "$CONFIG"

SELF="$(realpath "$0")"
VUSER=ccdc-vault
CHROOT=/srv/ccdc-vault
STORE=/root/ccdc-vault
RUN=/root/ccdc/vault
PORT="${BACKUP_VAULT_PORT:-2222}"
SSHD="$(command -v sshd || echo /usr/sbin/sshd)"
umask 077
mkdir -p "$RUN" "$STORE" && chmod 700 "$RUN" "$STORE"

if [ -t 1 ]; then R=$'\e[31m'; Y=$'\e[33m'; G=$'\e[32m'; B=$'\e[1m'; N=$'\e[0m'; else R=; Y=; G=; B=; N=; fi
ok()   { echo "${G}[OK]${N}   $*"; }
warn() { echo "${Y}[WARN]${N} $*"; }
fail() { echo "${R}[FAIL]${N} $*"; }

# Firewall hole: TCP PORT, new connections from INSIDE only
RULE=(-p tcp)
[ -n "$INSIDE" ] && RULE+=(-s "$INSIDE")
RULE+=(--dport "$PORT" -m conntrack --ctstate NEW -m comment --comment ccdc-vault -j ACCEPT)

ip2int() { local IFS=.; read -r a b c d <<< "$1"; echo $(( (a << 24) + (b << 16) + (c << 8) + d )); }
in_cidr() { local bits="${2#*/}" m; m=$(( bits == 0 ? 0 : (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
            [ $(( $(ip2int "$1") & m )) -eq $(( $(ip2int "${2%/*}") & m )) ]; }
lan_ip() {
  local a
  for a in $(ip -o -4 addr show 2>/dev/null | awk '{ split($4, x, "/"); print x[1] }'); do
    [[ "$INSIDE" == */* ]] && in_cidr "$a" "$INSIDE" && { echo "$a"; return; }
  done
}

# ------------------------------------------------------------------ close (idempotent)
do_close() {
  # the timer runs this too; stop it unless we ARE the timer
  if [ "$AUTO" -eq 0 ] && [ -f "$RUN/timer.pid" ]; then kill "$(cat "$RUN/timer.pid")" 2>/dev/null; fi
  rm -f "$RUN/timer.pid"
  [ -f "$RUN/sshd.pid" ] && kill "$(cat "$RUN/sshd.pid")" 2>/dev/null
  pkill -f "sshd -f $RUN/sshd_config" 2>/dev/null
  pkill -f "sshd: $VUSER" 2>/dev/null; pkill -u "$VUSER" 2>/dev/null     # sessions still connected
  rm -f "$RUN/sshd.pid"
  if command -v iptables > /dev/null; then
    while iptables -D INPUT "${RULE[@]}" 2>/dev/null; do :; done
  fi
  if [ -f "$RUN/semanage-added" ]; then
    semanage port -d -t ssh_port_t -p tcp "$PORT" 2>/dev/null; rm -f "$RUN/semanage-added"
  fi
  if id "$VUSER" > /dev/null 2>&1; then usermod -L "$VUSER" 2>/dev/null; chage -E 0 "$VUSER" 2>/dev/null; fi

  # Collect uploads: check each against its .sha256, move it out of the account's reach
  local f name host status got=0
  for f in "$CHROOT"/incoming/*; do
    [ -f "$f" ] || continue
    name="$(basename "$f")"
    [[ "$name" == *.sha256 ]] && continue
    host="${name%%__*}"; [ "$host" = "$name" ] && host=unsorted
    host="${host//[^A-Za-z0-9._-]/_}"
    mkdir -p "$STORE/$host" && chmod 700 "$STORE/$host"
    if [ -f "$f.sha256" ]; then
      (cd "$CHROOT/incoming" && sha256sum --status -c "$name.sha256" 2>/dev/null) && status=OK || status="CHECKSUM MISMATCH"
      mv -f "$f.sha256" "$STORE/$host/"
    else
      status="no .sha256"
    fi
    mv -f "$f" "$STORE/$host/" && chmod 600 "$STORE/$host/$name"
    got=$((got + 1))
    logger -t ccdc-vault "stored $name ($status)" 2>/dev/null
    [ "$AUTO" -eq 0 ] && { [ "$status" = OK ] && ok "received $host/$name ($(du -h "$STORE/$host/$name" | cut -f1))" || fail "received $host/$name - $status"; }
  done
  for f in "$CHROOT"/incoming/*; do [ -e "$f" ] && { mkdir -p "$STORE/unsorted"; mv -f "$f" "$STORE/unsorted/"; }; done
  rm -f "$CHROOT"/outgoing/* 2>/dev/null
  [ -f "$RUN/open" ] && logger -t ccdc-vault "window closed ($got upload(s))" 2>/dev/null
  rm -f "$RUN/open"
  [ "$AUTO" -eq 0 ] && ok "window closed: server stopped, port $PORT closed, $VUSER locked ($got upload(s) stored in $STORE)"
}

# ------------------------------------------------------------------ open
do_open() {
  [ -f "$RUN/open" ] && { warn "a window was still open - closing it first"; do_close; }
  [ -x "$SSHD" ] || { fail "no sshd binary (install openssh-server - the scored SSH service is not touched)"; exit 1; }
  ls /etc/ssh/ssh_host_*_key > /dev/null 2>&1 || ssh-keygen -A > /dev/null

  # Account and folders (ChrootDirectory must be root-owned and not writable by others)
  if ! id "$VUSER" > /dev/null 2>&1; then
    useradd -r -M -d "$CHROOT" -s "$(command -v nologin || echo /sbin/nologin)" "$VUSER" || { fail "useradd failed"; exit 1; }
  fi
  mkdir -p "$CHROOT/incoming" "$CHROOT/outgoing"
  chown root:root "$CHROOT" "$CHROOT/outgoing"; chmod 755 "$CHROOT"; chmod 711 "$CHROOT/outgoing"
  chown "$VUSER:$VUSER" "$CHROOT/incoming"; chmod 330 "$CHROOT/incoming"     # write, but no listing
  if [ -n "$SERVE_FILE" ]; then
    local src="$SERVE_FILE"
    [ -f "$src" ] || src="$(find "$STORE" -type f -name "$(basename "$SERVE_FILE")" -print -quit)"
    [ -n "$src" ] && [ -f "$src" ] || { fail "not found: $SERVE_FILE (see: vault.sh list)"; exit 1; }
    install -m 644 -o root -g root "$src" "$CHROOT/outgoing/"
    [ -f "$src.sha256" ] && install -m 644 -o root -g root "$src.sha256" "$CHROOT/outgoing/"
    SERVE_NAME="$(basename "$src")"
  fi

  local pw ip keys="" k
  # 20 random characters with upper case, lower case and digits (passes the password policy)
  while :; do
    pw="$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 20)"
    [[ "$pw" =~ [A-Z] && "$pw" =~ [a-z] && "$pw" =~ [0-9] ]] && break
  done
  echo "$VUSER:$pw" | chpasswd || { fail "couldn't set the $VUSER password (password policy?)"; do_close; exit 1; }
  usermod -U "$VUSER" 2>/dev/null; chage -E -1 "$VUSER"
  ip="$(lan_ip)"
  for k in /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ecdsa_key /etc/ssh/ssh_host_rsa_key; do
    [ -f "$k" ] && keys+="HostKey $k"$'\n'
  done
  cat > "$RUN/sshd_config" <<EOF
# CCDC vault window (linux/vault.sh) - a separate sshd, stopped when the window closes
Port $PORT
${ip:+ListenAddress $ip}
${keys}PidFile $RUN/sshd.pid
AllowUsers $VUSER
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
ChrootDirectory $CHROOT
ForceCommand internal-sftp -u 0077 -l INFO
Subsystem sftp internal-sftp -u 0077 -l INFO
AllowTcpForwarding no
AllowAgentForwarding no
AllowStreamLocalForwarding no
X11Forwarding no
PermitTunnel no
PermitTTY no
PermitUserRC no
MaxAuthTries 3
LoginGraceTime 30
MaxSessions 2
MaxStartups 5:50:10
ClientAliveInterval 30
LogLevel VERBOSE
SyslogFacility AUTH
EOF
  mkdir -p /run/sshd && chmod 755 /run/sshd      # privilege-separation folder (Debian/Ubuntu)
  # SELinux (Rocky): sshd may only bind ports labelled ssh_port_t
  if command -v getenforce > /dev/null && [ "$(getenforce)" = Enforcing ]; then
    if ! semanage port -l 2>/dev/null | grep -qE "^ssh_port_t .*[ ,]$PORT(,|$)"; then
      if semanage port -a -t ssh_port_t -p tcp "$PORT" 2>/dev/null; then touch "$RUN/semanage-added"
      else warn "SELinux: couldn't label port $PORT for sshd (dnf install policycoreutils-python-utils)"; fi
    fi
  fi
  "$SSHD" -t -f "$RUN/sshd_config" 2> "$RUN/sshd-t.txt" || { fail "sshd config check: $(head -3 "$RUN/sshd-t.txt")"; do_close; exit 1; }
  command -v iptables > /dev/null && iptables -I INPUT 1 "${RULE[@]}"
  "$SSHD" -f "$RUN/sshd_config" -E "$RUN/sshd.log" || { fail "sshd didn't start: $(tail -3 "$RUN/sshd.log")"; do_close; exit 1; }
  sleep 1
  ss -Hltn 2>/dev/null | grep -qE ":$PORT\b" || { fail "nothing listens on $PORT: $(tail -3 "$RUN/sshd.log")"; do_close; exit 1; }
  touch "$RUN/open"
  logger -t ccdc-vault "window opened on ${ip:-all addresses}:$PORT for $MINUTES min" 2>/dev/null

  # Safety net: closes the window even if this console session dies
  # (it writes its own PID: setsid may fork, so $! isn't always the timer)
  setsid bash -c "echo \$\$ > '$RUN/timer.pid'; sleep $((MINUTES * 60 + 30)); bash '$SELF' close --auto --config '$CONFIG'" > /dev/null 2>&1 < /dev/null &
  trap 'echo; do_close; exit 0' INT TERM HUP

  local until; until="$(date -d "+$MINUTES min" +%H:%M)"
  cat <<EOF

${B}Vault window OPEN until $until${N}  (from ${INSIDE:-anywhere} only)
  address   ${ip:-<this box>}   port $PORT
  user      $VUSER
  password  ${B}$pw${N}
  host key fingerprints (the uploading box shows one of these - they must match):
$(for k in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf "$k" 2>/dev/null | sed 's/^/    /'; done)

EOF
  if [ -n "${SERVE_NAME:-}" ]; then
    echo "On the box being restored:  sudo bash linux/offbox.sh fetch $SERVE_NAME"
  else
    echo "On each box:  sudo bash linux/offbox.sh push      (type the password above when asked)"
  fi
  echo "Disk free here: $(df -h "$STORE" | awk 'NR == 2 { print $4 }')"
  read -r -t $((MINUTES * 60)) -p "Press Enter to close the window now: " _ < /dev/tty
  echo
  trap - INT TERM HUP
  do_close
}

do_list() {
  local d f status n=0
  for d in "$STORE"/*/; do
    [ -d "$d" ] || continue
    echo "${B}$(basename "$d")${N}"
    for f in "$d"*; do
      [ -f "$f" ] || continue
      [[ "$f" == *.sha256 ]] && continue
      if [ -f "$f.sha256" ]; then (cd "$d" && sha256sum --status -c "$(basename "$f").sha256") && status=OK || status=MISMATCH
      else status="no checksum"; fi
      printf '  %-48s %6s  %s  %s\n' "$(basename "$f")" "$(du -h "$f" | cut -f1)" "$(date -r "$f" '+%m-%d %H:%M')" "$status"
      n=$((n + 1))
    done
  done
  [ "$n" -eq 0 ] && echo "No backups stored in $STORE yet."
  [ -f "$RUN/open" ] && warn "a window is open right now (close: sudo bash $SELF close)"
}

case "$CMD" in
  open|serve) do_open ;;
  list)  do_list ;;
  close) do_close ;;
esac
