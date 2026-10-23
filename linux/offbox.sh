#!/bin/bash
# Copy this box's backup off the box - encrypted - to the vault (linux/vault.sh), and get it back.
#
# Usage: sudo linux/offbox.sh push  [--backup DIR] [--include PATH]... [--vault IP]
#                                                           send the newest backup.sh backup (+ extra paths,
#                                                           e.g. --include /root/ccdc/palo-alto on the workstation)
#        sudo linux/offbox.sh fetch FILE [--vault IP]             get a backup back (vault.sh serve FILE first)
#        sudo linux/offbox.sh decrypt FILE                        unpack a .ccdc.enc that's already here
#                                                           (a Windows .ccdc-win.enc becomes a .zip)
#
# First the vault person opens a window (sudo linux/vault.sh open) and reads out its password.
# push:  tar + AES-256 with the team backup passphrase (on paper; the same on every box, so any
#        teammate can restore), a .sha256 next to it, outbound TCP BACKUP_VAULT_PORT opened to the
#        vault only, upload over SFTP, the opening closed again. Nothing listens on this box.
# fetch: the same opening, download, checksum, decrypt, unpack to /root/ccdc/full-backup-<time>/,
#        then use backup.sh restore-web / restore-db / restore-file on it.
# The outbound-SSH monitor alerts on the upload; a ccdc-offbox syslog line marks it as ours.

set -u
CMD="${1:-}"; [ $# -gt 0 ] && shift
FILE=""
case "$CMD" in fetch|decrypt) FILE="${1:-}"; [ $# -gt 0 ] && shift ;; esac
BACKUP=""; VAULT_OPT=""; INCLUDE=()
CONFIG="$(dirname "$0")/../ccdc.conf"
usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --backup) BACKUP="$2"; shift 2 ;;
    --include) INCLUDE+=("$(realpath -m "$2")"); shift 2 ;;
    --vault)  VAULT_OPT="$2"; shift 2 ;;
    --config) CONFIG="$2"; shift 2 ;;
    *) usage ;;
  esac
done
case "$CMD" in push|fetch|decrypt) ;; *) usage ;; esac
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)"; exit 1; }
BACKUP_VAULT=""; BACKUP_VAULT_ALT=""; BACKUP_VAULT_PORT=2222
# shellcheck source=../ccdc.conf
[ -f "$CONFIG" ] && . "$CONFIG"

HERE="$(cd "$(dirname "$0")" && pwd)"
DEST=/root/ccdc
OUT="$DEST/offbox"
PORT="${BACKUP_VAULT_PORT:-2222}"
CIPHER=(-aes-256-cbc -pbkdf2 -iter 200000 -md sha256)
umask 077
mkdir -p "$OUT" && chmod 700 "$DEST" "$OUT"

if [ -t 1 ]; then R=$'\e[31m'; Y=$'\e[33m'; G=$'\e[32m'; B=$'\e[1m'; N=$'\e[0m'; else R=; Y=; G=; B=; N=; fi
ok()   { echo "${G}[OK]${N}   $*"; }
warn() { echo "${Y}[WARN]${N} $*"; }
fail() { echo "${R}[FAIL]${N} $*"; }
ask()  { local a; read -r -p "$1 [y/N] " a < /dev/tty || return 1; [[ "$a" =~ ^[Yy] ]]; }
command -v openssl > /dev/null || { fail "openssl is missing"; exit 1; }

is_me() { [ -n "$1" ] && ip -o addr show 2>/dev/null | awk '{ split($4, a, "/"); print a[1] }' | grep -qxF "$1"; }
VAULT="${VAULT_OPT:-$BACKUP_VAULT}"
if [ "$CMD" != decrypt ]; then
  [ -z "$VAULT_OPT" ] && is_me "$VAULT" && VAULT="$BACKUP_VAULT_ALT"   # this IS the vault: use the other one
  [ -n "$VAULT" ] || { fail "set BACKUP_VAULT / BACKUP_VAULT_ALT in ccdc.conf (or --vault IP)"; exit 1; }
fi

read_pass() {   # read_pass CONFIRM(0|1) -> PASS
  local p2
  read -r -s -p "Team backup passphrase: " PASS < /dev/tty; echo
  [ "${#PASS}" -ge 12 ] || { fail "at least 12 characters"; exit 1; }
  [ "$1" -eq 1 ] || return 0
  read -r -s -p "Again: " p2 < /dev/tty; echo
  [ "$PASS" = "$p2" ] || { fail "they don't match"; exit 1; }
}

# Outbound opening to the vault only, removed again however the script ends
OPENED=0
RULE=(-p tcp -d "$VAULT" --dport "$PORT" -m conntrack --ctstate NEW -m comment --comment ccdc-offbox -j ACCEPT)
close_out() {
  [ "$OPENED" -eq 1 ] || return 0
  while iptables -D OUTPUT "${RULE[@]}" 2>/dev/null; do :; done
  OPENED=0
  ok "outbound port $PORT to $VAULT closed again"
}
open_out() {
  command -v iptables > /dev/null || return 0
  trap close_out EXIT; trap 'close_out; exit 1' INT TERM HUP
  iptables -I OUTPUT 1 "${RULE[@]}" && OPENED=1
}

# sftp with password login: -o BatchMode=no must come before -b (ssh keeps the first value given)
vault_sftp() {
  sftp -o BatchMode=no -b - -P "$PORT" -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile="$OUT/known_hosts" \
       -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive -o ConnectTimeout=10 \
       "ccdc-vault@$VAULT"
}
show_hostkey() {
  local fp; fp="$(ssh-keygen -l -F "[$VAULT]:$PORT" -f "$OUT/known_hosts" 2>/dev/null | grep -v '^#' | awk '{ print $2, $3 }' | head -1)"
  [ -n "$fp" ] && echo "Vault host key: $fp  - must match one shown on the vault's screen"
}

# ------------------------------------------------------------------ push
do_push() {
  local b="$BACKUP"
  [ -n "$b" ] || b="$(ls -1d "$DEST"/full-backup-* 2>/dev/null | sort | tail -1)"
  if [ -z "$b" ] || [ ! -d "$b" ]; then
    warn "no backup on this box yet"
    ask "Make one now with backup.sh?" || exit 1
    bash "$HERE/backup.sh" || exit 1
    b="$(ls -1d "$DEST"/full-backup-* 2>/dev/null | sort | tail -1)"
  fi
  [ -d "$b" ] || { fail "backup folder not found: $b"; exit 1; }
  echo "Backup: $b  ($(du -sh "$b" | cut -f1), made $(date -r "$b" '+%H:%M'))"
  local name; name="$(hostname -s)__$(date +%Y%m%d-%H%M%S).ccdc.enc"
  local extra=() p
  for p in "${INCLUDE[@]}"; do
    if [ -e "$p" ]; then extra+=(-C / "${p#/}"); echo "Also including: $p ($(du -sh "$p" | cut -f1))"
    else warn "--include $p: not found, skipped"; fi
  done
  read_pass 1
  tar -czf - -C "$(dirname "$b")" "$(basename "$b")" "${extra[@]}" | openssl enc "${CIPHER[@]}" -salt -pass fd:3 -out "$OUT/$name" 3<<< "$PASS"
  local st=("${PIPESTATUS[@]}")
  [ "${st[0]}" -le 1 ] && [ "${st[1]}" -eq 0 ] || { fail "encrypting failed"; rm -f "$OUT/$name"; exit 1; }   # tar 1 = file changed while read
  (cd "$OUT" && sha256sum "$name" > "$name.sha256")
  ok "encrypted: $OUT/$name ($(du -h "$OUT/$name" | cut -f1))"

  logger -t ccdc-offbox "uploading $name to $VAULT:$PORT (our own backup - expected outbound SSH)" 2>/dev/null
  open_out
  echo "Uploading to $VAULT:$PORT - type the vault window's password:"
  if printf 'put %s /incoming/\nput %s /incoming/\n' "$OUT/$name" "$OUT/$name.sha256" | vault_sftp; then
    close_out
    ok "uploaded $name - the vault checks it when its window closes"
    show_hostkey
    echo "Local encrypted copy stays in $OUT (remove it if space is short)."
  else
    close_out
    fail "upload failed (window open? right password? vault reachable: ping $VAULT)"
    exit 1
  fi
}

# ------------------------------------------------------------------ fetch / decrypt
do_decrypt() {
  local f="$1"
  [ -f "$f" ] || { fail "no such file: $f"; exit 1; }
  read_pass 0
  if [[ "$f" == *.ccdc-win.enc ]]; then      # Windows backup (windows/offbox.ps1): a zip inside
    local zip="${f%.enc}.zip"
    openssl enc -d "${CIPHER[@]}" -pass fd:3 -in "$f" -out "$zip" 3<<< "$PASS" 2>/dev/null ||
      { rm -f "$zip"; fail "could not decrypt - wrong passphrase or damaged file"; exit 1; }
    ok "decrypted Windows backup: $zip (unzip -l $zip)"; return 0
  fi
  local tmp; tmp="$(mktemp -d "$DEST/offbox-restore-XXXXXX")"
  if ! openssl enc -d "${CIPHER[@]}" -pass fd:3 -in "$f" 3<<< "$PASS" | tar -C "$tmp" -xzf -; then
    rm -rf "$tmp"; fail "could not decrypt/unpack - wrong passphrase or damaged file"; exit 1
  fi
  local d; d="$(ls -1d "$tmp"/full-backup-* 2>/dev/null | head -1)"
  [ -n "$d" ] || { fail "no backup folder inside $f"; exit 1; }
  local target="$DEST/$(basename "$d")"
  [ -e "$target" ] && target="$target-fetched"
  mv "$d" "$target"
  if rmdir "$tmp" 2>/dev/null; then :; else      # --include extras came along
    local ex="$DEST/offbox-extras-$(date +%Y%m%d-%H%M%S)"
    mv "$tmp" "$ex" && ok "extra files (--include): $ex"
  fi
  if (cd "$target" && sha256sum --quiet -c SHA256SUMS); then ok "unpacked and verified: $target"
  else fail "checksums inside the backup don't match - inspect before restoring: $target"; fi
  cat <<EOF

Restore from it (each one shows the differences and asks first):
  sudo bash $HERE/backup.sh restore-web  $(basename "$target") [WEBROOT]
  sudo bash $HERE/backup.sh restore-db   $(basename "$target")
  sudo bash $HERE/backup.sh restore-file $(basename "$target") /etc/<file or folder>
EOF
}

do_fetch() {
  local name; name="$(basename "$FILE")"
  [ -n "$name" ] || usage
  open_out
  echo "Downloading $name from $VAULT:$PORT - type the vault window's password:"
  if printf 'get /outgoing/%s %s/\nget /outgoing/%s.sha256 %s/\n' "$name" "$OUT" "$name" "$OUT" | vault_sftp; then
    close_out
  else
    close_out; fail "download failed (did the vault run: vault.sh serve $name ?)"; exit 1
  fi
  show_hostkey
  (cd "$OUT" && sha256sum --quiet -c "$name.sha256") && ok "checksum OK" || { fail "checksum mismatch - not using it"; exit 1; }
  do_decrypt "$OUT/$name"
}

case "$CMD" in
  push)    do_push ;;
  fetch)   do_fetch ;;
  decrypt) do_decrypt "$FILE" ;;
esac
