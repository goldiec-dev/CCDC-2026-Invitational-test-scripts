#!/bin/bash
# File integrity monitor for the important system folders on a Linux box.
#
# Usage: fim.sh COMMAND [options]
#   init             Baseline every watched file (hash, owner, permissions). Run it
#                    AFTER the box is hardened and scanned, so the baseline is clean.
#   check            Compare once and report (exit 1 if anything changed)
#   watch            Check every --interval seconds until stopped. Each change is
#                    reported once (again only if it changes again).
#   accept [PATH..]  After a change you made on purpose (password change, config
#                    edit), take those files or folders into the baseline.
#                    No PATH: re-baseline everything (asks first).
#   list             Show the watched folders and exclusions
#
# Options:
#   --role ROLE      dns|mail|ecom|mysql|splunk - adds that role's folders at init
#                    (default: $CCDC_ROLE, which deploy.sh sets)
#   --interval SEC   watch interval (default FIM_INTERVAL from ccdc.conf, or 60)
#   --store DIR      baseline and evidence (default /root/.ccdc-fim)
#   --config FILE    default ../ccdc.conf (FIM_EXTRA_PATHS, FIM_EXCLUDE, FIM_INTERVAL)
#
# Alert only: nothing is changed or restored automatically. Changed and new files
# are copied to the evidence folder, with a diff against the baseline copy for text
# files, for incident reports. Alerts go to syslog (tag ccdc-fim) so Splunk sees
# them. Web roots are covered by webguard.sh instead.

set -u

CMD="${1:-}"; [ $# -gt 0 ] && shift
STORE="/root/.ccdc-fim"
CONFIG="$(dirname "$0")/../ccdc.conf"
ROLE="${CCDC_ROLE:-}"
INTERVAL=""
ARGS=()
FULL_EVERY=10          # watch: re-hash everything every N passes, not just files whose stat changed
MAX_EVIDENCE=$((50 * 1024 * 1024))
MAX_COPY=$((1024 * 1024))

usage() { sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --role)     ROLE="$2"; shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --store)    STORE="$2"; shift 2 ;;
    --config)   CONFIG="$2"; shift 2 ;;
    -*)         usage ;;
    *)          ARGS+=("$1"); shift ;;
  esac
done
case "$CMD" in init|check|watch|accept|list) ;; *) usage ;; esac
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)"; exit 1; }
# A missing tool would make every check look clean - refuse to run instead
for t in awk find sha256sum xargs sort comm; do
  command -v "$t" > /dev/null || { echo "fim.sh: required command '$t' not found"; logger -t ccdc-fim "fim.sh cannot run: '$t' missing" 2>/dev/null; exit 3; }
done

FIM_EXTRA_PATHS=(); FIM_EXCLUDE=(); FIM_INTERVAL=60
# shellcheck source=../ccdc.conf
[ -f "$CONFIG" ] && . "$CONFIG"
INTERVAL="${INTERVAL:-${FIM_INTERVAL:-60}}"

# ------------------------------------------------------------------ what to watch
DEFAULT_PATHS=(
  /etc
  /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin
  /lib/systemd/system /usr/lib/systemd/system
  /lib/security /lib64/security /usr/lib/security /usr/lib64/security
  /lib/x86_64-linux-gnu/security /usr/lib/x86_64-linux-gnu/security
  /var/spool/cron
  /opt/ccdc                      # our own monitors (installed by deploy.sh)
)
role_paths() {
  case "$ROLE" in
    dns)        echo /var/named /var/cache/bind /var/lib/bind ;;
    mysql|ecom) shopt -s nullglob
                printf '%s\n' /usr/lib*/mysql/plugin /usr/lib*/mariadb/plugin /usr/lib/*/mariadb*/plugin ;;
    splunk)     echo /opt/splunk/etc/apps /opt/splunk/etc/system/local ;;
  esac
}
# Files that change on their own (find -path patterns)
DEFAULT_EXCLUDES=(
  /etc/mtab /etc/adjtime /etc/ld.so.cache /etc/.pwd.lock '/etc/*-' /etc/aliases.db
  /etc/prelink.cache /etc/udev/hwdb.bin /etc/lvm/archive /etc/lvm/backup /etc/lvm/cache
  '/etc/cups/subscriptions.conf*'
  '*.jnl' /var/named/data /var/named/dynamic '/var/cache/bind/managed-keys*'
  '/opt/splunk/etc/apps/*/metadata/local.meta'
)
# Login/SSH files in home directories (found by name, so new users are covered)
DOTFILES=(.bashrc .bash_profile .bash_login .bash_logout .profile .zshrc)

# Folders whose files are binaries: hashed, but not copied for diffs
BIN_RE='^/(usr/(local/)?)?(s?bin|lib(64|32)?)/|^/opt/splunk/bin/'

# Existing paths, symlinks resolved (/bin -> /usr/bin), nested ones dropped
resolve_roots() {
  local p
  for p in "$@"; do [ -e "$p" ] && readlink -f "$p"; done | sort -u |
    awk '{ for (i = 1; i <= n; i++) if (index($0, keep[i] "/") == 1) next; keep[++n] = $0; print }'
}

STORE_CONF="$STORE/config"
BASELINE="$STORE/baseline"
COPIES="$STORE/copies"
EVIDENCE="$STORE/evidence"
LOG=/var/log/ccdc-fim.log

log() {
  local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
  echo "$msg"
  { echo "$msg" >> "$LOG"; } 2>/dev/null
  logger -t ccdc-fim -p auth.alert "$1" 2>/dev/null
}

NICE=(nice -n 10); command -v ionice > /dev/null && NICE+=(ionice -c3)

TMP="$(mktemp -d)" || exit 1
trap 'rm -rf "$TMP"' EXIT

# ------------------------------------------------------------------ scanning
# One record per file:  HASH \t TYPE \t MODE UID GID \t SIZE MTIME CTIME INODE \t PATH
# (state files). Symlinks are "hashed" as their target.
FMT='%y\t%m %U %G\t%s %T@ %C@ %i\t%l\t%p\n'

raw_scan() {
  local prune=() e
  for e in "${EXCLUDES[@]}" "$STORE"; do prune+=(-path "$e" -o); done
  unset 'prune[${#prune[@]}-1]'
  find "${ROOTS[@]}" -xdev \( "${prune[@]}" \) -prune -o \( -type f -o -type l \) -printf "$FMT" 2>/dev/null
  local names=() n
  for n in "${DOTFILES[@]}"; do names+=(-name "$n" -o); done
  find /root /home -maxdepth 3 -xdev \( -path '*/.ssh/*' -o "${names[@]}" -false \) \
    \( -type f -o -type l \) -printf "$FMT" 2>/dev/null
}

AWK_REST='function rest(s, n,   k) { while (n-- > 0) { k = index(s, "\t"); if (!k) return ""; s = substr(s, k + 1) } return s }'

# scan PREV_STATE FULL OUT: re-hash files that are new, whose stat changed, or all if FULL=1
scan() {
  local prev="$1" full="$2" out="$3"
  raw_scan > "$TMP/scan"
  : > "$TMP/tohash"
  awk -F'\t' -v full="$full" -v need="$TMP/tohash" "$AWK_REST"'
    FILENAME == ARGV[1] { p = rest($0, 4); ph[p] = $1; ps[p] = $4; next }
    NF < 5 { next }
    { p = rest($0, 4)
      if ($1 == "l") h = "link:" $4
      else if (!full && (p in ps) && ps[p] == $3 && ph[p] != "unreadable") h = ph[p]
      else { h = "?"; print p > need }
      print h "\t" $1 "\t" $2 "\t" $3 "\t" p }' "$prev" "$TMP/scan" > "$TMP/partial"
  tr '\n' '\0' < "$TMP/tohash" | "${NICE[@]}" xargs -0 -r sha256sum 2>/dev/null > "$TMP/hashed"
  # sha256sum escapes names containing a backslash with a leading "\"
  awk -F'\t' "$AWK_REST"'
    FILENAME == ARGV[1] {
      if (substr($0, 1, 1) == "\\") { h = substr($0, 2, 64); p = substr($0, 68); gsub(/\\\\/, "\\", p) }
      else { h = substr($0, 1, 64); p = substr($0, 67) }
      H[p] = h; next }
    $1 == "?" { p = rest($0, 4); print ((p in H) ? H[p] : "unreadable") substr($0, 2); next }
    { print }' "$TMP/hashed" "$TMP/partial" > "$out"
}

# Prints "TYPE \t DETAIL \t PATH" for each difference from the baseline
changes() {
  awk -F'\t' "$AWK_REST"'
    FILENAME == ARGV[1] { if (NF >= 5) { p = rest($0, 4); bh[p] = $1; bm[p] = $3 } next }
    NF < 5 { next }
    { p = rest($0, 4); seen[p] = 1
      if (!(p in bh))        print "NEW\t" $1 "\t" p
      else if (bh[p] != $1)  print "CHANGED\t" $1 "\t" p
      else if (bm[p] != $3)  print "PERMS\tmode/uid/gid " bm[p] " -> " $3 "\t" p }
    END { for (p in bh) if (!(p in seen)) print "DELETED\t-\t" p }' "$BASELINE" "$1" | sort -t$'\t' -k3
}

# Keep copies of small text/config files so changes can be shown as a diff
save_copies() {   # save_copies STATEFILE
  awk -F'\t' -v max="$MAX_COPY" -v re="$BIN_RE" "$AWK_REST"'
    $2 == "f" { split($4, s, " "); p = rest($0, 4); if (s[1] + 0 <= max && p !~ re) printf "%s%c", p, 0 }' "$1" |
    xargs -0 -r cp -a --parents -t "$COPIES" 2>/dev/null
}

handle() {   # handle TYPE DETAIL PATH EVIDENCE_DIR
  local type="$1" detail="$2" path="$3" ev="$4" size
  case "$type" in
    PERMS)   log "PERMS: $path ($detail)" ;;
    DELETED) log "DELETED: $path" ;;
    *)       log "$type: $path" ;;
  esac
  [ "$type" = CHANGED ] || [ "$type" = NEW ] || return 0
  [ -f "$path" ] && [ ! -L "$path" ] || return 0
  size=$(stat -c %s "$path" 2>/dev/null || echo 0)
  if [ "$size" -le "$MAX_EVIDENCE" ]; then
    mkdir -p "$ev/files$(dirname "$path")" && cp -a "$path" "$ev/files$path" 2>/dev/null
  fi
  grep -qI . "$path" 2>/dev/null || return 0
  if [ "$type" = CHANGED ] && [ -f "$COPIES$path" ]; then
    { echo "=== CHANGED $path"; diff -u "$COPIES$path" "$path" | head -n 200; } >> "$ev/changes.diff"
  elif [ "$type" = NEW ]; then
    { echo "=== NEW $path"; head -n 50 "$path"; } >> "$ev/changes.diff"
  fi
}

load_store() {
  [ -f "$STORE_CONF" ] && [ -f "$BASELINE" ] || { echo "No baseline. Run: $0 init"; exit 1; }
  # shellcheck source=/dev/null
  . "$STORE_CONF"
}

# Report changes not already reported (PREV holds the last pass's list)
PREV=""
report() {   # report STATEFILE
  local now new ev type detail path
  now="$(changes "$1")"
  new="$(comm -13 <(printf '%s\n' "$PREV" | sort) <(printf '%s\n' "$now" | sort) | sed '/^$/d')"
  PREV="$now"
  [ -z "$new" ] && return 0
  ev="$EVIDENCE/$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$ev"
  while IFS=$'\t' read -r type detail path; do
    handle "$type" "$detail" "$path" "$ev"
  done <<< "$new"
  log "$(printf '%s\n' "$new" | wc -l) change(s). Evidence: $ev  If you made the change: $0 accept <path>"
  return 1
}

baseline_sum() { sha256sum "$BASELINE" | cut -c1-64; }

do_init() {
  ROOTS=(); EXCLUDES=()
  local r
  while IFS= read -r r; do ROOTS+=("$r"); done < <(resolve_roots "${DEFAULT_PATHS[@]}" $(role_paths) "${FIM_EXTRA_PATHS[@]}")
  EXCLUDES=("${DEFAULT_EXCLUDES[@]}" "${FIM_EXCLUDE[@]}")
  if [ -d "$STORE" ]; then
    local old
    old="$STORE.old-$(date +%Y%m%d-%H%M%S)"
    mv "$STORE" "$old" && echo "Previous baseline kept in $old"
  fi
  mkdir -p "$COPIES" "$EVIDENCE" && chmod 700 "$STORE"
  { printf 'ROOTS=(%s)\n' "$(printf '%q ' "${ROOTS[@]}")"
    printf 'EXCLUDES=(%s)\n' "$(printf '%q ' "${EXCLUDES[@]}")"; } > "$STORE_CONF"
  echo "Hashing ${ROOTS[*]} + SSH keys and shell startup files in /root and /home ..."
  scan /dev/null 1 "$BASELINE"
  save_copies "$BASELINE"
  echo "Baseline: $(wc -l < "$BASELINE") files -> $STORE"
  log "Baseline taken (role ${ROLE:-none}, $(wc -l < "$BASELINE") files, sha256 $(baseline_sum))"
}

# ------------------------------------------------------------------ commands
case "$CMD" in
  init)
    do_init
    ;;

  list)
    load_store
    echo "Watched folders:";  printf '  %s\n' "${ROOTS[@]}"
    echo "  + .ssh/* and ${DOTFILES[*]} under /root and /home"
    echo "Excluded:";         printf '  %s\n' "${EXCLUDES[@]}"
    ;;

  check)
    load_store
    scan /dev/null 1 "$TMP/state"
    if report "$TMP/state"; then echo "No changes."; exit 0; else exit 1; fi
    ;;

  accept)
    load_store
    if [ ${#ARGS[@]} -eq 0 ]; then
      read -r -p "Re-baseline EVERY watched file? Only if the box is known clean. [y/N] " a
      [[ "$a" =~ ^[Yy] ]] || exit 1
      do_init
      exit 0
    fi
    scan /dev/null 1 "$TMP/state"
    prefixes=()
    for p in "${ARGS[@]}"; do
      [[ "$p" = /* ]] || p="$PWD/$p"
      # resolve the folder (/bin -> /usr/bin) but not the file itself, which may be a symlink
      d="$(readlink -m "$(dirname "$p")")"
      prefixes+=("${d%/}/$(basename "$p")")
    done
    printf '%s\n' "${prefixes[@]}" > "$TMP/prefixes"
    match='function under(p,  i) { for (i in pre) if (p == pre[i] || index(p, pre[i] "/") == 1) return 1; return 0 }'
    awk -F'\t' "$AWK_REST $match"'
      FILENAME == ARGV[1] { pre[NR] = $0; next }
      FILENAME == ARGV[2] { if (!under(rest($0, 4))) print; next }
      { if (under(rest($0, 4))) { print; n++ } }
      END { print n + 0 > "/dev/stderr" }' "$TMP/prefixes" "$BASELINE" "$TMP/state" > "$TMP/newbase" 2> "$TMP/count"
    awk -F'\t' "$AWK_REST $match"'
      FILENAME == ARGV[1] { pre[NR] = $0; next }
      under(rest($0, 4))' "$TMP/prefixes" "$TMP/state" > "$TMP/accepted"
    save_copies "$TMP/accepted"
    cat "$TMP/newbase" > "$BASELINE"
    log "Accepted current state of ${prefixes[*]} ($(cat "$TMP/count") files) into the baseline, sha256 $(baseline_sum)"
    ;;

  watch)
    load_store
    log "Watching ${ROOTS[*]} every ${INTERVAL}s (full re-hash every $FULL_EVERY passes)"
    sum="$(baseline_sum)"
    : > "$TMP/state"
    pass=0
    while true; do
      now_sum="$(baseline_sum 2>/dev/null)"
      if [ "$now_sum" != "$sum" ]; then
        log "Baseline file changed since the last pass (fim.sh accept, or someone tampering) - now sha256 $now_sum"
        sum="$now_sum"
      fi
      full=0; [ $((pass % FULL_EVERY)) -eq 0 ] && full=1
      scan "$TMP/state" "$full" "$TMP/state.new" && mv "$TMP/state.new" "$TMP/state"
      report "$TMP/state"
      pass=$((pass + 1))
      sleep "$INTERVAL"
    done
    ;;
esac
