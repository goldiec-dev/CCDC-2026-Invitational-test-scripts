#!/bin/bash
# Web defacement guard: baseline a web root, detect changes, optionally restore.
#
# Usage: webguard.sh COMMAND [options]
#   init      Take a known-good baseline. Look at the site in a browser first!
#   check     Compare once against the baseline and report (exit 1 if changed)
#   watch     Check every --interval seconds until stopped
#   restore   Put every changed/deleted file back and quarantine new ones, now
#
# Options:
#   --webroot DIR    Web root (default /var/www/html)
#   --exclude PATH   Directory (relative to the web root) with legit runtime writes:
#                    cache, uploads, sessions. Repeatable. Common ones are excluded
#                    automatically. New or changed SCRIPT files (.php, .jsp, ...)
#                    inside excluded directories are still caught - that is where
#                    webshells get uploaded.
#   --auto-restore   check/watch: restore changed files and quarantine new ones
#                    instead of only alerting
#   --interval SEC   watch interval (default 15)
#   --store DIR      Where baselines and evidence live (default /root/.webguard)
#
# Re-run init after any legitimate site change (e.g. an inject asks you to edit a
# page), or --auto-restore will revert it. Nothing is ever deleted: modified and
# new files are copied to the evidence folder first, for incident reports.

set -u

CMD="${1:-}"; [ $# -gt 0 ] && shift
WEBROOT="/var/www/html"
STORE_BASE="/root/.webguard"
INTERVAL=15
AUTO=0
USER_EXCLUDES=()

usage() { sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --webroot)      WEBROOT="$2"; shift 2 ;;
    --exclude)      USER_EXCLUDES+=("${2%/}"); shift 2 ;;
    --auto-restore) AUTO=1; shift ;;
    --interval)     INTERVAL="$2"; shift 2 ;;
    --store)        STORE_BASE="$2"; shift 2 ;;
    *) usage ;;
  esac
done
case "$CMD" in init|check|watch|restore) ;; *) usage ;; esac

[ -d "$WEBROOT" ] || { echo "Web root not found: $WEBROOT"; exit 1; }
WEBROOT="$(cd "$WEBROOT" && pwd -P)"
[ "$(id -u)" -ne 0 ] && echo "WARN: not root - restores may not keep file ownership"

STORE="$STORE_BASE/$(echo "$WEBROOT" | tr / _)"
case "$STORE/" in "$WEBROOT"/*) echo "--store must be outside the web root"; exit 1 ;; esac
BASE="$STORE/files"
MANIFEST="$STORE/manifest"
CONF="$STORE/config"
EVIDENCE="$STORE/evidence"
LOG=/var/log/webguard.log
touch "$LOG" 2>/dev/null || LOG="$STORE/webguard.log"

# Directories that legitimately change at runtime in common PHP apps
DEFAULT_EXCLUDES=(
  cache tmp temp sessions logs log upload uploads
  var/cache var/logs var/sessions
  wp-content/cache wp-content/uploads wp-content/upgrade
  img/tmp img/p upload/tmp download
  storage/framework storage/logs
  system/storage/cache system/storage/logs system/storage/session image/cache
)
SCRIPT_EXT=(php php3 php4 php5 php7 phtml phar pl py cgi sh jsp jspx asp aspx)

log() {
  local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
  echo "$msg"
  echo "$msg" >> "$LOG"
  logger -t webguard -p auth.warning "$1" 2>/dev/null
}

# Manifest: sha256 of every file outside excluded dirs, plus script files inside them
manifest() {
  local prune=() ext=() e
  for e in "${EXCLUDES[@]}"; do prune+=(-path "./$e" -o); done
  for e in "${SCRIPT_EXT[@]}"; do ext+=(-iname "*.$e" -o); done
  unset 'ext[${#ext[@]}-1]'
  (
    cd "$WEBROOT" || exit 1
    {
      if [ ${#prune[@]} -gt 0 ]; then
        unset 'prune[${#prune[@]}-1]'
        find . \( "${prune[@]}" \) -prune -o -type f -print0
        for e in "${EXCLUDES[@]}"; do
          find "./$e" -type f \( "${ext[@]}" \) -print0
        done
      else
        find . -type f -print0
      fi
    } | sort -zu | xargs -0 -r sha256sum
  )
}

# Prints "TYPE<tab>HASH<tab>PATH" for each difference. TYPE: MODIFIED, NEW, DELETED
changes() {
  awk 'NR == FNR { base[substr($0, 67)] = substr($0, 1, 64); next }
       { h = substr($0, 1, 64); p = substr($0, 67); seen[p] = 1
         if (!(p in base))      print "NEW\t" h "\t" p
         else if (base[p] != h) print "MODIFIED\t" h "\t" p }
       END { for (p in base) if (!(p in seen)) print "DELETED\t-\t" p }' \
    "$MANIFEST" <(manifest) | sort -t$'\t' -k3
}

handle() {
  local type="$1" path="$2" ev="$3"
  local rel="${path#./}" live="$WEBROOT/${path#./}"
  log "$type: $live"

  if [ "$type" != DELETED ]; then
    mkdir -p "$ev/$(dirname "$rel")"
    cp -a "$live" "$ev/$rel" 2>/dev/null
  fi
  if [ "$type" = MODIFIED ] && grep -qI . "$live" 2>/dev/null; then
    { echo "=== $rel"; diff -u "$BASE/$rel" "$live" | head -n 200; } >> "$ev/changes.diff"
  fi

  [ "$AUTO" -eq 1 ] || return
  if [ "$type" = NEW ]; then
    if [ -e "$ev/$rel" ] || [ -L "$ev/$rel" ]; then
      rm -f "$live" && log "  quarantined to $ev/$rel"
    else
      log "  NOT quarantined: could not copy it to evidence first"
    fi
  else
    mkdir -p "$(dirname "$live")"
    rm -f "$live"   # never write through a symlink an attacker swapped in
    cp -a "$BASE/$rel" "$live" && log "  restored from baseline"
  fi
}

load_config() {
  [ -f "$CONF" ] && [ -f "$MANIFEST" ] || { echo "No baseline for $WEBROOT. Run: $0 init --webroot $WEBROOT"; exit 1; }
  # shellcheck source=/dev/null
  . "$CONF"
  [ ${#USER_EXCLUDES[@]} -gt 0 ] && echo "NOTE: --exclude is only read at init; using the baseline's list"
}

# Runs one pass. Only reports changes not already reported in PREV (for watch).
PREV=""
run_check() {
  local now new ev type hash path
  now="$(changes)"
  new="$(comm -13 <(printf '%s\n' "$PREV" | sort) <(printf '%s\n' "$now" | sort) | sed '/^$/d')"
  [ "$AUTO" -eq 1 ] && PREV="" || PREV="$now"
  [ -z "$new" ] && return 0
  ev="$EVIDENCE/$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$ev"
  while IFS=$'\t' read -r type hash path; do
    handle "$type" "$path" "$ev"
  done <<< "$new"
  log "Evidence saved in $ev"
  return 1
}

case "$CMD" in
  init)
    EXCLUDES=()
    for e in "${DEFAULT_EXCLUDES[@]}" "${USER_EXCLUDES[@]}"; do
      [ -d "$WEBROOT/$e" ] && EXCLUDES+=("$e")
    done
    if [ -d "$STORE" ]; then
      mv "$STORE" "$STORE.old-$(date +%Y%m%d-%H%M%S)"
      echo "Previous baseline kept as $STORE.old-*"
    fi
    mkdir -p "$BASE" && chmod 700 "$STORE_BASE" "$STORE"
    printf 'EXCLUDES=(%s)\n' "$(printf '%q ' "${EXCLUDES[@]}")" > "$CONF"
    manifest > "$MANIFEST"
    (cd "$WEBROOT" && cut -c67- "$MANIFEST" | tr '\n' '\0' | xargs -0 -r cp -a --parents -t "$BASE")
    echo "Baseline of $WEBROOT: $(wc -l < "$MANIFEST") files -> $STORE"
    echo "Excluded (runtime-writable, only script files watched): ${EXCLUDES[*]:-none}"
    log "Baseline taken for $WEBROOT"
    ;;
  check)
    load_config
    if run_check; then echo "No changes."; exit 0; else exit 1; fi
    ;;
  restore)
    load_config
    AUTO=1
    run_check && echo "Nothing to restore."
    ;;
  watch)
    load_config
    mode="alert only"; [ "$AUTO" -eq 1 ] && mode="auto-restore"
    log "Watching $WEBROOT every ${INTERVAL}s ($mode)"
    while true; do
      run_check
      sleep "$INTERVAL"
    done
    ;;
esac
