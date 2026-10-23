#!/bin/bash
# Back up a Linux box before anyone changes it: configs, web roots, databases, mail,
# Splunk config, plus a snapshot of the box's state for later comparison.
# Run it FIRST (before passwords/firewall) - it is the only copy of the original state.
#
# Usage: backup.sh [--role ROLE] [--dest DIR] [--no-web] [--no-db] [--config FILE]
#        backup.sh list                           show backups on this box
#        backup.sh restore-web BACKUP [WEBROOT]   put a backed-up web root back (asks first)
#        backup.sh restore-db  BACKUP             load the database dump back (asks first)
#        backup.sh restore-file BACKUP PATH       put one file back (from /etc, a web root, Splunk
#                                                 config, mail, cron or dotfile archive; a folder works too)
#   ROLE: ecom | mail | splunk | workstation | dns | mysql (default: CCDC_ROLE or none)
#   BACKUP: a backup folder from "list", or "latest"
#
# Writes /root/ccdc/full-backup-<time>/ (root-only):
#   etc.tar.gz, web-<n>.tar.gz, mysql-all.sql.gz / postgres-all.sql.gz, mail.tar.gz,
#   splunk-etc.tar.gz, home-dotfiles.tar.gz, cron.tar.gz, firewall.txt,
#   state/ (users, packages, services, listeners... - diff later to see what changed),
#   SHA256SUMS. Nothing on the box is changed.
#
# The red team can delete /root/ccdc too: copy it off the box with linux/offbox.sh push
# (encrypted, to the vault - see linux/vault.sh). Restores always save the current state first.

set -u

CMD=backup
case "${1:-}" in list|restore-web|restore-db|restore-file) CMD="$1"; shift ;; esac
ARGS=()
ROLE="${CCDC_ROLE:-}"
DEST_BASE=/root/ccdc
DO_WEB=1
DO_DB=1
CONFIG="$(dirname "$0")/../ccdc.conf"

usage() { sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --role)   ROLE="$2"; shift 2 ;;
    --dest)   DEST_BASE="$2"; shift 2 ;;
    --no-web) DO_WEB=0; shift ;;
    --no-db)  DO_DB=0; shift ;;
    --config) CONFIG="$2"; shift 2 ;;
    -h|--help) usage ;;
    -*) usage ;;
    *) ARGS+=("$1"); shift ;;
  esac
done

WEB_ROOTS=(/var/www)
# shellcheck source=../ccdc.conf
[ -f "$CONFIG" ] && CCDC_ROLE="$ROLE" . "$CONFIG"

[ "$(id -u)" -eq 0 ] || { echo "Run as root"; exit 1; }
umask 077

if [ -t 1 ]; then R='\e[31m'; Y='\e[33m'; G='\e[32m'; B='\e[1m'; N='\e[0m'; else R=; Y=; G=; B=; N=; fi
ok()   { echo -e "${G}[OK]${N} $*"; }
warn() { echo -e "${Y}[WARN]${N} $*"; }
fail() { echo -e "${R}[FAIL]${N} $*"; }
ask()  { local a; read -r -p "$1 [y/N] " a < /dev/tty || return 1; [[ "$a" =~ ^[Yy] ]]; }

# Free space (KB) on the filesystem holding $1
free_kb() { df -Pk "$1" 2>/dev/null | awk 'NR == 2 { print $4 }'; }
size_kb() { du -skx "$@" 2>/dev/null | awk '{ s += $1 } END { print s + 0 }'; }

# tar_to NAME PATH... - gzip the given paths (absolute names kept, relative to /)
tar_to() {
  local name="$1"; shift
  local rel=() p
  for p in "$@"; do [ -e "$p" ] && rel+=("${p#/}"); done
  [ ${#rel[@]} -eq 0 ] && return 1
  # exit 1 = "file changed while reading" (live logs/sessions) - the archive is still usable
  tar -C / --warning=no-file-changed -czf "$DIR/$name" "${rel[@]}" 2>> "$DIR/errors.log"
  [ $? -le 1 ]
}

# ------------------------------------------------------------------ database helpers
MYSQL_CNF=""
mysql_client() { command -v mysql || command -v mariadb; }
mysql_dump_bin() { command -v mysqldump || command -v mariadb-dump; }
# Same login order as audit.sh mysql: root over the socket, debian.cnf, then ask
mysql_login() {
  local client cur
  client="$(mysql_client)" || return 1
  MYSQL_CNF="$(mktemp "$DEST_BASE/.my.cnf-XXXXXX")"
  trap 'rm -f "$MYSQL_CNF"' EXIT
  : > "$MYSQL_CNF"
  "$client" --defaults-extra-file="$MYSQL_CNF" -uroot -e 'SELECT 1' > /dev/null 2>&1 && { MYSQL_USER=root; return 0; }
  if [ -f /etc/mysql/debian.cnf ] && "$client" --defaults-extra-file=/etc/mysql/debian.cnf -e 'SELECT 1' > /dev/null 2>&1; then
    cp /etc/mysql/debian.cnf "$MYSQL_CNF"; MYSQL_USER=""; return 0
  fi
  read -r -s -p "MySQL root password (empty = skip the database): " cur < /dev/tty; echo
  [ -n "$cur" ] || return 1
  printf '[client]\npassword="%s"\n' "$cur" > "$MYSQL_CNF"
  MYSQL_USER=root
  "$client" --defaults-extra-file="$MYSQL_CNF" -uroot -e 'SELECT 1' > /dev/null 2>&1
}
mysql_running() { pgrep -x mysqld > /dev/null || pgrep -x mariadbd > /dev/null; }

# ------------------------------------------------------------------ backup
backup_db() {
  if mysql_running; then
    local dump
    dump="$(mysql_dump_bin)" || { fail "MySQL is running but there is no mysqldump here"; return; }
    if mysql_login; then
      local u=(); [ -n "$MYSQL_USER" ] && u=(-u"$MYSQL_USER")
      # --single-transaction: consistent InnoDB dump without locking the shop
      # mysql database included = users and grants (restore them if the red team adds/changes users)
      if "$dump" --defaults-extra-file="$MYSQL_CNF" "${u[@]}" --all-databases --single-transaction \
           --routines --events --triggers --hex-blob 2>> "$DIR/errors.log" | gzip > "$DIR/mysql-all.sql.gz" &&
         [ "${PIPESTATUS[0]}" -eq 0 ]; then
        ok "MySQL: every database -> mysql-all.sql.gz ($(du -h "$DIR/mysql-all.sql.gz" | cut -f1))"
        "$(mysql_client)" --defaults-extra-file="$MYSQL_CNF" "${u[@]}" -N -B -e \
          "SELECT CONCAT(User,'@',Host,' ',IFNULL(plugin,'')) FROM mysql.user" > "$DIR/state/mysql-users.txt" 2>/dev/null
      else
        fail "mysqldump failed - see $DIR/errors.log"
      fi
    else
      fail "Could not log in to MySQL - database NOT backed up"
    fi
  fi
  if pgrep -x postgres > /dev/null && id postgres > /dev/null 2>&1 && command -v pg_dumpall > /dev/null; then
    if (cd /tmp && su postgres -s /bin/sh -c pg_dumpall 2>> "$DIR/errors.log") | gzip > "$DIR/postgres-all.sql.gz" &&
       [ "${PIPESTATUS[0]}" -eq 0 ]; then
      ok "PostgreSQL: every database -> postgres-all.sql.gz"
    else
      fail "pg_dumpall failed - see $DIR/errors.log"
    fi
  fi
}

backup_state() {
  local s="$DIR/state"
  mkdir -p "$s"
  getent passwd > "$s/passwd.txt"
  getent group > "$s/group.txt"
  awk -F: '{ print $1, $2 ~ /^[!*]/ ? "locked/none" : "has-password" }' /etc/shadow > "$s/password-status.txt" 2>/dev/null
  if command -v dpkg-query > /dev/null; then dpkg-query -W -f '${Package} ${Version}\n' > "$s/packages.txt"
  elif command -v rpm > /dev/null; then rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' | sort > "$s/packages.txt"; fi
  command -v systemctl > /dev/null && {
    systemctl list-unit-files --no-pager --no-legend > "$s/unit-files.txt"
    systemctl list-units --type=service --state=running --no-pager --no-legend > "$s/running-services.txt"
    systemctl list-timers --all --no-pager > "$s/timers.txt"
  }
  ss -tulpn > "$s/listeners.txt" 2>/dev/null
  ss -tunap > "$s/connections.txt" 2>/dev/null
  ps auxww > "$s/processes.txt"
  ip -o addr > "$s/ip-addr.txt"; ip route > "$s/ip-route.txt"
  for u in $(cut -d: -f1 /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s|^|$u: |"; done > "$s/crontabs.txt"
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort > "$s/suid-sgid.txt"
  find /root /home -maxdepth 3 -name authorized_keys\* 2>/dev/null -exec sh -c 'for f; do echo "== $f"; cat "$f"; done' _ {} + > "$s/authorized_keys.txt"
  uname -a > "$s/uname.txt"; cat /etc/os-release >> "$s/uname.txt" 2>/dev/null
  ok "State snapshot -> state/ (diff it later: diff -r <old>/state <new>/state)"
}

do_backup() {
  local ts; ts="$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$DEST_BASE" && chmod 700 "$DEST_BASE"
  DIR="$DEST_BASE/full-backup-$ts"
  mkdir -p "$DIR/state"
  echo -e "${B}== Backup of $(hostname) (role ${ROLE:-none}) -> $DIR ==${N}"

  # Web roots that exist; warn before archiving something huge
  local webs=() w
  if [ "$DO_WEB" -eq 1 ]; then
    for w in "${WEB_ROOTS[@]}"; do [ -d "$w" ] && webs+=("$w"); done
  fi
  local need avail
  need=$(( $(size_kb /etc) + $(size_kb "${webs[@]:-/nonexistent}") ))
  avail="$(free_kb "$DEST_BASE")"
  echo "About $((need / 1024)) MB to archive (before compression), $((avail / 1024)) MB free on $DEST_BASE"
  if [ "$need" -gt "$avail" ]; then
    warn "Probably not enough space. Use --dest on a bigger filesystem, or --no-web"
    ask "Continue anyway?" || exit 1
  fi

  tar_to etc.tar.gz /etc && ok "/etc -> etc.tar.gz" || fail "/etc archive failed (errors.log)"

  local i=0
  for w in "${webs[@]}"; do
    i=$((i + 1))
    if [ "$(size_kb "$w")" -gt 2097152 ] && ! ask "$w is over 2 GB - archive it anyway?"; then
      warn "skipped $w"; continue
    fi
    tar_to "web-$i.tar.gz" "$w" && { echo "$w" > "$DIR/web-$i.path"; ok "$w -> web-$i.tar.gz"; } || fail "$w archive failed"
  done
  [ ${#webs[@]} -eq 0 ] && [ "$DO_WEB" -eq 1 ] && echo "    (no WEB_ROOTS folders on this box)"

  [ "$DO_DB" -eq 1 ] && backup_db

  # Mail spools and Maildirs (mail role, or wherever a mail server runs)
  local mail=() d
  for d in /var/mail /var/spool/mail /var/vmail /var/spool/postfix/etc; do [ -d "$d" ] && mail+=("$d"); done
  for d in /home/*/Maildir /home/*/mail; do [ -d "$d" ] && mail+=("$d"); done
  if [ ${#mail[@]} -gt 0 ] && { [ "$ROLE" = mail ] || pgrep -x master > /dev/null || pgrep -x dovecot > /dev/null; }; then
    tar_to mail.tar.gz "${mail[@]}" && ok "mail spools/Maildirs -> mail.tar.gz" || fail "mail archive failed"
  fi

  # Splunk config: apps, users, inputs/outputs (not the indexed data)
  local sh
  for sh in "${SPLUNK_HOME:-}" /opt/splunk /opt/splunkforwarder; do
    [ -n "$sh" ] && [ -d "$sh/etc" ] || continue
    tar_to "splunk-etc-$(basename "$sh").tar.gz" "$sh/etc" && ok "$sh/etc -> splunk-etc-$(basename "$sh").tar.gz"
  done

  # SSH keys and shell startup files of root and every home folder (persistence lives here)
  local dots=() h f
  for h in /root /home/*; do
    for f in .ssh .bashrc .bash_profile .profile .bash_logout .zshrc .config/autostart; do
      [ -e "$h/$f" ] && dots+=("$h/$f")
    done
  done
  tar_to home-dotfiles.tar.gz "${dots[@]:-/nonexistent}" && ok "SSH keys + shell startup files -> home-dotfiles.tar.gz"
  tar_to cron.tar.gz /var/spool/cron /var/spool/at /var/spool/cron/atjobs && ok "user crontabs/at jobs -> cron.tar.gz"

  {
    echo "### iptables-save"; iptables-save 2>/dev/null
    echo "### ip6tables-save"; ip6tables-save 2>/dev/null
    command -v nft > /dev/null && { echo "### nft list ruleset"; nft list ruleset 2>/dev/null; }
    command -v firewall-cmd > /dev/null && { echo "### firewall-cmd --list-all-zones"; firewall-cmd --list-all-zones 2>/dev/null; }
    command -v ufw > /dev/null && { echo "### ufw status verbose"; ufw status verbose 2>/dev/null; }
  } > "$DIR/firewall.txt"
  ok "firewall rules -> firewall.txt"

  backup_state

  (cd "$DIR" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
  [ -s "$DIR/errors.log" ] || rm -f "$DIR/errors.log"
  chmod -R go-rwx "$DIR"
  logger -t ccdc-backup "backup written to $DIR" 2>/dev/null
  echo
  ok "Done: $DIR ($(du -sh "$DIR" | cut -f1))"
  echo "Copy it off the box (encrypted, during a vault window):  sudo bash $(dirname "$0")/offbox.sh push"
  [ -f "$DIR/errors.log" ] && warn "Some files could not be read - see $DIR/errors.log"
  return 0
}

# ------------------------------------------------------------------ list / restore
resolve() {
  local b="${1:-}"
  [ -n "$b" ] || { echo "Which backup? (folder from 'list', or latest)"; exit 1; }
  if [ "$b" = latest ]; then
    b="$(ls -1d "$DEST_BASE"/full-backup-* 2>/dev/null | sort | tail -1)"
  elif [ ! -d "$b" ] && [ -d "$DEST_BASE/$b" ]; then
    b="$DEST_BASE/$b"
  fi
  [ -d "$b" ] || { echo "No backup folder: ${1}"; exit 1; }
  echo "$b"
}

verify() {
  (cd "$1" && sha256sum --quiet -c SHA256SUMS) || {
    fail "Checksums in $1 do not match - the backup was changed or damaged"
    ask "Use it anyway?" || exit 1
  }
}

do_list() {
  local b
  for b in $(ls -1d "$DEST_BASE"/full-backup-* 2>/dev/null | sort); do
    printf '%s  %6s  ' "$b" "$(du -sh "$b" | cut -f1)"
    ls "$b" | grep -E '\.(gz|txt)$' | tr '\n' ' '; echo
  done
}

do_restore_web() {
  local b; b="$(resolve "${ARGS[0]:-}")"; verify "$b"
  local want="${ARGS[1]:-}" p n
  for p in "$b"/web-*.path; do
    [ -f "$p" ] || continue
    if [ -z "$want" ] || [ "$(cat "$p")" = "${want%/}" ]; then n="${p%.path}"; break; fi
  done
  [ -n "${n:-}" ] || { echo "No web archive${want:+ for $want} in $b"; ls "$b"/web-*.path 2>/dev/null | xargs -r cat; exit 1; }
  local root; root="$(cat "$n.path")"
  local stage="$DEST_BASE/restore-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$stage"
  tar -C "$stage" -xzf "$n.tar.gz" || { fail "could not extract $n.tar.gz"; exit 1; }
  echo "Differences between the live $root and the backup (live <-> backup):"
  diff -rq "$root" "$stage$root" | head -50
  echo "Current $root will be saved to $stage/current.tar.gz first."
  ask "Replace $root with the backup (files added since the backup are deleted)?" || { echo "Nothing changed. Extracted copy: $stage$root"; exit 0; }
  tar -C / -czf "$stage/current.tar.gz" "${root#/}" 2>/dev/null
  if command -v rsync > /dev/null; then
    rsync -a --delete "$stage$root/" "$root/"
  else
    find "$root" -mindepth 1 -delete && cp -a "$stage$root/." "$root/"
  fi && ok "$root restored from $b (previous state: $stage/current.tar.gz)"
  command -v restorecon > /dev/null && restorecon -R "$root" && ok "SELinux labels reset on $root"
  echo "Check the site, then re-baseline the defacement guard: sudo bash $(dirname "$0")/../deploy.sh --role <role> --only webguard"
}

do_restore_db() {
  local b; b="$(resolve "${ARGS[0]:-}")"; verify "$b"
  [ -f "$b/mysql-all.sql.gz" ] || { echo "No mysql-all.sql.gz in $b"; exit 1; }
  mysql_login || { fail "Cannot log in to MySQL"; exit 1; }
  local u=(); [ -n "$MYSQL_USER" ] && u=(-u"$MYSQL_USER")
  local cur; cur="$DEST_BASE/mysql-before-restore-$(date +%Y%m%d-%H%M%S).sql.gz"
  warn "This loads EVERY database from $b, including the mysql user table:"
  warn "MySQL passwords go back to what they were at backup time (the original, possibly default, ones)."
  echo "Afterwards: run audit.sh mysql again, then audit.sh app-password on the web box."
  ask "Restore the database now?" || exit 0
  "$(mysql_dump_bin)" --defaults-extra-file="$MYSQL_CNF" "${u[@]}" --all-databases --single-transaction \
    --routines --events --triggers --hex-blob 2>/dev/null | gzip > "$cur" && ok "current databases saved to $cur"
  if gunzip -c "$b/mysql-all.sql.gz" | "$(mysql_client)" --defaults-extra-file="$MYSQL_CNF" "${u[@]}"; then
    "$(mysql_client)" --defaults-extra-file="$MYSQL_CNF" "${u[@]}" -e 'FLUSH PRIVILEGES' 2>/dev/null
    ok "Databases restored from $b"
  else
    fail "Restore failed part-way - the previous state is in $cur"
  fi
}

do_restore_file() {
  local b; b="$(resolve "${ARGS[0]:-}")"; verify "$b"
  local path="${ARGS[1]:-}"
  [ -n "$path" ] || { echo "Which file? e.g. /etc/ssh/sshd_config"; exit 1; }
  local arch
  for arch in "$b"/etc.tar.gz "$b"/home-dotfiles.tar.gz "$b"/cron.tar.gz "$b"/web-*.tar.gz "$b"/splunk-etc-*.tar.gz "$b"/mail.tar.gz; do
    [ -f "$arch" ] && tar -tzf "$arch" "${path#/}" > /dev/null 2>&1 && break
    arch=""
  done
  [ -n "$arch" ] || { echo "$path is not in any archive in $b"; exit 1; }
  local stage; stage="$(mktemp -d "$DEST_BASE/restore-file-XXXXXX")"
  path="${path%/}"
  tar -C "$stage" -xzf "$arch" "${path#/}"
  if [ -e "$path" ]; then
    if [ -d "$path" ]; then diff -rq "$path" "$stage$path" | head -60; else diff -u "$path" "$stage$path" | head -60; fi
    cp -a "$path" "$stage/current-$(basename "$path")"
  fi
  if [ -d "$stage$path" ]; then
    ask "Copy the backed-up $path back (missing and changed files come back; newer files stay)?" || { echo "Extracted copy: $stage$path"; exit 0; }
    mkdir -p "$path" && cp -a "$stage$path/." "$path/" && ok "$path restored (previous version: $stage/current-$(basename "$path"))"
  else
    ask "Put the backed-up $path back?" || { echo "Extracted copy: $stage$path"; exit 0; }
    cp -a "$stage$path" "$path" && ok "$path restored (previous version: $stage/current-$(basename "$path"))"
  fi
  echo "If the file integrity monitor watches it: sudo bash $(dirname "$0")/fim.sh accept $path"
}

case "$CMD" in
  backup)       do_backup ;;
  list)         do_list ;;
  restore-web)  do_restore_web ;;
  restore-db)   do_restore_db ;;
  restore-file) do_restore_file ;;
esac
