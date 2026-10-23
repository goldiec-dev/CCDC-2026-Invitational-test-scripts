#!/bin/bash
# Lock down one Linux box, in order, from ccdc.conf.
#
# Usage: sudo ./deploy.sh --role ROLE [--only STEPS] [--skip STEPS]
#   ROLE:  ecom | mail | splunk | workstation   (dns | mysql: older topologies)
#   STEPS: comma-separated from: backup,passwords,database,firewall,secure,cis,scan,services,forwarder,webguard,beacon,fim
#
# Order:
#   backup     full backup of the box as it is now (linux/backup.sh) - the original state;
#              copy it off the box later with linux/offbox.sh push   (all boxes)
#   passwords  change every password + password policy           (all boxes)
#   database   DB on this box (2026 E-com) or mysql box: change every MySQL password;
#              ecom/mail: then put the new DB password in the web app config
#   firewall   fw.sh at FIREWALL_LEVEL with its rollback timer - test scored services
#   secure     harden the scored services (HTTP -> HTTPS, SSH, mail TLS, FTP, Splunk); each
#              part tests its service and undoes itself if the test fails
#   cis        CIS Benchmark Level 1 controls not covered above (modules, sysctl, perms, banners,
#              auditd, sudo/su...) - asks per section; scoring/lockout risks are report-only
#   scan       backdoor/persistence hunt, asks before each fix
#   services   legacy services (telnet, rsh, tftp, ftp, snmp...) - asks before disabling each;
#              lists pending updates for important services
#   forwarder  Splunk Universal Forwarder 10.0.2 -> SPLUNK:9997 (not on the Splunk box)
#   webguard   baseline the web root (after the scan removed webshells) and start
#              watching it in the background                      (ecom, mail)
#   beacon     watch outbound connections for anything calling home on a timer, and
#              for outbound SSH (pivoting)                          (all boxes)
#   Monitors (webguard, beacon, outbound-ssh, fim) are copied to root-only /opt/ccdc and
#   run as systemd services ccdc-<name> that start at boot.
#   fim        baseline /etc, system binaries, PAM, systemd, cron, SSH keys (after
#              everything above, so the baseline is clean) and watch them    (all boxes)
#
# Each step asks before it runs, and a failed step doesn't stop the rest.
# Re-run one step later with e.g.: sudo ./deploy.sh --role ecom --only database
# Log: /root/ccdc/deploy-<time>.log (root-only; it includes scored users' new passwords)

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
CONF="$HERE/ccdc.conf"
FW="$HERE/linux/fw.sh"
AUDIT="$HERE/linux/audit.sh"
WG="$HERE/linux/webguard.sh"
FIM="$HERE/linux/fim.sh"
BEACON="$HERE/linux/beacon.sh"
SSHWATCH="$HERE/linux/outbound_ssh.sh"
SERVICES="$HERE/linux/services.sh"
SECURE="$HERE/linux/secure.sh"
FORWARDER="$HERE/linux/forwarder.sh"
BACKUP="$HERE/linux/backup.sh"
OPT=/opt/ccdc
ALL_STEPS=(backup passwords database firewall secure cis scan services forwarder webguard beacon fim)

ROLE=""
ONLY=""
SKIP=""
usage() { sed -n '2,34p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --role) ROLE="$2"; shift 2 ;;
    --only) ONLY="$2"; shift 2 ;;
    --skip) SKIP="$2"; shift 2 ;;
    *) usage ;;
  esac
done
case "$ROLE" in dns|mail|ecom|mysql|splunk|workstation) ;; *) echo "Bad or missing --role"; usage ;; esac
for s in ${ONLY//,/ } ${SKIP//,/ }; do
  [[ " ${ALL_STEPS[*]} " == *" $s "* ]] || { echo "Unknown step '$s'. Steps: ${ALL_STEPS[*]}"; exit 1; }
done
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)"; exit 1; }

for f in "$CONF" "$FW" "$AUDIT" "$WG" "$FIM" "$BEACON" "$SSHWATCH" "$SERVICES" "$FORWARDER" "$SECURE" "$BACKUP" "$HERE/linux/offbox.sh" "$HERE/linux/vault.sh"; do
  [ -f "$f" ] || { echo "Missing $f - copy the whole scripts folder"; exit 1; }
done
# Files copied through Windows get CRLF line endings, which break bash
sed -i 's/\r$//' "$CONF" "$HERE"/linux/*.sh
find "$HERE/containers" "$HERE/vyos" -type f \( -name '*.sh' -o -name '*.conf' \) -exec sed -i 's/\r$//' {} + 2>/dev/null
chmod +x "$HERE"/linux/*.sh

export CCDC_ROLE="$ROLE"
# shellcheck source=ccdc.conf
. "$CONF"
if [ "${CONFIG_REVIEWED:-no}" != yes ]; then
  echo "Check every value in $CONF for this year's topology, then set CONFIG_REVIEWED=yes."
  exit 1
fi

umask 077
mkdir -p /root/ccdc && chmod 700 /root/ccdc
LOG="/root/ccdc/deploy-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1

ask() {   # ask "question" default(y|n)
  local a hint="[y/N]"; [ "$2" = y ] && hint="[Y/n]"
  read -r -p "$1 $hint " a < /dev/tty || a=""
  a="${a:-$2}"
  [[ "$a" =~ ^[Yy] ]]
}

wanted() {
  [ -n "$ONLY" ] && [[ ",$ONLY," != *",$1,"* ]] && return 1
  [[ ",$SKIP," == *",$1,"* ]] && return 1
  return 0
}

# ------------------------------------------------------------------ steps

step_backup() { "$BACKUP" --role "$ROLE"; }

step_passwords() { "$AUDIT" passwords; }

step_database() {
  case "$ROLE" in
    mysql)
      "$AUDIT" mysql || return
      echo
      echo ">>> Tell the web box(es) now: run  sudo ./deploy.sh --role ecom --only database"
      ;;
    ecom|mail)
      if [ -z "${MYSQL:-}" ] && { command -v mysql || command -v mariadb; } > /dev/null &&
         { systemctl is-active --quiet mariadb mysqld mysql 2>/dev/null || ss -Hltn 2>/dev/null | grep -qE ':3306\b'; }; then
        # 2026: the shop's database runs on the E-com box itself
        echo "MySQL/MariaDB is on this box: changing its passwords, then the app config right after."
        "$AUDIT" mysql || return
      elif ! ask "Has the DB box already changed this app's MySQL password?" n; then
        echo "Do it after the DB box: sudo ./deploy.sh --role $ROLE --only database"
        return 5
      fi
      local configs=() f i
      while IFS= read -r f; do configs+=("$f"); done < <(
        for r in "${WEB_ROOTS[@]}"; do [ -d "$r" ] && echo "$r"; done |
          xargs -r -d '\n' grep -rlIE --include='*.php' --include='.env' \
            "DB_PASSWORD|database_password|_DB_PASSWD_|db_dsnw|^[[:space:]]*\\\$dbpass[[:space:]]*=" 2>/dev/null | grep -v -- '-dist\|sample\|example')
      [ ${#configs[@]} -eq 0 ] && { echo "No web app DB config found in WEB_ROOTS"; return 1; }
      for i in "${!configs[@]}"; do echo "  [$((i + 1))] ${configs[$i]}"; done
      read -r -p "Which config does the app use? (number) " i < /dev/tty
      [[ "$i" =~ ^[0-9]+$ ]] && [ "$i" -ge 1 ] && [ "$i" -le ${#configs[@]} ] || { echo "No config chosen"; return 1; }
      "$AUDIT" app-password "${configs[$((i - 1))]}"
      ;;
    *) echo "No database on a $ROLE box"; return 0 ;;
  esac
}

step_firewall() {
  "$FW" --role "$ROLE" --level "${FIREWALL_LEVEL:-medium}" --config "$CONF"
}

step_secure() {
  local parts=(ssh) p rc=0
  case "$ROLE" in
    ecom)   parts+=(web) ;;
    mail)   parts+=(web mail) ;;
    splunk) parts+=(splunk) ;;
    *)      "$SECURE" all; return ;;      # workstation / older roles: whatever runs here
  esac
  [ "${FTP_SCORED:-no}" = yes ] && parts+=(ftp)
  for p in "${parts[@]}"; do "$SECURE" "$p" || rc=1; done
  return "$rc"
}

step_cis() {
  "$HERE/linux/cis.sh" --fix
  local rc=$?
  [ "$rc" -le 1 ] && return 0   # 1 = some controls still not passing (reported), not "failed"
  return "$rc"
}

step_scan() {
  "$AUDIT" scan --fix
  local rc=$?
  [ "$rc" -le 2 ] && return 0   # 1 and 2 mean "findings", not "failed"
  return "$rc"
}

step_forwarder() {
  [ "$ROLE" = splunk ] && { echo "This is the Splunk server - no forwarder needed"; return 0; }
  "$FORWARDER"
}

step_services() {
  "$SERVICES" --fix
  local rc=$?
  [ "$rc" -le 2 ] && return 0   # 1 and 2 mean "findings", not "failed"
  return "$rc"
}

# ------------------------------------------------------------------ monitors
# Monitors run as root at boot, so they run from a root-only copy: a compromised web
# user can't edit them, and fim.sh watches /opt/ccdc for changes. Checksums are kept in
# /opt/ccdc/SHA256SUMS (verify: cd /opt/ccdc && sha256sum -c SHA256SUMS).
install_monitors() {
  install -d -m 700 -o root -g root "$OPT" "$OPT/linux" &&
    install -m 600 -o root -g root "$CONF" "$OPT/ccdc.conf" &&
    install -m 700 -o root -g root "$HERE"/linux/*.sh "$OPT/linux/" &&
    (cd "$OPT" && sha256sum ccdc.conf linux/*.sh > SHA256SUMS && chmod 600 SHA256SUMS)
}

# write_unit NAME COMMAND...: a systemd service that starts at boot and restarts on failure
write_unit() {
  local name="$1" a cmd=""; shift
  for a in "$@"; do
    a="${a//%/%%}"          # systemd expands % specifiers
    a="${a//\\/\\\\}"       # escape backslashes, then double quotes
    a="${a//\"/\\\"}"
    cmd+=" \"$a\""
  done
  cat > "/etc/systemd/system/$name.service" <<EOF
[Unit]
Description=CCDC $name (installed by deploy.sh)
After=network-online.target

[Service]
Environment=CCDC_ROLE=$ROLE
ExecStart=${cmd# }
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload && systemctl enable "$name" > /dev/null 2>&1
}

# start_service NAME COMMAND...: (re)start it now. Without systemd it runs in the
# background but does NOT start at boot.
start_service() {
  local name="$1"; shift
  if [ -d /run/systemd/system ]; then
    [ -f "/etc/systemd/system/$name.service" ] || write_unit "$name" "$@" || return
    systemctl restart "$name" || return
    sleep 2
    systemctl is-active --quiet "$name" || { journalctl -u "$name" -n 10 --no-pager; return 1; }
    echo "$name: running, starts at boot. Logs: journalctl -u $name -f   Stop: systemctl stop $name"
  else
    nohup setsid "$@" >> "/var/log/$name.out" 2>&1 < /dev/null &
    echo "$name: running in the background (pid $!), NOT started at boot (no systemd). Output: /var/log/$name.out"
  fi
}

step_webguard() {
  case "$ROLE" in ecom|mail) ;; *) echo "Not a web box"; return 0 ;; esac
  [ -d "$WEBROOT" ] || { echo "No web root at $WEBROOT - set WEBROOT in ccdc.conf"; return 1; }
  echo "Open the site in a browser NOW. The baseline is what webguard restores, so it must be clean."
  ask "Does the site look right?" n || { echo "Fix the site first, then: --only webguard"; return 5; }
  install_monitors || return
  "$OPT/linux/webguard.sh" init --webroot "$WEBROOT" || return
  local args=(watch --webroot "$WEBROOT")
  [ "${WEBGUARD_AUTO_RESTORE:-no}" = yes ] && args+=(--auto-restore)
  rm -f /etc/systemd/system/ccdc-webguard.service    # rewritten with the current settings
  start_service ccdc-webguard "$OPT/linux/webguard.sh" "${args[@]}"
}

step_beacon() {
  install_monitors || return
  rm -f /etc/systemd/system/ccdc-beacon.service /etc/systemd/system/ccdc-outbound-ssh.service
  start_service ccdc-beacon "$OPT/linux/beacon.sh" watch || return
  journalctl -u ccdc-beacon -n 3 --no-pager -o cat 2>/dev/null
  echo "Beacon table any time: $BEACON report"
  start_service ccdc-outbound-ssh "$OPT/linux/outbound_ssh.sh" --watch 10
}

step_fim() {
  install_monitors || return
  # Write the unit BEFORE the baseline: unit files are in /etc, which fim watches
  if [ -d /run/systemd/system ]; then
    systemctl stop ccdc-fim 2>/dev/null
    write_unit ccdc-fim "$OPT/linux/fim.sh" watch || return
  fi
  "$OPT/linux/fim.sh" init || return
  start_service ccdc-fim "$OPT/linux/fim.sh" watch
}

# ------------------------------------------------------------------ run

echo "=== CCDC deploy: $(hostname), role $ROLE, $(date) ==="
declare -A RESULT=()
for step in "${ALL_STEPS[@]}"; do
  if ! wanted "$step"; then RESULT[$step]="skipped"; continue; fi
  echo
  echo "################ $step ################"
  if ! ask "Run $step now?" y; then RESULT[$step]="skipped by you"; continue; fi
  "step_$step"
  case $? in
    0) RESULT[$step]="done" ;;
    3) RESULT[$step]="ROLLED BACK - rules not kept" ;;
    4) RESULT[$step]="applied but NOT saved for reboot" ;;
    5) RESULT[$step]="postponed" ;;
    *) RESULT[$step]="FAILED - see log" ;;
  esac
done

echo
echo "################ summary ################"
for step in "${ALL_STEPS[@]}"; do printf '  %-10s %s\n' "$step" "${RESULT[$step]}"; done
cat <<EOF

Log: $LOG
Passwords: /root/ccdc/passwords-*.csv (submit scored users' changes)
Next:
  - Tighten the firewall when stable:  $FW --role $ROLE --level hard
  - Harden a service again (after an inject changed it):  $SECURE web|ssh|mail|ftp|splunk
  - Backup of the hardened box, then off the box (vault window open):
        $BACKUP --role $ROLE  &&  $HERE/linux/offbox.sh push
  - Re-scan every so often:            CCDC_ROLE=$ROLE $AUDIT scan
  - Beacons (anything calling home on a timer):  $BEACON report
  - Outbound SSH right now:            $SSHWATCH
  - Updates for important services:    $SERVICES --refresh   (install: --update, one at a time)
  - Our monitors unchanged?            cd $OPT && sha256sum -c SHA256SUMS
  - Evidence for injects:              $HERE/linux/evidence.sh
  - After changing files on purpose (new passwords, config edits), tell the
    integrity monitor so it stops alerting:   $FIM accept /etc/shadow
EOF
