#!/bin/bash
# Collect evidence for the initial injects in one report (read-only, except the two
# optional tests below). Paste the output or screenshot it into the inject memo.
#
# Usage: sudo ./evidence.sh [--section LIST] [--fim-test] [--log-test]
#   --section LIST  comma-separated, from: system,time,network,firewall,startup,fim,logging,traffic
#                   (default: all)
#   --fim-test      prove file integrity monitoring works: create a test file in /etc, show
#                   fim.sh detecting it, delete it, show the alert clears
#   --log-test      send a uniquely tagged test message to syslog, to find in Splunk/Wazuh
#   --config FILE   default ../ccdc.conf (SPLUNK, WAZUH, AD)
#
# Report: /root/ccdc/evidence-<host>-<time>.txt

set -u
SECTIONS="system,time,network,firewall,startup,fim,logging,traffic"
FIM_TEST=0; LOG_TEST=0
HERE="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$HERE/../ccdc.conf"
usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --section)  SECTIONS="$2"; shift 2 ;;
    --fim-test) FIM_TEST=1; shift ;;
    --log-test) LOG_TEST=1; shift ;;
    --config)   CONFIG="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)"; exit 1; }
SPLUNK=""; WAZUH=""; AD=""
# shellcheck source=../ccdc.conf
[ -f "$CONFIG" ] && . "$CONFIG"

umask 077; mkdir -p /root/ccdc
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="/root/ccdc/evidence-$(hostname -s)-$STAMP.txt"
exec > >(tee "$OUT") 2>&1

want() { [[ ",$SECTIONS," == *",$1,"* ]]; }
h1() { printf '\n==================== %s ====================\n' "$1"; }
run() { printf '\n$ %s\n' "$*"; "$@" 2>&1; }          # show the command, then its output
have() { command -v "$1" > /dev/null; }
tcp_ok() { timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null && echo "OK    $1:$2" || echo "FAIL  $1:$2"; }

echo "CCDC evidence report - $(hostname -f 2>/dev/null || hostname) - $(date '+%Y-%m-%d %H:%M:%S %Z')"

# ------------------------------------------------------------------ system
if want system; then
  h1 "SYSTEM"
  grep -E '^PRETTY_NAME' /etc/os-release
  run uname -r
  run ip -br addr
  run uptime
fi

# ------------------------------------------------------------------ time
if want time; then
  h1 "TIME SYNCHRONIZATION (NTP / PTP)"
  run timedatectl
  if have chronyc; then
    run chronyc tracking
    run chronyc sources -v
  elif systemctl is-active --quiet systemd-timesyncd 2>/dev/null; then
    run timedatectl timesync-status
  elif have ntpq; then
    run ntpq -p
  else
    echo "No NTP client found (chrony, systemd-timesyncd or ntpd) - see checklists/TIME_SYNC.md"
  fi
  if have pmc && systemctl is-active --quiet ptp4l 2>/dev/null; then
    run pmc -u -b 0 'GET CURRENT_DATA_SET'
  else
    echo "PTP (ptp4l): not running - NTP is the time source"
  fi
fi

# ------------------------------------------------------------------ network
if want network; then
  h1 "NETWORK CONNECTIVITY"
  run ip route
  gw="$(ip route | awk '/^default/ { print $3; exit }')"
  [ -n "$gw" ] && run ping -c 2 -W 2 "$gw"
  echo; echo "DNS servers: $(awk '/^nameserver/ { printf "%s ", $2 }' /etc/resolv.conf)"
  if have getent; then run getent hosts "$(hostname -f 2>/dev/null || hostname)"; run getent hosts www.google.com; fi
  echo; echo "Required services:"
  [ -n "$AD" ]     && tcp_ok "$AD" 53
  [ -n "$SPLUNK" ] && tcp_ok "$SPLUNK" 9997
  [ -n "$WAZUH" ]  && tcp_ok "$WAZUH" 1514
  tcp_ok 1.1.1.1 443
fi

# ------------------------------------------------------------------ firewall
if want firewall; then
  h1 "HOST FIREWALL POLICY"
  for t in iptables ip6tables; do
    echo; echo "$t default policies:"
    $t -S 2>/dev/null | grep '^-P'
  done
  echo; echo "Inbound allowed (NEW connections):"
  iptables -S INPUT 2>/dev/null | grep -- '-j ACCEPT' | grep -E 'NEW|dport' |
    sed -E 's/-m conntrack --ctstate NEW//; s/-A INPUT //; s/ -j ACCEPT//'
  echo; echo "Outbound allowed (NEW connections):"
  iptables -S OUTPUT 2>/dev/null | grep -- '-j ACCEPT' | grep -E 'NEW|dport' |
    sed -E 's/-m conntrack --ctstate NEW//; s/-A OUTPUT //; s/ -j ACCEPT//'
  echo; echo "Deny-by-default with logging (for threat hunting):"
  for c in INPUT OUTPUT; do
    p="$(iptables -S 2>/dev/null | awk -v c="$c" '$1 == "-P" && $2 == c { print $3 }')"
    l="$(iptables -S "$c" 2>/dev/null | grep -c 'CCDC-DROP')"
    echo "  $c: policy ${p:-?}, drop logging rule: $([ "$l" -gt 0 ] && echo yes || echo NO)"
  done
  echo "  Dropped packets logged in the last hour: $(journalctl -k --since '-1h' 2>/dev/null | grep -c 'CCDC-DROP')"
  journalctl -k --since '-1h' 2>/dev/null | grep 'CCDC-DROP' | tail -5
  run iptables -L -n -v --line-numbers
  have ufw && run ufw status
  systemctl is-active --quiet firewalld 2>/dev/null && run firewall-cmd --list-all
fi

# ------------------------------------------------------------------ startup
if want startup; then
  h1 "STARTUP SCRIPTS AND THEIR INTEGRITY"
  echo "Our monitors (systemd services, start at boot):"
  for s in ccdc-webguard ccdc-beacon ccdc-outbound-ssh ccdc-fim; do
    e="$(systemctl is-enabled "$s" 2>/dev/null)"; a="$(systemctl is-active "$s" 2>/dev/null)"
    printf '  %-20s enabled=%-10s active=%s\n' "$s" "${e:-no}" "${a:-no}"
  done
  if [ -f /opt/ccdc/SHA256SUMS ]; then
    echo; echo "Integrity of the installed monitor scripts:"
    run bash -c 'cd /opt/ccdc && ls -la . linux && sha256sum -c SHA256SUMS'
  else
    echo "  /opt/ccdc not installed - run deploy.sh (webguard / beacon / fim steps)"
  fi
  echo; echo "Other things that start at boot (review for persistence):"
  run systemctl list-unit-files --type=service --state=enabled --no-pager
  run bash -c 'grep -rHs "@reboot" /etc/crontab /etc/cron.d /var/spool/cron 2>/dev/null || echo "no @reboot cron entries"'
  [ -s /etc/rc.local ] && run cat /etc/rc.local
fi

# ------------------------------------------------------------------ fim
if want fim; then
  h1 "FILE INTEGRITY MONITORING"
  FIMSH=/opt/ccdc/linux/fim.sh; [ -x "$FIMSH" ] || FIMSH="$HERE/fim.sh"
  a="$(systemctl is-active ccdc-fim 2>/dev/null)"; printf 'Service ccdc-fim: %s\n' "${a:-not running}"
  [ -f /root/.ccdc-fim/baseline ] && echo "Baseline: $(wc -l < /root/.ccdc-fim/baseline) files, $(date -r /root/.ccdc-fim/baseline '+taken %Y-%m-%d %H:%M')"
  run "$FIMSH" list
  if [ "$FIM_TEST" -eq 1 ]; then
    T="/etc/ccdc-fim-proof-$STAMP.txt"
    echo; echo "--- FIM proof: create $T, detect it, remove it"
    echo "CCDC file integrity test $STAMP" > "$T"
    run "$FIMSH" check
    rm -f "$T"
    echo "--- test file removed; check again (expect 'No changes.' unless something else changed):"
    run "$FIMSH" check
  else
    echo "(add --fim-test for a live detection demo)"
  fi
  echo; echo "Recent fim alerts:"
  journalctl -t ccdc-fim -n 10 --no-pager -o short-iso 2>/dev/null || tail -10 /var/log/ccdc-fim.log 2>/dev/null
fi

# ------------------------------------------------------------------ logging
if want logging; then
  h1 "CENTRALIZED LOGGING"
  for s in wazuh-agent SplunkForwarder splunk rsyslog systemd-journald; do
    systemctl list-unit-files "$s.service" > /dev/null 2>&1 &&
      printf '  %-18s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null)"
  done
  echo; echo "Live connections to log collectors (Wazuh 1514, Splunk 9997, syslog 514):"
  ss -Htnp state established '( dport = :1514 or dport = :9997 or dport = :514 )' 2>/dev/null || true
  [ -f /var/ossec/logs/ossec.log ] && { echo; echo "Wazuh agent:"; grep -E "Connected to the server|Lost connection|Unable to connect" /var/ossec/logs/ossec.log | tail -3; }
  if [ "$LOG_TEST" -eq 1 ]; then
    ID="ccdc-logtest-$(hostname -s)-$STAMP"
    logger -t ccdc-evidence -p auth.notice "CCDC centralized logging test id=$ID"
    echo; echo "Sent test message id=$ID. Find it and screenshot it:"
    echo "  Splunk: index=* \"$ID\""
    echo "  Wazuh:  Discover / Threat Hunting, search \"$ID\""
  else
    echo "(add --log-test to send a tagged test message to find in Splunk/Wazuh)"
  fi
fi

# ------------------------------------------------------------------ traffic
if want traffic; then
  h1 "TRAFFIC PROFILE"
  run ss -tulpn
  echo; echo "Established connections by remote address and program (count, remote, program):"
  ss -Htnp state established 2>/dev/null | awk '
    { p = "-"; if (match($0, /users:\(\("[^"]+"/)) p = substr($0, RSTART + 9, RLENGTH - 10)
      r = $4; sub(/:[0-9]+$/, "", r); gsub(/^\[|\]$/, "", r); c[r "\t" p]++ }
    END { for (k in c) print c[k] "\t" k }' | sort -rn | head -25 | column -t -s$'\t'
  BEACON=/opt/ccdc/linux/beacon.sh; [ -x "$BEACON" ] || BEACON="$HERE/beacon.sh"
  [ -s /root/ccdc/beacon/events ] && run "$BEACON" report
  SSHW=/opt/ccdc/linux/outbound_ssh.sh; [ -x "$SSHW" ] || SSHW="$HERE/outbound_ssh.sh"
  run "$SSHW" --no-state
fi

echo; echo "Report saved: $OUT"
