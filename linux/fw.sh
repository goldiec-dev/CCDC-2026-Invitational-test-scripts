#!/bin/bash
# Unified iptables firewall for CCDC Linux boxes.
#
# Usage: fw.sh --role ROLE --level LEVEL [--config FILE] [--timeout SEC] [--dry-run]
#   ROLE:  ecom | mail | splunk | workstation   (dns | mysql: older topologies)
#   LEVEL: light   - filter inbound only, outbound open
#          medium  - default-deny both ways, outbound allowed to any destination
#          hard    - medium + drop bogus TCP flags/fragments, inbound ping requests only
#          extreme - hard + internal-only ports restricted to INSIDE, outbound pinned to
#                    known hosts, web egress only to non-team addresses
#
# Scored service ports accept connections from anywhere at every level (the scoring
# engine's address isn't known), and inbound ping is always allowed (competition rule).
# SSH (22) is open to everyone on the servers while SSH_SCORED=yes in ccdc.conf (it's scored),
# and closed otherwise. Workstations never accept SSH. We manage boxes from their VM consoles.
#
# Safety: current rules are backed up to /var/tmp and restored automatically after
# --timeout seconds (default 90) unless you type "yes". This also happens if your
# session drops. Rules are persisted for reboot only after you confirm.

set -u

ROLE=""
LEVEL=""
CONFIG="$(dirname "$0")/../ccdc.conf"
TIMEOUT=90
DRY_RUN=0

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --role)    ROLE="$2"; shift 2 ;;
    --level)   LEVEL="$2"; shift 2 ;;
    --config)  CONFIG="$2"; shift 2 ;;
    --timeout) TIMEOUT="$2"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    *) usage ;;
  esac
done

case "$ROLE" in dns|mail|ecom|mysql|splunk|workstation) ;; *) echo "Bad or missing --role"; usage ;; esac
case "$LEVEL" in light|medium|hard|extreme) ;; *) echo "Bad or missing --level"; usage ;; esac
[ -f "$CONFIG" ] || { echo "Config not found: $CONFIG"; exit 1; }
# shellcheck source=../ccdc.conf
. "$CONFIG"

if [ "$DRY_RUN" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
  echo "Run as root (or use --dry-run)"; exit 1
fi
# Debian 12 (and some minimal Rocky installs) ship nftables without the iptables tools
if [ "$DRY_RUN" -eq 0 ] && ! { command -v iptables && command -v ip6tables; } > /dev/null; then
  echo "iptables is not installed. Debian/Ubuntu: apt install iptables iptables-persistent"
  echo "Rocky/RHEL: dnf install iptables-nft iptables-services"
  exit 1
fi

# Extreme pins rules to specific hosts, so every host this role uses must be set
if [ "$LEVEL" = extreme ]; then
  need="INSIDE EXTERNAL AD"
  [ "$ROLE" != splunk ] && need="$need SPLUNK"
  [ "$ROLE" = mysql ] && need="$need ECOM"
  [[ "${EXTERNAL:-}" == *XX* ]] && { echo "ccdc.conf: set EXTERNAL to the team's public range (172.25.<20+team>.0/24)"; exit 1; }
  for v in $need; do
    [ -n "${!v:-}" ] || { echo "ccdc.conf: $v must be set for extreme"; exit 1; }
  done
fi

ipt()  { if [ "$DRY_RUN" -eq 1 ]; then echo "iptables $*";  else iptables "$@";  fi; }
ipt6() { if [ "$DRY_RUN" -eq 1 ]; then echo "ip6tables $*"; else ip6tables "$@"; fi; }

STATE="-m conntrack --ctstate"

# Docker / Podman keep their own chains in the nat and filter tables (a published container port
# is a DNAT rule plus FORWARD rules). Flushing them would cut a containerized scored service off,
# so with a container engine on the box only our INPUT and OUTPUT chains are rebuilt.
CONTAINERS=0
if systemctl is-active --quiet docker 2>/dev/null || systemctl is-active --quiet podman 2>/dev/null ||
   [ -S /var/run/docker.sock ] || { [ "$DRY_RUN" -eq 0 ] && iptables -S 2>/dev/null | grep -qE '^-N (DOCKER|NETAVARK|CNI-)'; }; then
  CONTAINERS=1
  echo "Container engine found: leaving the nat table, FORWARD and the Docker/Podman chains alone."
  echo "Published container ports (-p) are filtered by the engine, not by these INPUT rules - publish only scored ports."
fi

# allow_in PROTO PORT [SRC]  - SRC is only applied at extreme; prefix with ! to negate
allow_in() {
  local src=()
  if [ "$LEVEL" = extreme ] && [ -n "${3:-}" ]; then
    if [ "${3:0:1}" = "!" ]; then src=(! -s "${3:1}"); else src=(-s "$3"); fi
  fi
  ipt -A INPUT -p "$1" "${src[@]}" --dport "$2" $STATE NEW -j ACCEPT
}

# allow_out PROTO PORT [DST] - DST is only applied at extreme
allow_out() {
  local dst=()
  [ "$LEVEL" = extreme ] && [ -n "${3:-}" ] && dst=(-d "$3")
  ipt -A OUTPUT -p "$1" "${dst[@]}" --dport "$2" $STATE NEW -j ACCEPT
}

# Is IP one of this box's addresses?
is_me() { [ -n "$1" ] && ip -o addr show 2>/dev/null | awk '{ split($4, a, "/"); print a[1] }' | grep -qxF "$1"; }

role_inbound() {
  # Wazuh manager on this box: agents enroll (1515) and report (1514); dashboard for the team
  if is_me "${WAZUH:-}"; then
    allow_in tcp 1514 "$INSIDE"
    allow_in tcp 1515 "$INSIDE"
    allow_in tcp "${WAZUH_DASHBOARD_PORT:-443}" "$INSIDE"
  fi
  # Scored services: no source restriction (the scoring engine may be inside or outside)
  case "$ROLE" in
    dns)
      allow_in udp 53
      allow_in tcp 53 ;;
    mail)
      allow_in tcp 25                      # SMTP (scored)
      allow_in tcp 110                     # POP3 (scored)
      allow_in tcp 143                     # IMAP (scored)
      allow_in tcp 80                      # webmail (scored)
      allow_in tcp 443
      for p in 465 587 993 995; do allow_in tcp "$p"; done ;;   # TLS / submission variants
    ecom)
      allow_in tcp 80                      # HTTP (scored)
      allow_in tcp 443 ;;                  # HTTPS (scored)
    mysql)
      allow_in tcp 3306 "$ECOM" ;;
    splunk)
      allow_in tcp 8000                    # web UI (Splunk query check is scored)
      allow_in tcp 8089                    # management / REST API (scored)
      allow_in tcp 9997 "$INSIDE"          # forwarders
      [ -n "${KALI_NET:-}" ] && [ "$LEVEL" = extreme ] && allow_in tcp 9997 "$KALI_NET"   # Kali (behind the router)
      allow_in udp 514 "$INSIDE"           # syslog from the Palo Alto / FTD / Linux boxes
      allow_in tcp 514 "$INSIDE" ;;
    workstation) ;;                        # nothing inbound except ping
  esac
}

role_outbound() {
  allow_out udp 53
  allow_out tcp 53 "$AD"
  allow_out udp 123 "$AD"
  # Active Directory: Kerberos, LDAP, kpasswd, global catalog - needed when a box is joined
  # to the domain or (webmail) checks POP3/IMAP logins against AD
  if [ -n "${AD:-}" ]; then
    for p in 88 464; do allow_out tcp "$p" "$AD"; allow_out udp "$p" "$AD"; done
    allow_out udp 389 "$AD"
    for p in 389 636 3268 3269; do allow_out tcp "$p" "$AD"; done
  fi
  if [ "$ROLE" = splunk ]; then
    allow_out tcp 8089
  else
    allow_out tcp 9997 "$SPLUNK"
    allow_out tcp 8089 "$SPLUNK"
  fi
  if [ "$ROLE" = workstation ] && [ -n "${INSIDE:-}" ]; then
    # team console: Splunk web, the Palo Alto web UI (443 below)
    allow_out tcp 8000 "$INSIDE"
    [ "$LEVEL" = extreme ] && { ipt -A OUTPUT -p tcp -d "$INSIDE" --dport 443 $STATE NEW -j ACCEPT
                                ipt -A OUTPUT -p tcp -d "$INSIDE" --dport 80 $STATE NEW -j ACCEPT; }
  fi
  if [ -n "${WAZUH:-}" ] && ! is_me "$WAZUH"; then
    allow_out tcp 1514 "$WAZUH"
    allow_out tcp 1515 "$WAZUH"
  fi
  [ "$ROLE" = ecom ] && [ -n "${MYSQL:-}" ] && allow_out tcp 3306 "$MYSQL"
  ipt -A OUTPUT -p icmp --icmp-type echo-request $STATE NEW -j ACCEPT
  if [ "$LEVEL" = extreme ]; then
    # Web egress to the internet only, never to other team hosts
    ipt -A OUTPUT -d "$INSIDE" -j DROP
    ipt -A OUTPUT -d "$EXTERNAL" -j DROP
  fi
  allow_out tcp 80
  allow_out tcp 443
}

# Log what the default-deny is about to drop, rate-limited so a flood can't fill the
# disk. Kernel messages go to the journal / kern.log / syslog (Splunk): grep CCDC-DROP
log_drop() {   # log_drop ipt|ipt6 CHAIN TAG
  [ "${FW_LOG_DROPS:-yes}" = yes ] || return 0
  "$1" -A "$2" -m limit --limit 20/min --limit-burst 50 -j LOG --log-prefix "CCDC-DROP-$3: " --log-level 4
}
log_drops() { log_drop "$1" INPUT IN6; log_drop "$1" OUTPUT OUT6; }

apply_rules() {
  # IPv6: loopback and replies only
  if [ "$CONTAINERS" -eq 1 ]; then ipt6 -F INPUT; ipt6 -F OUTPUT
  else ipt6 -t nat -F; ipt6 -t mangle -F; ipt6 -F; ipt6 -X; ipt6 -Z; fi
  ipt6 -P INPUT ACCEPT; ipt6 -P OUTPUT ACCEPT
  ipt6 -A INPUT -i lo -j ACCEPT
  ipt6 -A INPUT $STATE ESTABLISHED,RELATED -j ACCEPT
  ipt6 -A OUTPUT -o lo -j ACCEPT
  ipt6 -A OUTPUT $STATE ESTABLISHED,RELATED -j ACCEPT
  log_drops ipt6
  ipt6 -P INPUT DROP; ipt6 -P OUTPUT DROP
  [ "$CONTAINERS" -eq 1 ] || ipt6 -P FORWARD DROP

  # IPv4 reset. Policies go to ACCEPT first so the box is never half-closed mid-build
  ipt -P INPUT ACCEPT; ipt -P OUTPUT ACCEPT
  if [ "$CONTAINERS" -eq 1 ]; then
    ipt -F INPUT; ipt -F OUTPUT; ipt -Z INPUT; ipt -Z OUTPUT     # containers' chains untouched
  else
    ipt -t nat -F; ipt -t mangle -F; ipt -F; ipt -X; ipt -Z
    ipt -P FORWARD DROP
  fi

  # IPv4 inbound
  if [ "$LEVEL" = hard ] || [ "$LEVEL" = extreme ]; then
    ipt -A INPUT -p tcp ! --syn $STATE NEW -j DROP
    ipt -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    ipt -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    ipt -A INPUT -f -j DROP
  fi
  ipt -A INPUT -i lo -j ACCEPT
  ipt -A INPUT $STATE ESTABLISHED,RELATED -j ACCEPT
  # Workstations have no inbound public address, so SSH can't be scored there
  if [ "${SSH_SCORED:-yes}" = yes ] && [ "$ROLE" != workstation ]; then
    ipt -A INPUT -p tcp --dport 22 $STATE NEW -j ACCEPT   # scored: the scorer's address isn't known
  fi
  role_inbound
  if [ "${FTP_SCORED:-no}" = yes ]; then   # FTP control + the passive range secure.sh sets in vsftpd
    ipt -A INPUT -p tcp --dport 21 $STATE NEW -j ACCEPT
    ipt -A INPUT -p tcp --dport "${FTP_PASV:-40000:40100}" $STATE NEW -j ACCEPT
  fi
  case "$LEVEL" in
    light|medium) ipt -A INPUT -p icmp -j ACCEPT ;;
    hard)         ipt -A INPUT -p icmp --icmp-type echo-request -j ACCEPT ;;
    extreme)                               # competition rule: keep ICMP up
      ipt -A INPUT -p icmp --icmp-type echo-request -j ACCEPT ;;
  esac
  log_drop ipt INPUT IN
  ipt -P INPUT DROP

  # IPv4 outbound
  [ "$LEVEL" = light ] && return
  ipt -A OUTPUT -o lo -j ACCEPT
  ipt -A OUTPUT $STATE ESTABLISHED,RELATED -j ACCEPT
  role_outbound
  log_drop ipt OUTPUT OUT
  ipt -P OUTPUT DROP
}

persist() {
  if [ -d /etc/sysconfig ]; then
    iptables-save > /etc/sysconfig/iptables && ip6tables-save > /etc/sysconfig/ip6tables || return 1
    systemctl enable iptables ip6tables 2>/dev/null || echo "WARN: install iptables-services to load rules at boot"
  else
    mkdir -p /etc/iptables &&
      iptables-save > /etc/iptables/rules.v4 && ip6tables-save > /etc/iptables/rules.v6 || return 1
    systemctl enable netfilter-persistent 2>/dev/null || echo "WARN: install iptables-persistent to load rules at boot"
  fi
}

if [ "$DRY_RUN" -eq 1 ]; then
  echo "# role=$ROLE level=$LEVEL (dry run, nothing applied)"
  apply_rules
  exit 0
fi

# Back up current state and arm the rollback timer
BK="/var/tmp/fw-backup-$(date +%Y%m%d-%H%M%S)"
iptables-save > "$BK.v4"
ip6tables-save > "$BK.v6"
RESTART=""
systemctl is-active --quiet firewalld 2>/dev/null && RESTART="systemctl start firewalld;"
ufw status 2>/dev/null | grep -q "Status: active" && RESTART="$RESTART ufw --force enable;"
# Open everything first: if the box had no rules, the backup is empty and restoring it alone changes nothing
OPEN="for t in iptables ip6tables; do \$t -P INPUT ACCEPT; \$t -P OUTPUT ACCEPT; \$t -F; \$t -X; done;"
ROLLBACK="$OPEN iptables-restore < '$BK.v4'; ip6tables-restore < '$BK.v6'; $RESTART"

setsid bash -c "echo \$\$ > '$BK.pid'; sleep $TIMEOUT; $ROLLBACK rm -f '$BK.pid'; echo 'fw.sh: no confirmation, firewall rolled back' | wall" \
  > /dev/null 2>&1 < /dev/null &
sleep 0.2

# Stop other firewall managers so they do not overwrite these rules
systemctl disable --now firewalld 2>/dev/null
ufw disable 2>/dev/null

apply_rules
iptables -L -n -v --line-numbers

echo
echo "Backup: $BK.v4 / $BK.v6"
echo "Check that scored services still work (from another box if you can)."
# Exit codes: 0 kept and persisted, 3 rolled back, 4 kept but not persisted
read -r -t "$TIMEOUT" -p "Type 'yes' within $TIMEOUT s to keep these rules: " ans
if [ "${ans:-}" = yes ]; then
  kill "$(cat "$BK.pid")" 2>/dev/null
  rm -f "$BK.pid"
  if persist; then
    echo "Rules kept and persisted."
  else
    echo "Rules kept but NOT persisted - they will be lost on reboot."
    exit 4
  fi
else
  kill "$(cat "$BK.pid")" 2>/dev/null
  rm -f "$BK.pid"
  eval "$ROLLBACK"
  echo "Not confirmed - previous rules restored."
  exit 3
fi
