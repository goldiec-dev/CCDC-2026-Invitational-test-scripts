#!/bin/bash
# Network port scan of the team's own hosts: which ports are actually reachable,
# as the scoring engine and the red team see them.
#
# Usage: ./portscan.sh [TARGET...] [options]
#   TARGET          IP, hostname or CIDR (up to /22). Default: every host in ccdc.conf
#                   (ECOM, WEBMAIL, SPLUNK, PA_MGMT, AD, MSSQL, WEB, FTP, WIN11, FTD_MGMT, MYSQL, WAZUH,
#                   SCAN_TARGETS and the hosts in SCAN_EXPECT)
#   --ports LIST    comma list / ranges (22,80,8000-8100), "common" (default, ~140 ports
#                   incl. admin, database and backdoor ports) or "all" (1-65535; use nmap)
#   --udp           also scan common UDP ports (needs nmap and root)
#   --banner        grab a banner from each open port (SSH/SMTP/FTP greeting, HTTP Server header)
#   --engine E      nmap | bash (default: nmap if installed, else a built-in TCP connect scan)
#   --timeout SEC   per-port timeout for the bash engine (default 1)
#   --watch MIN     rescan every MIN minutes and alert on changes
#   --allow-any     scan targets outside the team ranges (practice labs only - CCDC rules
#                   forbid scanning other teams and competition infrastructure)
#   --config FILE   default ../ccdc.conf (INSIDE, EXTERNAL, host IPs, SCAN_EXPECT, SCAN_TARGETS)
#
# Each open port is labeled: expected (listed in SCAN_EXPECT for that host), UNEXPECTED,
# RISKY (legacy / admin / database service reachable from the network) or SUSPICIOUS
# (port commonly used by backdoors and C2). Results are compared with the previous scan:
# NEW open ports and ports that are GONE (a scored service down?) are reported and logged
# to syslog (tag ccdc-portscan). Results: /root/ccdc/portscan/ (or ~/ccdc-portscan if not root).
# Exit: 2 suspicious or new ports, 1 unexpected/risky/gone, 0 everything expected.

set -u
PORTS=common; UDP=0; BANNER=0; ENGINE=""; TIMEOUT=1; WATCH=0; ALLOW_ANY=0
CONFIG="$(dirname "$0")/../ccdc.conf"
TARGETS=()
usage() { sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'; exit 3; }
while [ $# -gt 0 ]; do
  case "$1" in
    --ports) PORTS="$2"; shift ;;
    --udp) UDP=1 ;;
    --banner) BANNER=1 ;;
    --engine) ENGINE="$2"; shift ;;
    --timeout) TIMEOUT="$2"; shift ;;
    --watch) WATCH="$2"; shift ;;
    --allow-any) ALLOW_ANY=1 ;;
    --config) CONFIG="$2"; shift ;;
    -h|--help|-*) usage ;;
    *) TARGETS+=("$1") ;;
  esac
  shift
done

INSIDE=""; EXTERNAL=""; SCAN_EXPECT=(); SCAN_TARGETS=(); SCAN_SCOPE=()
ECOM=""; WEBMAIL=""; SPLUNK=""; PA_MGMT=""; AD=""; MSSQL=""; WEB=""; FTP=""; WIN11=""; FTD_MGMT=""; MYSQL=""; WAZUH=""
# shellcheck source=../ccdc.conf
[ -f "$CONFIG" ] && . "$CONFIG"
NAMED_VARS="ECOM WEBMAIL SPLUNK PA_MGMT AD MSSQL WEB FTP WIN11 FTD_MGMT MYSQL WAZUH"

if [ "$(id -u)" -eq 0 ]; then DIR=/root/ccdc/portscan; else DIR="$HOME/ccdc-portscan"; fi
umask 077; mkdir -p "$DIR" 2>/dev/null || { echo "Cannot create $DIR"; exit 3; }

if [ -t 1 ]; then R=$'\e[31m'; Y=$'\e[33m'; G=$'\e[32m'; C=$'\e[36m'; N=$'\e[0m'; else R=; Y=; G=; C=; N=; fi

# ------------------------------------------------------------------ ports
COMMON_TCP="21,22,23,25,53,69,79,80,81,88,110,111,113,119,135,139,143,161,179,389,427,443,444,445,464,465,
500,512,513,514,515,548,554,587,593,623,631,636,646,873,902,990,993,995,1025,1080,1099,1194,1337,1433,1434,
1514,1515,1521,1723,1883,2000,2049,2082,2083,2121,2181,2222,2323,2375,2376,2483,3000,3128,3260,3268,3269,
3306,3389,3632,3690,4243,4369,4433,4444,4445,4505,4506,4786,4848,5000,5001,5060,5061,5432,5555,5601,5672,
5800,5900,5901,5902,5985,5986,6000,6001,6379,6443,6666,6667,6697,7001,7070,7443,7474,7777,8000,8001,8008,
8009,8080,8081,8088,8089,8090,8161,8180,8191,8443,8500,8834,8880,8888,9000,9001,9042,9090,9092,9100,9200,
9300,9443,9997,9999,10000,10250,11211,12345,15672,20000,27017,31337,47001,50000,50050,54321,55000,61616"
COMMON_UDP="53,67,69,123,137,161,500,514,520,1900,4500,5353"

declare -A NAME=( [21]=ftp [22]=ssh [23]=telnet [25]=smtp [53]=dns [69]=tftp [79]=finger [80]=http [88]=kerberos
  [110]=pop3 [111]=rpcbind [123]=ntp [135]=msrpc [137]=netbios-ns [139]=netbios-ssn [143]=imap [161]=snmp
  [389]=ldap [443]=https [445]=smb [464]=kpasswd [465]=smtps [500]=ike [512]=rexec [513]=rlogin [514]=rsh/syslog
  [515]=lpd [587]=submission [593]=rpc-http [631]=ipp/cups [636]=ldaps [873]=rsync [993]=imaps [995]=pop3s
  [1080]=socks [1099]=java-rmi [1337]=? [1433]=mssql [1514]=wazuh [1515]=wazuh-enroll [1521]=oracle [1723]=pptp
  [1883]=mqtt [1900]=ssdp [2049]=nfs [2222]=ssh-alt [2375]=docker-api [2376]=docker-tls [3000]=web-dev
  [3128]=squid-proxy [3268]=ldap-gc [3269]=ldaps-gc [3306]=mysql [3389]=rdp [4444]=? [4445]=? [4505]=salt
  [4506]=salt [4848]=glassfish [5000]=web-dev [5353]=mdns [5432]=postgres [5555]=adb/? [5601]=kibana
  [5672]=amqp [5800]=vnc-http [5900]=vnc [5901]=vnc [5985]=winrm [5986]=winrm-https [6000]=x11 [6379]=redis
  [6443]=kubernetes [6666]=irc/? [6667]=irc [7001]=weblogic [7777]=? [8000]=splunk-web/http [8080]=http-alt
  [8089]=splunk-mgmt [8191]=splunk-kv [8443]=https-alt [8888]=http-alt [9000]=http-alt [9001]=tor/? [9090]=http-alt
  [9200]=elasticsearch [9997]=splunk-fwd [10000]=webmin [11211]=memcached [12345]=netbus/? [27017]=mongodb
  [31337]=back-orifice/? [47001]=winrm-alt [50050]=cobalt-strike/? [54321]=? [55000]=wazuh-api )
# Reachable over the network = needs a good reason
RISKY=" 21 23 69 79 111 135 137 139 161 445 512 513 514 515 593 873 1099 1433 1521 2049 2375 3306 3389 4505 4506 5432 5800 5900 5901 5902 5985 5986 6000 6001 6379 9200 9300 10000 11211 27017 "
# Ports typically used by backdoors, Metasploit handlers and C2 frameworks
SUSPICIOUS=" 1337 4444 4445 5555 6666 6667 6697 7777 9001 12345 31337 50050 54321 "

expand_ports() {   # "22,80,8000-8010" -> one per line
  tr ', \n' '\n\n\n' <<< "$1" | sed '/^$/d' | while IFS=- read -r a b; do
    if [ -n "$b" ]; then seq "$a" "$b"; else echo "$a"; fi
  done | sort -nu
}
case "$PORTS" in
  common) PORTLIST="$COMMON_TCP" ;;
  all)    PORTLIST="1-65535" ;;
  *)      PORTLIST="$PORTS" ;;
esac
PORTLIST="$(tr -d ' \n' <<< "$PORTLIST")"

# ------------------------------------------------------------------ targets and scope
ip2n() { awk -F. 'NF == 4 { print (($1 * 256 + $2) * 256 + $3) * 256 + $4; exit } { print -1 }' <<< "$1"; }
in_cidr() {   # in_cidr IP CIDR
  local n b bits; n=$(ip2n "$1"); b=$(ip2n "${2%/*}"); bits="${2#*/}"; [ "$bits" = "$2" ] && bits=32
  [ "$n" -ge 0 ] && [ "$b" -ge 0 ] || return 1
  local size=$(( 1 << (32 - bits) )); [ $(( n / size )) -eq $(( b / size )) ]
}
NAMED_IPS=""; for v in $NAMED_VARS; do [ -n "${!v:-}" ] && NAMED_IPS+=" ${!v}"; done
in_scope() {
  [ "$ALLOW_ANY" -eq 1 ] && return 0
  local c
  for c in $INSIDE $EXTERNAL "${SCAN_SCOPE[@]}"; do [ -n "$c" ] && in_cidr "$1" "$c" && return 0; done
  [[ " $NAMED_IPS " == *" $1 "* ]]
}
label() { local v; for v in $NAMED_VARS; do [ "${!v:-}" = "$1" ] && { echo "$v"; return; }; done; echo "-"; }

if [ ${#TARGETS[@]} -eq 0 ]; then
  TARGETS=("${SCAN_TARGETS[@]}")
  for v in $NAMED_VARS; do [ -n "${!v:-}" ] && TARGETS+=("${!v}"); done
  for e in "${SCAN_EXPECT[@]}"; do TARGETS+=("${e%%:*}"); done
fi
HOSTS=()
for t in "${TARGETS[@]}"; do
  if [[ "$t" == */* ]]; then
    bits="${t#*/}"; [ "$bits" -ge 22 ] 2>/dev/null || { echo "Refusing $t: larger than /22 - scan smaller ranges"; continue; }
    base=$(ip2n "${t%/*}"); size=$(( 1 << (32 - bits) )); start=$(( base / size * size ))
    for ((i = 1; i < size - 1; i++)); do n=$((start + i)); HOSTS+=("$((n >> 24 & 255)).$((n >> 16 & 255)).$((n >> 8 & 255)).$((n & 255))"); done
  elif [[ "$t" =~ ^[0-9.]+$ ]]; then HOSTS+=("$t")
  else
    ip="$(getent ahostsv4 "$t" 2>/dev/null | awk '{ print $1; exit }')"
    [ -n "$ip" ] && HOSTS+=("$ip") || echo "Can't resolve $t - skipped"
  fi
done
SCOPED=()
for h in $(printf '%s\n' "${HOSTS[@]}" | awk '!seen[$0]++'); do
  if in_scope "$h"; then SCOPED+=("$h"); else echo "${Y}Skipping $h: outside the team ranges (INSIDE/EXTERNAL/SCAN_SCOPE in ccdc.conf). CCDC rules forbid scanning other teams.${N}"; fi
done
[ ${#SCOPED[@]} -gt 0 ] || { echo "Nothing to scan. Give targets, or fill in the host IPs in ccdc.conf."; exit 3; }

[ -z "$ENGINE" ] && { command -v nmap > /dev/null && ENGINE=nmap || ENGINE=bash; }
[ "$ENGINE" = nmap ] && ! command -v nmap > /dev/null && { echo "nmap not installed - using the bash engine"; ENGINE=bash; }
[ "$UDP" -eq 1 ] && { [ "$ENGINE" = nmap ] && [ "$(id -u)" -eq 0 ] || { echo "--udp needs nmap and root - UDP skipped"; UDP=0; }; }

expected_for() {   # expected_for IP -> " 22 80 " (empty if no SCAN_EXPECT entry)
  local e
  for e in "${SCAN_EXPECT[@]}"; do [ "${e%%:*}" = "$1" ] && { echo " $(tr ',' ' ' <<< "${e#*:}") "; return; }; done
}

# ------------------------------------------------------------------ scanning
# Output lines: host proto port
scan_nmap() {
  local args=(-n -T4 --open -oG -)
  [ $# -le 50 ] && args+=(-Pn)        # few hosts: scan even if they don't answer ping; big ranges: find live hosts first
  [ "$(id -u)" -eq 0 ] && args+=(-sS) || args+=(-sT)
  nmap "${args[@]}" -p "$PORTLIST" "$@" 2>/dev/null | parse_grepable tcp
  [ "$UDP" -eq 1 ] && nmap -n -Pn -sU --open -oG - -p "$COMMON_UDP" "$@" 2>/dev/null | parse_grepable udp
}
parse_grepable() {
  awk -v want="$1" '/Ports:/ { split($0, a, "Ports: "); host = $2; n = split(a[2], p, ", ")
    for (i = 1; i <= n; i++) { split(p[i], f, "/"); if (f[2] == "open" && f[3] == want) print host, want, f[1] } }'
}
probe() { timeout "$TIMEOUT" bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null && echo "$1 tcp $2"; }
export -f probe; export TIMEOUT
scan_bash() {
  local live=("$@")
  # Ranges: only scan hosts that answer ping (explicitly listed hosts are always scanned)
  if [ $# -gt 8 ]; then
    mapfile -t live < <(printf '%s\n' "$@" | xargs -P 64 -I{} sh -c 'ping -c1 -W1 {} > /dev/null 2>&1 && echo {}')
    echo "  ${#live[@]} of $# hosts answered ping" >&2
  fi
  [ ${#live[@]} -gt 0 ] || return 0
  local ports; ports="$(expand_ports "$PORTLIST")"
  for h in "${live[@]}"; do while read -r p; do echo "$h $p"; done <<< "$ports"; done |
    xargs -P 128 -n 2 bash -c 'probe "$0" "$1"'
}

banner() {   # banner HOST PORT -> one line
  local h="$1" p="$2"
  case "$p" in
    80|81|3000|5000|8000|8008|8080|8081|8088|8888|9000|9090)
      timeout 3 bash -c "exec 3<>/dev/tcp/$h/$p; printf 'HEAD / HTTP/1.0\r\nHost: $h\r\n\r\n' >&3; grep -im1 '^Server:' <&3" 2>/dev/null | tr -d '\r' ;;
    443|8443|9443|4433|7443|8089)
      command -v openssl > /dev/null && timeout 4 openssl s_client -connect "$h:$p" -servername "$h" < /dev/null 2>/dev/null |
        awk -F'subject=' '/subject=/ { print "TLS cert: " $2; exit }' ;;
    *) timeout 3 bash -c "exec 3<>/dev/tcp/$h/$p; read -t 2 -r l <&3 && printf '%s' \"\$l\"" 2>/dev/null | tr -d '\r' | cut -c1-80 ;;
  esac
}

# ------------------------------------------------------------------ report
run_scan() {
  local stamp out prev rc=0
  stamp="$(date +%Y%m%d-%H%M%S)"
  out="$DIR/scan-$stamp.txt"
  prev="$(ls -1t "$DIR"/scan-*.txt 2>/dev/null | head -1)"
  echo "${C}Port scan $(date '+%Y-%m-%d %H:%M:%S') - ${#SCOPED[@]} host(s) - engine $ENGINE - ports: $([ "$PORTS" = common ] && echo "common (~140)" || echo "$PORTS")$([ "$UDP" -eq 1 ] && echo " + UDP")${N}"
  case "$ENGINE" in nmap) scan_nmap "${SCOPED[@]}" ;; *) scan_bash "${SCOPED[@]}" ;; esac | sort -t' ' -k1,1V -k3,3n -u > "$out"

  local h proto port name exp status line found
  for h in "${SCOPED[@]}"; do
    exp="$(expected_for "$h")"
    found="$(awk -v h="$h" '$1 == h' "$out")"
    printf '\n%sHOST %s (%s)%s - %s open\n' "$C" "$h" "$(label "$h")" "$N" "$(grep -c . <<< "$found")"
    [ -z "$found" ] && { echo "  no open ports found (host down, all filtered, or not reachable from here)"; }
    while read -r _ proto port; do
      [ -n "${port:-}" ] || continue
      name="${NAME[$port]:-}"; [ -z "$name" ] && name="$(getent services "$port/$proto" 2>/dev/null | awk '{ print $1 }')"
      if [[ "$SUSPICIOUS" == *" $port "* ]] && [[ "$exp" != *" $port "* ]]; then
        status="${R}SUSPICIOUS - port commonly used by backdoors / C2; find the process on that host${N}"; rc=2
      elif [ -n "$exp" ] && [[ "$exp" == *" $port "* ]]; then status="${G}expected${N}"
      elif [[ "$RISKY" == *" $port "* ]]; then status="${Y}RISKY - ${name:-service} reachable from the network; needed?${N}"; [ $rc -lt 1 ] && rc=1
      elif [ -n "$exp" ]; then status="${Y}UNEXPECTED - not in SCAN_EXPECT for this host${N}"; [ $rc -lt 1 ] && rc=1
      else status="open"; fi
      line="$(printf '  %-5s %-6s %-22s %s' "$proto" "$port" "${name:--}" "$status")"
      [ "$BANNER" -eq 1 ] && [ "$proto" = tcp ] && b="$(banner "$h" "$port")" && [ -n "$b" ] && line+="  [$b]"
      echo "$line"
    done <<< "$found"
    if [ -n "$exp" ]; then
      for p in $exp; do grep -q "^$h [a-z]* $p\$" "$out" || { echo "  ${R}MISSING expected port $p${N} - is a scored service down or blocked?"; [ $rc -lt 1 ] && rc=1; }; done
    fi
  done

  if [ -n "$prev" ]; then
    local new gone
    new="$(comm -13 <(sort "$prev") <(sort "$out"))"; gone="$(comm -23 <(sort "$prev") <(sort "$out"))"
    # only compare hosts scanned both times
    new="$(grep -F -f <(printf '%s \n' "${SCOPED[@]}") <<< "$new")"; gone="$(grep -F -f <(printf '%s \n' "${SCOPED[@]}") <<< "$gone")"
    echo; echo "${C}Changes since $(basename "$prev" .txt | sed 's/scan-//'):${N}"
    [ -z "$new$gone" ] && echo "  none"
    while read -r h proto port; do [ -n "${port:-}" ] || continue
      echo "  ${R}NEW${N}  $h $proto/$port"; logger -t ccdc-portscan -p auth.warning "NEW open port $h $proto/$port" 2>/dev/null; rc=2; done <<< "$new"
    while read -r h proto port; do [ -n "${port:-}" ] || continue
      echo "  ${Y}GONE${N} $h $proto/$port (closed or blocked since last scan)"; logger -t ccdc-portscan -p auth.notice "port no longer open $h $proto/$port" 2>/dev/null
      [ $rc -lt 1 ] && rc=1; done <<< "$gone"
  else echo; echo "First scan - saved as the reference for the next one."; fi
  echo; echo "Saved: $out"
  return $rc
}

if [ "$WATCH" -gt 0 ] 2>/dev/null; then
  while true; do run_scan; echo "--- next scan in ${WATCH} min (Ctrl-C to stop)"; sleep $((WATCH * 60)); done
else
  run_scan; exit $?
fi
