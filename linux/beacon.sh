#!/bin/bash
# Beacon detector: find outbound connections that repeat on a timer (malware
# calling home every N seconds), and the process making them.
#
# Usage: beacon.sh COMMAND [options]
#   watch    Record every new outbound connection and check for beacons every
#            minute. Runs until stopped (deploy.sh runs it as the ccdc-beacon unit).
#   report   Show every repeating destination recorded so far, beacons first.
#            Works while watch is running.
#
# Options:
#   --interval SEC   poll interval (default 2)
#   --window SEC     how far back to look (default 7200 = 2 hours)
#   --min-hits N     connections needed before judging a destination (default 8)
#   --min-gap SEC    ignore destinations contacted more often than this (default 10)
#   --source S       conntrack | tcpdump | ss (default: the best one available)
#   --config FILE    default ../ccdc.conf (INSIDE, SPLUNK, BEACON_ALLOW)
#   --store DIR      where connections are recorded (default /root/ccdc/beacon)
#
# A destination (IP, port, protocol) is a BEACON when at least 80% of the gaps
# between connections to it are within 25% of the typical gap, and there are at
# least --min-hits connections ("maybe" in the report: 50-80%, worth a look).
# Report-only: nothing is blocked. Alerts go to syslog (tag ccdc-beacon) for Splunk.
#
# Sources, best first: the kernel connection table (keeps short connections ~2 min,
# so none are missed), tcpdump (exact times, TCP and ping only), ss (only sees
# connections open or in TIME-WAIT at the moment of a poll - can miss short ones).

set -u

CMD="${1:-}"; [ $# -gt 0 ] && shift
INTERVAL=2
WINDOW=7200
MIN_HITS=8
MIN_GAP=10
SOURCE=""
CONFIG="$(dirname "$0")/../ccdc.conf"
DIR=/root/ccdc/beacon
TOLERANCE=0.25
REGULAR=0.8

usage() { sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --interval) INTERVAL="$2"; shift 2 ;;
    --window)   WINDOW="$2"; shift 2 ;;
    --min-hits) MIN_HITS="$2"; shift 2 ;;
    --min-gap)  MIN_GAP="$2"; shift 2 ;;
    --source)   SOURCE="$2"; shift 2 ;;
    --config)   CONFIG="$2"; shift 2 ;;
    --store)    DIR="$2"; shift 2 ;;
    *) usage ;;
  esac
done
case "$CMD" in watch|report) ;; *) usage ;; esac
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)"; exit 1; }

INSIDE=""; SPLUNK=""; BEACON_ALLOW=()
# shellcheck source=../ccdc.conf
[ -f "$CONFIG" ] && . "$CONFIG"

# Regular traffic that is expected: NTP, DNS to our resolvers, Splunk forwarding
# and deployment-server check-ins. Format: IP, IP:PORT or :PORT
ALLOW=(":123" "${BEACON_ALLOW[@]}")
[ -n "$SPLUNK" ] && ALLOW+=("$SPLUNK:9997" "$SPLUNK:8089")
[ -n "${WAZUH:-}" ] && ALLOW+=("$WAZUH:1514" "$WAZUH:1515")
for r in $(awk '$1 == "nameserver" { print $2 }' /etc/resolv.conf 2>/dev/null); do ALLOW+=("$r:53"); done

umask 077
mkdir -p "$DIR"
EVENTS="$DIR/events"       # ts \t proto \t dst \t dport \t process
SEEN="$DIR/seen"           # connection key \t last seen
touch "$EVENTS" "$SEEN"
LOG=/var/log/ccdc-beacon.log

log() {
  local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $1"
  echo "$msg"
  { echo "$msg" >> "$LOG"; } 2>/dev/null
  logger -t ccdc-beacon -p auth.alert "$1" 2>/dev/null
}

TMP="$(mktemp -d)" || exit 1
TCPDUMP_PID=""
cleanup() { [ -n "$TCPDUMP_PID" ] && kill "$TCPDUMP_PID" 2>/dev/null; rm -rf "$TMP"; }
trap cleanup EXIT
trap 'exit 0' INT TERM

local_ips() { ip -o addr show 2>/dev/null | awk '{ split($4, a, "/"); print a[1] }' | tr '\n' ' '; }

# ------------------------------------------------------------------ sources
# Each prints "ts \t proto \t src \t sport \t dst \t dport" for OUTBOUND connections.

conntrack_raw() {
  if [ -r /proc/net/nf_conntrack ]; then cat /proc/net/nf_conntrack
  else conntrack -L -o extended 2>/dev/null || conntrack -L 2>/dev/null; fi
}
snap_conntrack() {
  conntrack_raw | awk -v now="$1" -v locals="$(local_ips)" '
    BEGIN { n = split(locals, L, " "); for (i = 1; i <= n; i++) mine[L[i]] = 1 }
    { proto = s = d = sp = dp = ""
      for (i = 1; i <= NF; i++) {
        f = $i
        if (proto == "" && (f == "tcp" || f == "udp" || f == "icmp" || f == "icmpv6")) proto = f
        else if (s == ""  && f ~ /^src=/)   s  = substr(f, 5)
        else if (d == ""  && f ~ /^dst=/)   d  = substr(f, 5)
        else if (sp == "" && f ~ /^sport=/) sp = substr(f, 7)
        else if (dp == "" && f ~ /^dport=/) dp = substr(f, 7)
        else if (sp == "" && f ~ /^id=/)    sp = substr(f, 4)
        else if (dp == "" && f ~ /^type=/)  dp = "type" substr(f, 6)
      }
      if (proto == "" || !(s in mine) || (d in mine) || d ~ /^127\./ || d == "::1") next
      print now "\t" proto "\t" s "\t" sp "\t" d "\t" dp }'
}

# "addr:port" (ss) -> addr, port. Handles [v6]:port, %iface and ::ffff: prefixes.
AWK_ADDR='function split_addr(x, r,   k) { k = 0; while (match(substr(x, k + 1), /:/)) k += RSTART
  r["a"] = substr(x, 1, k - 1); r["p"] = substr(x, k + 1)
  gsub(/^\[|\]$/, "", r["a"]); sub(/%.*/, "", r["a"]); sub(/^::ffff:/, "", r["a"]) }'

snap_ss() {
  local listening
  listening="$(ss -Htlnu 2>/dev/null | awk '{ n = split($5, a, ":"); print a[n] }' | sort -u | tr '\n' ' ')"
  ss -Htuan 2>/dev/null | awk -v now="$1" -v listen="$listening" "$AWK_ADDR"'
    BEGIN { n = split(listen, L, " "); for (i = 1; i <= n; i++) lp[L[i]] = 1 }
    $2 == "LISTEN" || $2 == "UNCONN" { next }
    { split_addr($5, l); split_addr($6, p)
      if (p["p"] == "*" || p["a"] ~ /^(\*|0\.0\.0\.0|::)$/ || p["a"] ~ /^127\./ || p["a"] == "::1") next
      if (l["p"] in lp) next                         # someone connected TO us
      print now "\t" $1 "\t" l["a"] "\t" l["p"] "\t" p["a"] "\t" p["p"] }'
}

# tcpdump runs in the background; each poll reads the lines added since the last one
start_tcpdump() {
  : > "$TMP/tcpdump.out"
  tcpdump -Z root -l -nn -tt -i any -Q out \
    '(tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn) or (icmp[icmptype] == icmp-echo) or (ip6 and ip6[40] == 128)' \
    >> "$TMP/tcpdump.out" 2>/dev/null &
  TCPDUMP_PID=$!
  TCPDUMP_OFF=0
  sleep 1
  kill -0 "$TCPDUMP_PID" 2>/dev/null
}
snap_tcpdump() {
  local size
  size=$(stat -c %s "$TMP/tcpdump.out")
  [ "$size" -gt "$TCPDUMP_OFF" ] || return 0
  tail -c +$((TCPDUMP_OFF + 1)) "$TMP/tcpdump.out" | head -c $((size - TCPDUMP_OFF)) | awk '
    { for (i = 2; i <= NF; i++) if ($i == "IP" || $i == "IP6") break
      if (i >= NF) next
      src = $(i + 1); dst = $(i + 3); sub(/:$/, "", dst)
      if ($0 ~ /ICMP6? echo request|ICMP6, echo request/) {
        proto = "icmp"; sp = ""; dp = "echo"
        if (match($0, /id [0-9]+/)) sp = substr($0, RSTART + 3, RLENGTH - 3)
      } else {
        proto = "tcp"
        k = 0; while (match(substr(src, k + 1), /\./)) k += RSTART; sp = substr(src, k + 1); src = substr(src, 1, k - 1)
        k = 0; while (match(substr(dst, k + 1), /\./)) k += RSTART; dp = substr(dst, k + 1); dst = substr(dst, 1, k - 1)
      }
      if (dst ~ /^127\./ || dst == "::1") next
      print int($1) "\t" proto "\t" src "\t" sp "\t" dst "\t" dp }'
  TCPDUMP_OFF=$size
}

# Which process owns each connection right now: "lport|peer|pport \t name[pid]"
procmap() {
  ss -Htuanp 2>/dev/null | awk "$AWK_ADDR"'
    { i = index($0, "users:((\""); if (!i) next
      rest = substr($0, i + 9); name = substr(rest, 1, index(rest, "\"") - 1)
      j = index(rest, "pid="); pid = substr(rest, j + 4); sub(/[^0-9].*/, "", pid)
      split_addr($5, l); split_addr($6, p)
      print l["p"] "|" p["a"] "|" p["p"] "\t" name "[" pid "]" }'
}

pick_source() {
  if [ -z "$SOURCE" ]; then
    if [ -r /proc/net/nf_conntrack ] || { command -v conntrack > /dev/null && conntrack -L > /dev/null 2>&1; }; then
      SOURCE=conntrack
    elif command -v tcpdump > /dev/null; then SOURCE=tcpdump
    else SOURCE=ss; fi
  fi
  case "$SOURCE" in
    conntrack) log "Source: kernel connection table (complete)" ;;
    tcpdump)   start_tcpdump || { log "tcpdump failed to start - falling back to ss"; SOURCE=ss; }
               [ "$SOURCE" = tcpdump ] && log "Source: tcpdump (TCP and ping; UDP not seen). Installing conntrack (conntrack-tools) would add UDP." ;;
    ss)        log "Source: ss polling every ${INTERVAL}s - short connections can be missed. Install tcpdump or conntrack for full coverage." ;;
    *) usage ;;
  esac
}

# Append connections not seen before to EVENTS; remember keys for 5 minutes
record() {
  local now="$1"
  case "$SOURCE" in
    conntrack) snap_conntrack "$now" ;;
    tcpdump)   snap_tcpdump ;;
    ss)        snap_ss "$now" ;;
  esac > "$TMP/snap"
  procmap > "$TMP/procs"
  awk -F'\t' -v now="$now" -v seen_out="$TMP/seen.new" -v ev="$EVENTS" '
    FILENAME == ARGV[1] { if (now - $2 < 300) seen[$1] = $2; next }
    FILENAME == ARGV[2] { proc[$1] = $2; next }
    { key = $2 " " $3 " " $4 " " $5 " " $6
      if (!(key in seen)) {
        p = proc[$4 "|" $5 "|" $6]; if (p == "") p = "-"
        print $1 "\t" $2 "\t" $5 "\t" $6 "\t" p >> ev
      }
      seen[key] = now }
    END { for (k in seen) print k "\t" seen[k] > seen_out }' "$SEEN" "$TMP/procs" "$TMP/snap"
  mv "$TMP/seen.new" "$SEEN" 2>/dev/null || : > "$SEEN"
}

# ------------------------------------------------------------------ analysis
# Prints: verdict \t regular% \t gap \t hits \t proto \t dst \t dport \t scope \t programs \t last name[pid]
analyze() {
  local now; now=$(date +%s)
  awk -F'\t' -v now="$now" -v win="$WINDOW" -v minhits="$MIN_HITS" -v mingap="$MIN_GAP" \
      -v poll="$INTERVAL" -v tolf="$TOLERANCE" -v regmin="$REGULAR" \
      -v allow="${ALLOW[*]}" -v inside="$INSIDE" '
    function ip2n(ip,   a) { if (split(ip, a, ".") != 4) return -1; return ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4] }
    function scope(ip,   i, c, n, b, size) {
      n = ip2n(ip); if (n < 0) return "ipv6"
      for (i = 1; i <= nin; i++) {
        split(cidr[i], c, "/"); b = ip2n(c[1]); size = 2 ^ (32 - (c[2] == "" ? 32 : c[2]))
        if (int(n / size) == int(b / size)) return "team"
      }
      if (ip ~ /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)/) return "private"
      return "EXTERNAL" }
    function allowed(ip, port,   i) {
      for (i = 1; i <= nal; i++) if (al[i] == ":" port || al[i] == ip || al[i] == ip ":" port) return 1
      return 0 }
    function addname(list, p) { sub(/\[[0-9]*\]$/, "", p); if (index("," list ",", "," p ",")) return list; return list == "" ? p : list "," p }
    BEGIN { nin = split(inside, cidr, " "); nal = split(allow, al, " ") }
    $1 < now - win || allowed($3, $4) { next }
    { key = $2 "\t" $3 "\t" $4
      if ($5 != "-") { names[key] = addname(names[key], $5); lastp[key] = $5 }
      # connections within 2 polls of the previous one are one burst
      if ((key in last) && $1 - last[key] <= 2 * poll) next
      n[key]++; t[key, n[key]] = $1; last[key] = $1 }
    END {
      for (key in n) {
        if (n[key] < minhits) continue
        m = 0; for (i = 2; i <= n[key]; i++) g[++m] = t[key, i] - t[key, i - 1]
        for (i = 2; i <= m; i++) { v = g[i]; j = i - 1; while (j >= 1 && g[j] > v) { g[j + 1] = g[j]; j-- } g[j + 1] = v }
        med = (m % 2) ? g[(m + 1) / 2] : (g[m / 2] + g[m / 2 + 1]) / 2
        if (med < mingap) continue
        tol = med * tolf; if (tol < 2 * poll) tol = 2 * poll
        ok = 0; for (i = 1; i <= m; i++) if (g[i] >= med - tol && g[i] <= med + tol) ok++
        reg = ok / m
        if (reg < 0.5) continue
        split(key, k, "\t")
        printf "%s\t%d%%\t%ds\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n", (reg >= regmin ? "BEACON" : "maybe"), reg * 100, med,
               n[key], k[1], k[2], k[3], scope(k[2]), (names[key] == "" ? "unknown" : names[key]), (key in lastp ? lastp[key] : "-")
      }
    }' "$EVENTS" | sort -t$'\t' -k1,1 -k2,2nr
}

exe_of() {   # "name[pid]" -> "name[pid] /path/to/exe" while the process is still running
  local pid="${1##*[}"; pid="${pid%]}"
  if [[ "$pid" =~ ^[0-9]+$ ]] && [ -e "/proc/$pid/exe" ]; then echo "$1 $(readlink "/proc/$pid/exe")"
  else echo "$1"; fi
}

# ------------------------------------------------------------------ commands
case "$CMD" in
  report)
    {
      printf 'VERDICT\tREGULAR\tEVERY\tHITS\tPROTO\tDESTINATION\tPORT\tSCOPE\tPROGRAMS\tLAST\n'
      analyze
    } | column -t -s$'\t'
    echo
    echo "Recorded since: $(head -1 "$EVENTS" | cut -f1 | xargs -r -I{} date -d @{} '+%H:%M:%S' 2>/dev/null || echo never)," \
         "$(wc -l < "$EVENTS") connections. Allowed (ignored): ${ALLOW[*]}"
    ;;

  watch)
    pick_source
    log "Watching outbound connections every ${INTERVAL}s; beacon = ${MIN_HITS}+ connections, gap ${MIN_GAP}s+, 80% within 25% of the typical gap"
    declare -A ALERTED=()
    last_analyze=$(date +%s); last_prune=$last_analyze
    while true; do
      now=$(date +%s)
      record "$now"
      if [ $((now - last_analyze)) -ge 60 ]; then
        last_analyze=$now
        while IFS=$'\t' read -r verdict reg gap hits proto dst port scope names lastp; do
          [ "$verdict" = BEACON ] || continue
          key="$proto $dst $port"
          [ -n "${ALERTED[$key]:-}" ] && continue
          ALERTED[$key]=1
          log "BEACON: $dst:$port/$proto ($scope) every ~$gap, $hits connections, $reg regular - program: $names (last: $(exe_of "$lastp"))"
          log "  Check: ss -tunap | grep '$dst'   (then ls -l /proc/<pid>/exe, the IR checklist, and block $dst on the Palo Alto if it's not ours)"
        done < <(analyze)
      fi
      if [ $((now - last_prune)) -ge 600 ]; then
        last_prune=$now
        awk -F'\t' -v cut=$((now - WINDOW)) '$1 >= cut' "$EVENTS" > "$TMP/ev" && cat "$TMP/ev" > "$EVENTS"
      fi
      if [ "$SOURCE" = tcpdump ] && ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        log "tcpdump stopped - restarting it"
        start_tcpdump || { log "tcpdump won't start - switching to ss"; SOURCE=ss; }
      fi
      sleep "$INTERVAL"
    done
    ;;
esac
