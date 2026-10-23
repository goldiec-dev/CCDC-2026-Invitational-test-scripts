#!/bin/bash
# Outbound SSH detector: flags SSH connections FROM this box to somewhere else -
# attackers use them to pivot, tunnel and move data out.
#
# Usage: outbound_ssh.sh [--watch SEC] [--allow ENTRY]... [--ports LIST] [--quiet]
#   (no option)      check once, print and log new findings (good for cron)
#   --watch SEC      keep checking every SEC seconds (deploy.sh runs this as ccdc-outbound-ssh)
#   --allow ENTRY    expected destination: IP, CIDR, IP:PORT or CIDR:PORT (repeatable)
#   --ports LIST     remote ports treated as SSH, comma-separated (default 22)
#   --quiet          only log to syslog, print nothing
#   --no-state       print every live finding and don't log or remember (for reports)
#   --config FILE    default ../ccdc.conf (SSH_ALLOW, SSH_DEFAULT_PORTS)
#
# A live connection is flagged when
#   - its remote port is one of the SSH ports, or
#   - the process is an SSH client (ssh, autossh, dbclient, plink, sshpass) - this
#     catches SSH on non-standard ports,
# and it doesn't match an allow entry. Inbound sessions to our own sshd are not flagged.
# Each live connection is logged to syslog ONCE (tag ccdc-outbound-ssh, priority warning);
# a small state file stops repeats and forgets connections that have closed.
# Exit code: 1 if any outbound SSH connection is live, 0 if none.

set -u
WATCH=0
QUIET=0
NOSTATE=0
ALLOW=()
PORTS=""
CONFIG="$(dirname "$0")/../ccdc.conf"
STATE=/run/ccdc-outbound-ssh.state
CLIENTS="ssh autossh dbclient plink sshpass"

usage() { sed -n '2,23p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --watch)  WATCH="$2"; shift 2 ;;
    --allow)  ALLOW+=("$2"); shift 2 ;;
    --ports)  PORTS="$2"; shift 2 ;;
    --quiet)  QUIET=1; shift ;;
    --no-state) NOSTATE=1; shift ;;
    --config) CONFIG="$2"; shift 2 ;;
    --state)  STATE="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[ "$(id -u)" -eq 0 ] || echo "WARN: not root - processes of other users won't be visible" >&2

SSH_ALLOW=(); SSH_DEFAULT_PORTS=22
# shellcheck source=../ccdc.conf
[ -f "$CONFIG" ] && . "$CONFIG"
PORTS="${PORTS:-$SSH_DEFAULT_PORTS}"
ALLOW+=("${SSH_ALLOW[@]}")

# One line per flagged live connection:
#   key \t reason \t local \t remote \t process \t pid
scan() {
  ss -Htnp state established 2>/dev/null | awk \
    -v ports="$PORTS" -v clients="$CLIENTS" -v allow="${ALLOW[*]}" -v listen="$(ss -Htln 2>/dev/null | awk '{ n = split($4, a, ":"); print a[n] }' | sort -u | tr '\n' ' ')" '
    function split_addr(x, r,   k) { k = 0; while (match(substr(x, k + 1), /:/)) k += RSTART
      r["a"] = substr(x, 1, k - 1); r["p"] = substr(x, k + 1)
      gsub(/^\[|\]$/, "", r["a"]); sub(/%.*/, "", r["a"]); sub(/^::ffff:/, "", r["a"]) }
    function ip2n(ip,   a) { if (split(ip, a, ".") != 4) return -1; return ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4] }
    function in_cidr(ip, c,   p, n, b, size) {
      if (index(c, "/") == 0) return ip == c
      split(c, p, "/"); n = ip2n(ip); b = ip2n(p[1]); if (n < 0 || b < 0) return 0
      size = 2 ^ (32 - p[2]); return int(n / size) == int(b / size) }
    function allowed(ip, port,   i, e, k, net, prt) {
      for (i = 1; i <= nal; i++) {
        e = al[i]; prt = ""
        # IP:PORT or CIDR:PORT (one colon = port suffix; IPv6 entries have several colons)
        if (gsub(/:/, ":", e) == 1) { k = index(e, ":"); net = substr(e, 1, k - 1); prt = substr(e, k + 1) } else net = e
        if (in_cidr(ip, net) && (prt == "" || prt == port)) return 1
      }
      return 0 }
    BEGIN { np = split(ports, P, /[ ,]+/); for (i = 1; i <= np; i++) sshp[P[i]] = 1
            nc = split(clients, C, " "); for (i = 1; i <= nc; i++) cli[C[i]] = 1
            nl = split(listen, L, " "); for (i = 1; i <= nl; i++) lp[L[i]] = 1
            nal = split(allow, al, " ") }
    { split_addr($3, l); split_addr($4, r)
      proc = "-"; pid = "-"
      i = index($0, "users:((\"")
      if (i) { rest = substr($0, i + 9); proc = substr(rest, 1, index(rest, "\"") - 1)
               j = index(rest, "pid="); pid = substr(rest, j + 4); sub(/[^0-9].*/, "", pid) }
      if (proc == "sshd" || (l["p"] in lp)) next      # inbound session to our server
      reason = ""
      if (r["p"] in sshp) reason = "remote port " r["p"]
      if (proc in cli)    reason = (reason == "" ? "" : reason ", ") "ssh client process"
      if (reason == "" || allowed(r["a"], r["p"])) next
      print l["a"] ":" l["p"] ">" r["a"] ":" r["p"] ">" pid "\t" reason "\t" l["a"] ":" l["p"] "\t" r["a"] ":" r["p"] "\t" proc "\t" pid }'
}

check() {
  local now found=0 key reason local remote proc pid user exe cmd msg
  now="$(scan)"
  [ "$NOSTATE" -eq 1 ] || touch "$STATE"
  while IFS=$'\t' read -r key reason local remote proc pid; do
    [ -n "$key" ] || continue
    found=1
    [ "$NOSTATE" -eq 0 ] && grep -qxF "$key" "$STATE" && continue
    user="-"; exe="-"; cmd="-"
    if [[ "$pid" =~ ^[0-9]+$ ]]; then
      user="$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')"
      exe="$(readlink "/proc/$pid/exe" 2>/dev/null || echo -)"
      cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c1-200)"
    fi
    msg="OUTBOUND SSH time=$(date -Is) host=$(hostname) user=${user:--} pid=$pid process=$proc exe=$exe local=$local remote=$remote reason=\"$reason\" cmd=\"${cmd:--}\""
    [ "$NOSTATE" -eq 1 ] || logger -t ccdc-outbound-ssh -p auth.warning "$msg" 2>/dev/null
    [ "$QUIET" -eq 1 ] || echo "$msg"
  done <<< "$now"
  # Remember only live connections, so a new connection later is reported again
  [ "$NOSTATE" -eq 1 ] || { printf '%s\n' "$now" | cut -f1 | sed '/^$/d' > "$STATE.new" && mv "$STATE.new" "$STATE"; }
  if [ "$found" -eq 0 ] && [ "$QUIET" -eq 0 ] && [ "$WATCH" = 0 ]; then echo "No outbound SSH connections."; fi
  return "$found"
}

if [ "$WATCH" = 0 ]; then
  check; exit $?
fi
logger -t ccdc-outbound-ssh "Watching for outbound SSH every ${WATCH}s (ports $PORTS; allowed: ${ALLOW[*]:-none})" 2>/dev/null
[ "$QUIET" -eq 1 ] || echo "Watching for outbound SSH every ${WATCH}s (ports $PORTS; allowed: ${ALLOW[*]:-none})"
while true; do check; sleep "$WATCH"; done
