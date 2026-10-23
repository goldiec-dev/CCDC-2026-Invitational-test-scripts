#!/bin/bash
# Firewall for the VyOS 1.4 router and the Kali workstation behind it, from ccdc.conf.
# They are NOT behind the Palo Alto, so the router protects both itself and Kali.
#
# Usage: bash vyos/vyos_fw.sh [--apply [--timeout SEC]] [--ssh-scored] [--dhcp] [--undo]
#   (no option)     print the VyOS commands (to read, or to type in configure mode)
#   --apply         on the router itself (VM console, logged in as vyos): save the current
#                   config, apply and commit, then roll back automatically unless you type
#                   "yes" within --timeout seconds (default 300) - also if the console drops
#   --ssh-scored    keep SSH on the router, open to everyone (only if Quotient shows an SSH
#                   check on the router). Default: SSH service removed - we use the console
#   --dhcp          also accept DHCP on the router (only if it serves DHCP to Kali:
#                   show configuration commands | match dhcp-server)
#   --undo          print the commands that remove all of this again
#
# What it does:
#   input   (to the router itself): ping from anywhere (rule: keep ICMP up), DNS from Kali,
#           BGP/OSPF from the core link only, everything else dropped and logged
#   forward (through the router): the LAN is left to the Palo Alto (default accept). Kali gets
#           nothing new inbound except ping; outbound only DNS, NTP, web, and our own servers
#   global  established/related accepted, no source routing / redirects, SYN cookies on

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CONF="$HERE/../ccdc.conf"
APPLY=0; TIMEOUT=300; SSH_SCORED_RTR=0; DHCP=0; UNDO=0
while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1 ;;
    --timeout) TIMEOUT="$2"; shift ;;
    --ssh-scored) SSH_SCORED_RTR=1 ;;
    --dhcp) DHCP=1 ;;
    --undo) UNDO=1 ;;
    *) sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
  esac
  shift
done
sed -i 's/\r$//' "$CONF" 2>/dev/null   # files copied through Windows get CRLF line endings
# shellcheck source=../ccdc.conf
. "$CONF"

undo_commands() {
  cat <<'EOF'
delete firewall ipv4 input filter
delete firewall ipv4 forward filter
delete firewall group network-group CCDC-OURS
delete firewall group network-group CCDC-TEAM
delete firewall global-options state-policy
EOF
}

commands() {
  team_oct="$(echo "${EXTERNAL:-}" | cut -d. -f3)"
  [[ "$team_oct" =~ ^[0-9]+$ ]] || { echo "ccdc.conf: set EXTERNAL to the team's public range (172.25.<20+team>.0/24)" >&2; return 1; }
  : "${INSIDE:?ccdc.conf: INSIDE is empty}" "${KALI_NET:?ccdc.conf: KALI_NET is empty}"
  local PUBLIC="172.25.$team_oct.0/24" CORE="172.31.$team_oct.0/29"
  local TRANSIT; TRANSIT="$(echo "${VYOS_INSIDE:-172.16.0.254}" | cut -d. -f1-3).0/24"
  cat <<EOF
# ---- CCDC VyOS firewall - team public range $PUBLIC
# Our own networks: the LAN, its public range (the Palo Alto may NAT LAN traffic to it), transit, Kali
set firewall group network-group CCDC-OURS network '$INSIDE'
set firewall group network-group CCDC-OURS network '$PUBLIC'
set firewall group network-group CCDC-OURS network '$TRANSIT'
set firewall group network-group CCDC-OURS network '$KALI_NET'
# Where Kali may go besides the internet basics: our servers (the Palo Alto filters them further)
set firewall group network-group CCDC-TEAM network '$INSIDE'
set firewall group network-group CCDC-TEAM network '$PUBLIC'
# Replies to connections that are already allowed - every chain
set firewall global-options state-policy established action 'accept'
set firewall global-options state-policy related action 'accept'
set firewall global-options all-ping 'enable'
set firewall global-options broadcast-ping 'disable'
set firewall global-options ip-src-route 'disable'
set firewall global-options receive-redirects 'disable'
set firewall global-options send-redirects 'disable'
set firewall global-options syn-cookies 'enable'
set firewall global-options log-martians 'enable'
# ---- input: traffic TO the router
set firewall ipv4 input filter default-action 'drop'
set firewall ipv4 input filter default-log
set firewall ipv4 input filter rule 10 action 'accept'
set firewall ipv4 input filter rule 10 protocol 'icmp'
set firewall ipv4 input filter rule 10 description 'CCDC ping - rule: keep ICMP up'
EOF
  if [ "$SSH_SCORED_RTR" -eq 1 ]; then
    cat <<'EOF'
set firewall ipv4 input filter rule 20 action 'accept'
set firewall ipv4 input filter rule 20 protocol 'tcp'
set firewall ipv4 input filter rule 20 destination port '22'
set firewall ipv4 input filter rule 20 description 'CCDC SSH from anywhere (scored)'
EOF
  else
    echo "# We manage the router from its console: no SSH service at all"
    echo "delete service ssh"
  fi
  cat <<EOF
set firewall ipv4 input filter rule 30 action 'accept'
set firewall ipv4 input filter rule 30 protocol 'tcp_udp'
set firewall ipv4 input filter rule 30 destination port '53'
set firewall ipv4 input filter rule 30 source address '$KALI_NET'
set firewall ipv4 input filter rule 30 description 'CCDC DNS forwarding for Kali'
set firewall ipv4 input filter rule 40 action 'accept'
set firewall ipv4 input filter rule 40 protocol 'tcp'
set firewall ipv4 input filter rule 40 destination port '179'
set firewall ipv4 input filter rule 40 source address '$CORE'
set firewall ipv4 input filter rule 40 description 'CCDC BGP from the core link, if used'
set firewall ipv4 input filter rule 41 action 'accept'
set firewall ipv4 input filter rule 41 protocol 'ospf'
set firewall ipv4 input filter rule 41 description 'CCDC OSPF, if used'
EOF
  if [ "$DHCP" -eq 1 ]; then
    cat <<'EOF'
set firewall ipv4 input filter rule 50 action 'accept'
set firewall ipv4 input filter rule 50 protocol 'udp'
set firewall ipv4 input filter rule 50 destination port '67'
set firewall ipv4 input filter rule 50 description 'CCDC DHCP server for Kali'
EOF
  fi
  cat <<EOF
# ---- forward: traffic THROUGH the router. The LAN is the Palo Alto's job (default accept);
# only Kali's segment is filtered here.
set firewall ipv4 forward filter default-action 'accept'
set firewall ipv4 forward filter rule 100 action 'accept'
set firewall ipv4 forward filter rule 100 destination address '$KALI_NET'
set firewall ipv4 forward filter rule 100 protocol 'icmp'
set firewall ipv4 forward filter rule 100 description 'CCDC ping to Kali'
set firewall ipv4 forward filter rule 110 action 'drop'
set firewall ipv4 forward filter rule 110 destination address '$KALI_NET'
set firewall ipv4 forward filter rule 110 log
set firewall ipv4 forward filter rule 110 description 'CCDC nothing new in to Kali'
set firewall ipv4 forward filter rule 200 action 'accept'
set firewall ipv4 forward filter rule 200 source address '$KALI_NET'
set firewall ipv4 forward filter rule 200 protocol 'icmp'
set firewall ipv4 forward filter rule 210 action 'accept'
set firewall ipv4 forward filter rule 210 source address '$KALI_NET'
set firewall ipv4 forward filter rule 210 protocol 'tcp_udp'
set firewall ipv4 forward filter rule 210 destination port '53'
set firewall ipv4 forward filter rule 210 description 'CCDC Kali DNS'
set firewall ipv4 forward filter rule 220 action 'accept'
set firewall ipv4 forward filter rule 220 source address '$KALI_NET'
set firewall ipv4 forward filter rule 220 protocol 'udp'
set firewall ipv4 forward filter rule 220 destination port '123'
set firewall ipv4 forward filter rule 220 description 'CCDC Kali NTP'
set firewall ipv4 forward filter rule 230 action 'accept'
set firewall ipv4 forward filter rule 230 source address '$KALI_NET'
set firewall ipv4 forward filter rule 230 protocol 'tcp'
set firewall ipv4 forward filter rule 230 destination port '80,443'
set firewall ipv4 forward filter rule 230 description 'CCDC Kali web, updates'
set firewall ipv4 forward filter rule 240 action 'accept'
set firewall ipv4 forward filter rule 240 source address '$KALI_NET'
set firewall ipv4 forward filter rule 240 destination group network-group 'CCDC-TEAM'
set firewall ipv4 forward filter rule 240 description 'CCDC Kali to our servers (Palo Alto filters further)'
set firewall ipv4 forward filter rule 290 action 'drop'
set firewall ipv4 forward filter rule 290 source address '$KALI_NET'
set firewall ipv4 forward filter rule 290 log
set firewall ipv4 forward filter rule 290 description 'CCDC Kali anything else out (reverse shells, C2)'
EOF
}

if [ "$UNDO" -eq 1 ] && [ "$APPLY" -eq 0 ]; then
  echo "# Removes the CCDC router firewall (or: load /config/ccdc-orig.boot, commit). Then commit-confirm 5, confirm, save."
  undo_commands
  exit 0
fi
if [ "$APPLY" -eq 0 ]; then
  commands || exit 1
  cat <<'EOF'
# Typing these by hand: configure ; (lines above) ; compare ; commit-confirm 5 ; test ; confirm ; save
# Easier on the router console: bash vyos/vyos_fw.sh --apply   (same rules, automatic rollback)
EOF
  exit 0
fi

# ------------------------------------------------------------------ --apply (on the router)
TEMPLATE="${VYOS_TEMPLATE:-/opt/vyatta/etc/functions/script-template}"   # override only for testing
[ -f "$TEMPLATE" ] || { echo "--apply runs on the VyOS router itself (no $TEMPLATE here)"; exit 1; }
[ "$(id -u)" -ne 0 ] || { echo "Run --apply as the vyos user, not root"; exit 1; }
[[ "$TIMEOUT" =~ ^[0-9]+$ ]] || { echo "Bad --timeout"; exit 1; }
CMDS="$(if [ "$UNDO" -eq 1 ]; then undo_commands; else commands; fi)" || exit 1
STAMP="$(date +%Y%m%d-%H%M%S)"
BEFORE="/config/ccdc-before-fw-$STAMP.boot"
W="/tmp/ccdc-vyos-$STAMP"; mkdir -p "$W"

# vbash script: save the running config, apply each line (report the ones VyOS rejects), commit
{
  echo "#!/bin/vbash"
  echo "source $TEMPLATE"
  echo "configure"
  echo "save $BEFORE > /dev/null || { echo 'could not save $BEFORE - not changing anything'; exit 1; }"
  grep -vE '^[[:space:]]*(#|$)' <<< "$CMDS" | while IFS= read -r line; do
    if [[ "$line" == delete* ]]; then printf '%s > /dev/null 2>&1\n' "$line"   # fine if it wasn't there
    else printf '%s > /dev/null 2>&1 || echo %q\n' "$line" "NOT APPLIED: $line"; fi
  done
  echo "commit || { echo 'COMMIT FAILED (or nothing to change) - running config unchanged'; exit 1; }"
  echo "exit"
} > "$W/apply.sh"
printf '#!/bin/vbash\nsource %s\nconfigure\nload %s\ncommit\nexit\n' "$TEMPLATE" "$BEFORE" > "$W/rollback.sh"
printf '#!/bin/vbash\nsource %s\nconfigure\nsave\nexit\n' "$TEMPLATE" > "$W/save.sh"

echo "Saving the current config to $BEFORE and applying $(grep -cvE '^[[:space:]]*(#|$)' <<< "$CMDS") commands..."
OUT="$(vbash "$W/apply.sh" 2>&1)"; RC=$?
grep -E 'NOT APPLIED|FAILED|Error|error' <<< "$OUT"
if [ "$RC" -ne 0 ] || grep -q 'COMMIT FAILED\|could not save' <<< "$OUT"; then
  echo "Nothing was committed. Full output: $W/apply.out"; echo "$OUT" > "$W/apply.out"; exit 1
fi
echo "$OUT" > "$W/apply.out"
grep -q 'NOT APPLIED' <<< "$OUT" && echo "^ VyOS rejected those lines (different syntax in this version?) - the rest is committed."

# Rollback timer, detached so a dropped console still rolls back
setsid bash -c "sleep $TIMEOUT; vbash '$W/rollback.sh' > '$W/rollback.out' 2>&1; echo 'vyos_fw.sh: not confirmed - firewall rolled back' | wall" \
  > /dev/null 2>&1 < /dev/null &
TIMER=$!
cat <<EOF

Committed (NOT saved yet). Test now:
  - from the LAN: ping 172.16.0.254 ; from Kali: ping 8.8.8.8, curl -I https://github.com, nslookup github.com
  - Quotient: every service still up?
  - dropped packets: show log firewall   (or: sudo journalctl -k | grep -i ipv4-)
EOF
if read -r -t "$TIMEOUT" -p "Type 'yes' within $TIMEOUT s to keep and save it: " ans && [ "$ans" = yes ]; then
  kill "$TIMER" 2>/dev/null; pkill -f "sleep $TIMEOUT" 2>/dev/null
  vbash "$W/save.sh" > "$W/save.out" 2>&1 && echo "Kept and saved (survives a reboot). Before: $BEFORE" ||
    echo "Kept but SAVE FAILED - run: configure ; save ; exit"
  exit 0
fi
echo
kill "$TIMER" 2>/dev/null; pkill -f "sleep $TIMEOUT" 2>/dev/null
echo "Not confirmed - rolling back to $BEFORE..."
vbash "$W/rollback.sh" > "$W/rollback.out" 2>&1 && echo "Rolled back." || echo "ROLLBACK FAILED - run: configure ; load $BEFORE ; commit ; exit"
exit 3
