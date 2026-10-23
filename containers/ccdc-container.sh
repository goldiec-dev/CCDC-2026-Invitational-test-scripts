#!/bin/bash
# Containerize a scored service ON ITS OWN BOX, inside the competition rules.
#
# Usage: sudo containers/ccdc-container.sh COMMAND [SERVICE] [options]
#   list                 the services, and whether this box can run each one
#   plan SERVICE         what build/switch would do (packages, image, mounts, run command) - changes nothing
#   build SERVICE        build the image from THIS box's repositories and installed packages
#   switch SERVICE       host service -> container: test the host service, check a fresh backup, stop the
#                        host service, start the container, test again; any failure = automatic rollback
#   rollback SERVICE     container -> the original host service
#   status               the ccdc-* containers and their health
#   Options: --mount PATH[:ro]   (switch/plan) an extra folder or file to mount (e.g. a second web root)
#            --yes               don't ask (still refuses unsafe switches)
#   SERVICE: ecom-web | ecom-db | mail | webmail | splunk | ftp
#
# How it stays inside the rules (see checklists/Docker_instructions.md):
#   same VM      - built and run here, from this box's own repos (same software versions)
#   same IP/DNS  - host networking: the box's own address, ports and hostname; nothing else changes
#   same data    - the host's code, config, data, mailboxes and user database are bind-mounted at the
#                  same paths - nothing is copied, nothing moves, rollback is instant
#   same users   - /etc/passwd etc. (and SSSD for AD users) are the host's
# Engine: Podman on Rocky/RHEL, Docker (docker.io) on Ubuntu/Debian - installed after asking.
# Logs: /root/ccdc/containers/. Workstations may not be re-tasked: servers only.

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
CMD="${1:-}"; [ $# -gt 0 ] && shift
SVC=""
case "$CMD" in plan|build|switch|rollback) SVC="${1:-}"; [ $# -gt 0 ] && shift ;; esac
EXTRA_MOUNTS=(); YES=0
CONFIG="$HERE/../ccdc.conf"
usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --mount)  EXTRA_MOUNTS+=("$2"); shift 2 ;;
    --yes)    YES=1; shift ;;
    --config) CONFIG="$2"; shift 2 ;;
    *) usage ;;
  esac
done
case "$CMD" in list|plan|build|switch|rollback|status) ;; *) usage ;; esac
[ "$CMD" = list ] || [ "$CMD" = status ] || [ -n "$SVC" ] || usage
[ "$CMD" = plan ] || [ "$CMD" = list ] || [ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)"; exit 1; }

INSIDE=""; EXTERNAL=""; WEB_CHECK_PATHS=(/); CCDC_ROLE="${CCDC_ROLE:-}"
# shellcheck source=../ccdc.conf
[ -f "$CONFIG" ] && . "$CONFIG"

OUT=/root/ccdc/containers
if [ "$(id -u)" -eq 0 ]; then umask 077; mkdir -p "$OUT"; chmod 700 "$OUT"; fi

if [ -t 1 ]; then R=$'\e[31m'; Y=$'\e[33m'; G=$'\e[32m'; B=$'\e[1m'; N=$'\e[0m'; else R=; Y=; G=; B=; N=; fi
ok()   { echo "${G}[OK]${N}   $*"; }
warn() { echo "${Y}[WARN]${N} $*"; }
fail() { echo "${R}[FAIL]${N} $*"; }
ask()  { [ "$YES" -eq 1 ] && return 0; local a; read -r -p "$1 [y/N] " a < /dev/tty || return 1; [[ "$a" =~ ^[Yy] ]]; }

# ------------------------------------------------------------------ this box
FAMILY=""
if command -v rpm > /dev/null && [ -f /etc/redhat-release ]; then FAMILY=rpm
elif command -v dpkg-query > /dev/null; then FAMILY=deb; fi
. /etc/os-release 2>/dev/null
base_image() {
  case "${ID:-}" in
    rocky)     echo "docker.io/rockylinux/rockylinux:${VERSION_ID%%.*}" ;;
    almalinux) echo "docker.io/library/almalinux:${VERSION_ID%%.*}" ;;
    ol)        echo "docker.io/library/oraclelinux:${VERSION_ID%%.*}" ;;
    centos)    echo "quay.io/centos/centos:stream${VERSION_ID%%.*}" ;;
    fedora)    echo "docker.io/library/fedora:${VERSION_ID}" ;;
    ubuntu)    echo "docker.io/library/ubuntu:${VERSION_ID}" ;;
    debian)    echo "docker.io/library/debian:${VERSION_ID}" ;;
    *)         echo "" ;;
  esac
}
installed_pkgs() {
  case "$FAMILY" in
    rpm) rpm -qa --qf '%{NAME}\n' ;;
    deb) dpkg-query -W -f '${db:Status-Abbrev} ${Package}\n' 2>/dev/null | awk '$1 ~ /^ii/ { print $2 }' ;;
  esac | sort -u
}
ENGINE="$(command -v podman || command -v docker || true)"

load_service() {
  local d="$HERE/services/$SVC"
  [ -f "$d/service.conf" ] || { fail "unknown service '$SVC' (list: $(ls "$HERE/services" | tr '\n' ' '))"; exit 1; }
  DESC=""; FAMILIES=""; REQUIRE=""; REQUIRE_PATH=""; PKG_PATTERNS=""; MODULE_NAMES=""; HOST_UNITS=""
  NO_NEW_PRIVS=yes; STOP_TIMEOUT=30; WAIT=60; MOUNTS=(); TESTS=(); EXTRA_PKGS_rpm=""; EXTRA_PKGS_deb=""
  unset -f hook_preflight hook_after_rollback 2>/dev/null
  # shellcheck source=/dev/null
  . "$d/service.conf"
  SDIR="$d"
  NAME="ccdc-$SVC"
  IMAGE="localhost/ccdc-$SVC:current"
}

# Packages of this service installed on the host (the image gets the same ones)
service_pkgs() {
  { [ -n "$PKG_PATTERNS" ] && installed_pkgs | grep -E "$PKG_PATTERNS"
    local x="EXTRA_PKGS_$FAMILY"; printf '%s\n' ${!x}; } | grep . | sort -u | tr '\n' ' '
}
module_streams() {   # enabled dnf module streams the image must enable too (e.g. php:8.1)
  [ "$FAMILY" = rpm ] && [ -n "$MODULE_NAMES" ] || return 0
  local m
  for m in $MODULE_NAMES; do
    dnf -q module list --enabled "$m" 2>/dev/null | awk -v m="$m" '$1 == m { print $1 ":" $2 }'
  done | sort -u | tr '\n' ' '
}
can_run() {   # can_run -> reason on stdout if not
  [[ " $FAMILIES " == *" $FAMILY "* ]] || { echo "needs a ${FAMILIES// / or } box, this is ${FAMILY:-unknown}"; return 1; }
  [ -z "$(base_image)" ] && { echo "no matching base image for ${ID:-this OS}"; return 1; }
  if [ -n "$REQUIRE" ] && ! installed_pkgs | grep -qE "$REQUIRE"; then echo "the service isn't installed here"; return 1; fi
  if [ -n "$REQUIRE_PATH" ] && [ ! -e "$REQUIRE_PATH" ]; then echo "$REQUIRE_PATH not found"; return 1; fi
  return 0
}

# ------------------------------------------------------------------ run arguments
run_args() {
  local m p opt restart
  if [[ "$ENGINE" == *podman ]]; then restart=always; else restart=unless-stopped; fi
  RUN=(run -d --name "$NAME" --network host --restart "$restart" --log-driver journald
       --security-opt label=disable --stop-timeout "$STOP_TIMEOUT" -v /etc/localtime:/etc/localtime:ro)
  [ "$NO_NEW_PRIVS" = yes ] && RUN+=(--security-opt no-new-privileges)
  MOUNTED=()
  for m in "${MOUNTS[@]}" "${EXTRA_MOUNTS[@]}"; do
    p="${m%%:*}"; opt=""
    [[ "$m" == *:ro ]] && opt=":ro"
    [ -e "$p" ] || continue
    RUN+=(-v "$p:$p$opt"); MOUNTED+=("$p$opt")
  done
  RUN+=("$IMAGE")
}

# ------------------------------------------------------------------ tests
ip2int() { local IFS=.; read -r a b c d <<< "$1"; echo $(( (a << 24) + (b << 16) + (c << 8) + d )); }
in_cidr() { local bits="${2#*/}" msk; msk=$(( bits == 0 ? 0 : (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
            [ $(( $(ip2int "$1") & msk )) -eq $(( $(ip2int "${2%/*}") & msk )) ]; }
WEBHOST=127.0.0.1
for a in $(ip -o -4 addr show 2>/dev/null | awk '{ split($4, x, "/"); print x[1] }'); do
  if [[ "$INSIDE" == */* ]] && in_cidr "$a" "$INSIDE"; then
    WEBHOST="$a"
    [[ "$EXTERNAL" =~ ^172\.25\.([0-9]+)\. ]] && WEBHOST="172.25.${BASH_REMATCH[1]}.${a##*.}"
    break
  fi
done
fetch() {   # fetch URL FILE -> status code; connects to 127.0.0.1 whatever the host name (vhosts see the public name)
  curl -sk --max-time 10 --connect-to "$WEBHOST:80:127.0.0.1:80" --connect-to "$WEBHOST:443:127.0.0.1:443" \
       -o "$2" -w '%{http_code}' "$1" 2>/dev/null
}
banner() { timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1 && head -n1 <&3" 2>/dev/null | tr -d '\r'; }
tcp_open() { timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null; }
same_page() {
  cmp -s "$1" "$2" && return 0
  [ "${DYNAMIC:-0}" -eq 1 ] || return 1
  local t1 t2 s1 s2
  t1="$(grep -oi '<title>[^<]*' "$1" | head -1)"; t2="$(grep -oi '<title>[^<]*' "$2" | head -1)"
  s1=$(wc -c < "$1"); s2=$(wc -c < "$2")
  [ "$t1" = "$t2" ] && [ $(( s1 * 10 )) -ge $(( s2 * 9 )) ] && [ $(( s2 * 10 )) -ge $(( s1 * 9 )) ]
}

# run_tests baseline|after: baseline records what works now; after must match it
run_tests() {
  local phase="$1" t kind port pat i p code all=0 W="$OUT/test-$SVC"
  mkdir -p "$W"
  [ "$phase" = baseline ] && { REQUIRED=(); DYNAMIC=0; }
  for t in "${TESTS[@]}"; do
    read -r kind port pat <<< "$t"
    if [ "$phase" = after ] && [[ ! " ${REQUIRED[*]} " == *" ${t// /_} "* ]]; then continue; fi
    case "$kind" in
      web)
        i=0
        for p in "${WEB_CHECK_PATHS[@]}"; do
          i=$((i + 1))
          for proto in http https; do
            code="$(fetch "$proto://$WEBHOST$p" "$W/$phase-$proto-$i")"
            if [ "$phase" = baseline ]; then
              [ "$code" = 000 ] && continue
              fetch "$proto://$WEBHOST$p" "$W/$phase-$proto-$i.b" > /dev/null
              cmp -s "$W/$phase-$proto-$i" "$W/$phase-$proto-$i.b" || DYNAMIC=1
              echo "$code" > "$W/code-$proto-$i"
              [[ " ${REQUIRED[*]} " == *" web "* ]] || REQUIRED+=("web")
            else
              [ -f "$W/code-$proto-$i" ] || continue
              if [ "$code" != "$(cat "$W/code-$proto-$i")" ] || ! same_page "$W/after-$proto-$i" "$W/baseline-$proto-$i"; then
                echo "    $proto://$WEBHOST$p: status $code (was $(cat "$W/code-$proto-$i")) or different page"; all=1
              fi
            fi
          done
        done ;;
      banner)
        local b; b="$(banner "$port")"
        if [[ "$b" =~ $pat ]]; then [ "$phase" = baseline ] && REQUIRED+=("${t// /_}")
        elif [ "$phase" = after ]; then echo "    port $port: no '$pat' banner (got: ${b:-nothing})"; all=1; fi ;;
      tcp)
        if tcp_open "$port"; then [ "$phase" = baseline ] && REQUIRED+=("${t// /_}")
        elif [ "$phase" = after ]; then echo "    port $port: not answering"; all=1; fi ;;
      http|https)
        code="$(curl -sk --max-time 10 -o /dev/null -w '%{http_code}' "$kind://127.0.0.1:$port/" 2>/dev/null)"
        if [[ "$code" =~ ^(2|3|401) ]]; then [ "$phase" = baseline ] && REQUIRED+=("${t// /_}")
        elif [ "$phase" = after ]; then echo "    $kind port $port: status $code"; all=1; fi ;;
      socket)
        local s; s="$(ls /var/lib/mysql/mysql.sock /run/mysqld/mysqld.sock /run/mariadb/mariadb.sock 2>/dev/null | head -1)"
        if [ -S "${s:-/nonexistent}" ]; then [ "$phase" = baseline ] && REQUIRED+=("${t// /_}")
        elif [ "$phase" = after ]; then echo "    MySQL socket missing"; all=1; fi ;;
    esac
  done
  if [ "$phase" = baseline ]; then
    [ ${#REQUIRED[@]} -gt 0 ] || { fail "none of the service's checks pass on the host right now - fix the service first"; return 1; }
    echo "Checks that pass now (and must pass in the container): ${REQUIRED[*]//_/ }"
    [ "$DYNAMIC" -eq 1 ] && warn "the page changes on every load - comparing title and size only"
  fi
  return "$all"
}

# ------------------------------------------------------------------ engine
ensure_engine() {
  [ -n "$ENGINE" ] && return 0
  warn "no container engine on this box"
  case "$FAMILY" in
    rpm) ask "Install Podman (from this box's repositories)?" && dnf -y install podman ;;
    deb) ask "Install Docker (docker.io, from this box's repositories)?" && apt-get install -y docker.io && systemctl enable --now docker ;;
  esac
  ENGINE="$(command -v podman || command -v docker || true)"
  [ -n "$ENGINE" ] || { fail "no container engine"; exit 1; }
}
enable_restart_at_boot() {
  if [[ "$ENGINE" == *podman ]]; then
    if systemctl cat podman-restart.service > /dev/null 2>&1; then systemctl enable podman-restart.service > /dev/null 2>&1
    else "$ENGINE" generate systemd --name "$NAME" > "/etc/systemd/system/container-$NAME.service" 2>/dev/null &&
           systemctl daemon-reload && systemctl enable "container-$NAME.service" > /dev/null 2>&1; fi
  else
    systemctl enable docker > /dev/null 2>&1
  fi
}

# ------------------------------------------------------------------ commands
do_list() {
  local d r
  echo "This box: ${PRETTY_NAME:-?} (${FAMILY:-unknown} family), engine: ${ENGINE:-none yet}"
  for d in "$HERE"/services/*/; do
    SVC="$(basename "$d")"; load_service
    if r="$(can_run)"; then printf '  %-10s %sready%s     %s\n' "$SVC" "$G" "$N" "$DESC"
    else printf '  %-10s %s-%s         %s\n' "$SVC" "$Y" "$N" "$r"; fi
  done
  echo "Windows services (AD/DNS, MSSQL) can't be containerized within the rules - they stay as they are."
}

do_plan() {
  load_service
  local r; r="$(can_run)" || { fail "$SVC can't run here: $r"; exit 1; }
  run_args
  echo "${B}$SVC${N} - $DESC"
  echo "  base image : $(base_image)  (same distribution as this box)"
  echo "  packages   : $(service_pkgs)"
  [ -n "$(module_streams)" ] && echo "  dnf modules: $(module_streams)"
  echo "  replaces   : host units $HOST_UNITS (stopped and masked; rollback restores them)"
  echo "  mounts     : ${MOUNTED[*]}"
  echo "  tests      : ${TESTS[*]}"
  echo "  run        : ${ENGINE:-<engine>} ${RUN[*]}"
}

do_build() {
  load_service
  local r; r="$(can_run)" || { fail "$SVC can't run here: $r"; exit 1; }
  ensure_engine
  local ctx="$OUT/build-$SVC" pkgs mods base
  pkgs="$(service_pkgs)"; mods="$(module_streams)"; base="$(base_image)"
  rm -rf "$ctx"; mkdir -p "$ctx/rootfs/usr/local/share"
  cp "$HERE/Containerfile.$FAMILY" "$ctx/Containerfile"
  cp "$SDIR/entrypoint.sh" "$ctx/entrypoint.sh"
  [ -d "$SDIR/rootfs" ] && cp -a "$SDIR/rootfs/." "$ctx/rootfs/"
  echo "ccdc-$SVC built $(date) on $(hostname) from: $pkgs" > "$ctx/rootfs/usr/local/share/ccdc-container"
  if [ "$FAMILY" = rpm ]; then
    mkdir -p "$ctx/repos" "$ctx/rpm-gpg" "$ctx/dnfvars"
    cp -a /etc/yum.repos.d/. "$ctx/repos/"; cp -a /etc/pki/rpm-gpg/. "$ctx/rpm-gpg/" 2>/dev/null
    [ -d /etc/dnf/vars ] && cp -a /etc/dnf/vars/. "$ctx/dnfvars/"
  else
    mkdir -p "$ctx/apt/sources.list.d" "$ctx/apt/trusted.gpg.d" "$ctx/apt/keyrings" "$ctx/apt/apt.conf.d"
    [ -f /etc/apt/sources.list ] && cp /etc/apt/sources.list "$ctx/apt/"
    cp -a /etc/apt/sources.list.d/. "$ctx/apt/sources.list.d/" 2>/dev/null
    cp -a /etc/apt/trusted.gpg.d/. "$ctx/apt/trusted.gpg.d/" 2>/dev/null
    cp -a /etc/apt/keyrings/. "$ctx/apt/keyrings/" 2>/dev/null
    cp /etc/apt/apt.conf.d/*proxy* "$ctx/apt/apt.conf.d/" 2>/dev/null
  fi
  echo "Building $IMAGE from $base with: ${pkgs:-(no packages: it runs the binaries of the host)} ${mods:+[modules: $mods]}"
  local log="$OUT/build-$SVC-$(date +%Y%m%d-%H%M%S).log"
  # host networking for the build: the host's DNS and firewall rules (DNS/HTTP/HTTPS out) apply
  if "$ENGINE" build --network host -t "$IMAGE" -t "localhost/ccdc-$SVC:$(date +%Y%m%d-%H%M)" \
       --build-arg BASE="$base" --build-arg PKGS="$pkgs" --build-arg MODULES="$mods" \
       -f "$ctx/Containerfile" "$ctx" 2>&1 | tee "$log"; [ "${PIPESTATUS[0]}" -eq 0 ]; then
    ok "built $IMAGE (log: $log)"
    echo "Next: sudo bash $0 plan $SVC   then   sudo bash $0 switch $SVC"
  else
    fail "build failed - see $log"; exit 1
  fi
}

host_units_active() { local u; for u in $HOST_UNITS; do systemctl is-active --quiet "$u" 2>/dev/null && echo "$u"; done; }

rollback_now() {
  local st="$OUT/$SVC.state" u
  "$ENGINE" stop -t "$STOP_TIMEOUT" "$NAME" > /dev/null 2>&1
  "$ENGINE" rm -f "$NAME" > /dev/null 2>&1
  rm -f "/etc/systemd/system/container-$NAME.service"
  if [ -f "$st" ]; then
    while read -r u was_enabled; do
      [ -n "$u" ] || continue
      systemctl unmask "$u" > /dev/null 2>&1
      [ "$was_enabled" = enabled ] && systemctl enable "$u" > /dev/null 2>&1
      systemctl start "$u" && ok "host service $u started again" || fail "$u didn't start - check: journalctl -u $u"
    done < "$st"
  fi
  declare -F hook_after_rollback > /dev/null && hook_after_rollback
  rm -f "$OUT/$SVC.active"
}

do_switch() {
  load_service
  local r; r="$(can_run)" || { fail "$SVC can't run here: $r"; exit 1; }
  [ -f "$OUT/$SVC.active" ] && { warn "$SVC already runs in a container (rollback: $0 rollback $SVC)"; exit 0; }
  [[ "${CCDC_ROLE:-}" == workstation ]] && { fail "workstations may not be re-tasked"; exit 1; }
  # Servers have fixed addresses in ccdc.conf; workstations are on DHCP (and may not be re-tasked)
  local me v isserver=0
  for v in ECOM WEBMAIL SPLUNK AD MSSQL WEB FTP MYSQL; do
    [ -n "${!v:-}" ] && ip -o addr show 2>/dev/null | grep -qw "${!v}" && { isserver=1; me="$v"; }
  done
  if [ "$isserver" -eq 1 ]; then echo "This box: $me (${!me})"
  else warn "this box's address isn't one of the server addresses in ccdc.conf - containers belong on servers only"
       ask "Is this really a server (not a workstation)?" || exit 1; fi
  ensure_engine
  "$ENGINE" image inspect "$IMAGE" > /dev/null 2>&1 || { fail "no image yet: sudo bash $0 build $SVC"; exit 1; }
  "$ENGINE" container inspect "$NAME" > /dev/null 2>&1 && { fail "a container named $NAME exists - remove it first ($ENGINE rm -f $NAME)"; exit 1; }
  run_args

  local units=() u
  while read -r u; do [ -n "$u" ] && units+=("$u"); done < <(host_units_active)
  [ ${#units[@]} -gt 0 ] || { fail "none of the host units ($HOST_UNITS) are running - nothing to replace"; exit 1; }
  echo "Host service now: ${units[*]}"
  echo "Testing the host service first (the container must do the same)..."
  run_tests baseline || exit 1
  if declare -F hook_preflight > /dev/null; then hook_preflight || exit 1; fi

  # A recent backup, in case a mount option or the image damages data
  local newest; newest="$(ls -1dt /root/ccdc/full-backup-* 2>/dev/null | head -1)"
  if [ -z "$newest" ] || [ -n "$(find "$newest" -maxdepth 0 -mmin +60)" ]; then
    warn "no backup from the last hour"
    if ask "Make one now with linux/backup.sh?"; then bash "$HERE/../linux/backup.sh" ${CCDC_ROLE:+--role "$CCDC_ROLE"} || exit 1
    else ask "Continue WITHOUT a fresh backup?" || exit 1; fi
  else
    ok "recent backup: $newest"
  fi
  echo "Mounts: ${MOUNTED[*]}"
  ask "Stop ${units[*]} and start the container now (downtime: seconds)?" || exit 0

  : > "$OUT/$SVC.state"
  for u in "${units[@]}"; do echo "$u $(systemctl is-enabled "$u" 2>/dev/null)" >> "$OUT/$SVC.state"; done
  trap 'echo; warn "interrupted - rolling back"; rollback_now; exit 1' INT TERM HUP
  systemctl stop "${units[@]}"
  if ! "$ENGINE" "${RUN[@]}" > "$OUT/$SVC.container-id" 2> "$OUT/$SVC.run-error"; then
    fail "the container didn't start: $(head -3 "$OUT/$SVC.run-error")"; rollback_now; exit 1
  fi
  echo "Container started - waiting up to ${WAIT}s for the same checks to pass..."
  local t=0 out=""
  while [ "$t" -lt "$WAIT" ]; do
    sleep 3; t=$((t + 3))
    if ! "$ENGINE" container inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null | grep -q true; then out="container stopped"; break; fi
    if out="$(run_tests after)"; then out=""; break; fi
  done
  if [ -n "$out" ]; then
    fail "the container doesn't pass the checks:"; echo "$out"
    echo "Container log (last lines):"; "$ENGINE" logs --tail 15 "$NAME" 2>&1 | sed 's/^/    /'
    rollback_now; trap - INT TERM HUP
    fail "rolled back - the host service runs again"; exit 1
  fi
  trap - INT TERM HUP
  for u in "${units[@]}"; do
    systemctl disable --quiet "$u" 2>/dev/null
    systemctl mask --quiet "$u" 2>/dev/null || warn "couldn't mask $u (disabled only) - never start it while the container runs"
  done
  enable_restart_at_boot
  date > "$OUT/$SVC.active"
  ok "$SVC now runs in container $NAME on this box's own address and ports - every check passed"
  cat <<EOF
  Watch Quotient for the next minutes. Back to the host service any time:  sudo bash $0 rollback $SVC
  Logs: $ENGINE logs -f $NAME   (also in the journal)      Shell inside: $ENGINE exec -it $NAME bash
EOF
  [ "$SVC" = mail ] && warn "users come from the host's /etc/passwd/shadow: after changing a local password, run: $ENGINE restart $NAME"
}

do_rollback() {
  load_service
  ensure_engine
  [ -f "$OUT/$SVC.state" ] || { fail "no record of a switch for $SVC"; exit 1; }
  ask "Stop container $NAME and start the host service again?" || exit 0
  rollback_now
  ok "rolled back - test the service (and Quotient)"
}

do_status() {
  [ -n "$ENGINE" ] || { echo "No container engine on this box."; return; }
  "$ENGINE" ps -a --filter name=ccdc- --format '{{.Names}}  {{.Status}}  {{.Image}}'
  local f
  for f in "$OUT"/*.active; do [ -f "$f" ] && echo "switched: $(basename "$f" .active) since $(cat "$f")"; done
}

case "$CMD" in
  list)     do_list ;;
  plan)     do_plan ;;
  build)    do_build ;;
  switch)   do_switch ;;
  rollback) do_rollback ;;
  status)   do_status ;;
esac
