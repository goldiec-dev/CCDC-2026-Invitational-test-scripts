#!/bin/bash
# Service inventory, legacy-service removal and update check for a Linux box.
#
# Usage: sudo ./services.sh [--fix] [--remove] [--yes] [--refresh] [--update] [--config FILE]
#   (no option)  report: what listens on the network (process, systemd unit, package,
#                version), legacy / insecure services that should go, end-of-life
#                software, and available updates for important services
#   --fix        stop, disable and mask each legacy service (asks per item)
#   --remove     with --fix: also uninstall its packages
#   --yes        with --fix / --update: don't ask (scored services are still never touched)
#   --refresh    refresh the package lists first (apt-get update / dnf makecache) - needs internet
#   --update     install the available updates for important services (asks per package,
#                keeps existing config files; kernel updates are listed, never installed here)
#
# Scoring safety: a legacy service on a port listed in EXPECTED_PORTS (ccdc.conf, per role)
# is reported as SCORED? and never stopped or removed - check the team packet first.
# Undo a --fix: systemctl unmask <unit> && systemctl enable --now <unit>
# Log: /root/ccdc/services-<time>.log. Exit: 2 legacy service found, 1 updates/warnings, 0 clean.

set -u
FIX=0; REMOVE=0; YES=0; REFRESH=0; UPDATE=0
CONFIG="$(dirname "$0")/../ccdc.conf"
usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --fix) FIX=1 ;; --remove) REMOVE=1 ;; --yes) YES=1 ;; --refresh) REFRESH=1 ;; --update) UPDATE=1 ;;
    --config) CONFIG="$2"; shift ;;
    *) usage ;;
  esac
  shift
done
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)"; exit 1; }
EXPECTED_PORTS=(); WEB_ROOTS=(/var/www)
# shellcheck source=../ccdc.conf
[ -f "$CONFIG" ] && . "$CONFIG"

umask 077; mkdir -p /root/ccdc
LOG="/root/ccdc/services-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG") 2>&1

if [ -t 1 ] || [ -t 0 ]; then R=$'\e[31m'; Y=$'\e[33m'; G=$'\e[32m'; C=$'\e[36m'; N=$'\e[0m'; else R=; Y=; G=; C=; N=; fi
CRIT=0; WARN=0
crit() { CRIT=$((CRIT + 1)); echo "${R}[LEGACY]${N} $*"; logger -t ccdc-services -p auth.warning "LEGACY: $*" 2>/dev/null; }
warn() { WARN=$((WARN + 1)); echo "${Y}[WARN]${N}   $*"; }
ok()   { echo "${G}[OK]${N}     $*"; }
info() { echo "         $*"; }
h1()   { printf '\n%s==================== %s ====================%s\n' "$C" "$1" "$N"; }
ask()  { [ "$YES" -eq 1 ] && return 0; local a; read -r -p "    $1 [y/N] " a < /dev/tty || a=""; [[ "$a" =~ ^[Yy] ]]; }

# ------------------------------------------------------------------ package manager
if command -v dpkg-query > /dev/null; then PM=apt
elif command -v rpm > /dev/null; then PM=rpm; DNF=$(command -v dnf || command -v yum)
else PM=none; fi

installed_pkgs() {
  case "$PM" in
    apt) dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 2>/dev/null | awk '$1 ~ /^ii/ { print $2 }' ;;
    rpm) rpm -qa --qf '%{NAME}\n' ;;
  esac | sort -u
}
pkg_of() {   # package owning a file
  case "$PM" in
    apt) dpkg -S "$1" 2>/dev/null | head -1 | cut -d: -f1 ;;
    rpm) rpm -qf --qf '%{NAME}\n' "$1" 2>/dev/null | head -1 | grep -v 'not owned' ;;
  esac
}
pkg_ver() {
  case "$PM" in
    apt) dpkg-query -W -f='${Version}' "$1" 2>/dev/null ;;
    rpm) rpm -q --qf '%{VERSION}-%{RELEASE}' "$1" 2>/dev/null ;;
  esac
}
PKGS="$(installed_pkgs)"
UNITS="$(systemctl list-unit-files --no-legend --plain --type=service,socket 2>/dev/null | awk '{ print $1 }')"
ENABLED="$(systemctl list-unit-files --no-legend --plain --type=service,socket --state=enabled,static,indirect,generated 2>/dev/null | awk '{ print $1 }')"
ACTIVE="$(systemctl list-units --no-legend --plain --type=service,socket --state=active 2>/dev/null | awk '{ print $1 }')"
LISTEN="$(ss -Htulpn 2>/dev/null)"
listening_on() {   # listening_on tcp/23 -> 0/1
  local proto="${1%/*}" port="${1#*/}"
  awk -v p="$proto" -v port="$port" '$1 == p { n = split($5, a, ":"); if (a[n] == port) f = 1 } END { exit !f }' <<< "$LISTEN"
}
is_expected() { local p; for p in "${EXPECTED_PORTS[@]}"; do [ "$p" = "$1" ] && return 0; done; return 1; }

echo "Service scan of $(hostname) - $(date '+%Y-%m-%d %H:%M:%S') - role ${CCDC_ROLE:-not set}"

# ------------------------------------------------------------------ 1. inventory
h1 "LISTENING SERVICES"
printf '%-5s %-28s %-16s %-26s %-24s %s\n' PROTO ADDRESS PROCESS UNIT PACKAGE VERSION
while read -r proto _ _ _ local _ procinfo; do
  [ -n "${proto:-}" ] || continue
  pid="$(sed -n 's/.*pid=\([0-9]*\).*/\1/p' <<< "$procinfo")"
  name="$(sed -n 's/.*(("\([^"]*\)".*/\1/p' <<< "$procinfo")"
  unit="-"; pkg="-"; ver="-"
  if [ -n "$pid" ]; then
    unit="$(grep -o '[^/]*\.service' "/proc/$pid/cgroup" 2>/dev/null | head -1)"
    exe="$(readlink "/proc/$pid/exe" 2>/dev/null)"
    [ -n "$exe" ] && pkg="$(pkg_of "$exe")"
    [ -n "$pkg" ] && ver="$(pkg_ver "$pkg")"
    [ -n "$exe" ] && [ -z "$pkg" ] && pkg="NOT FROM A PACKAGE ($exe)"
  fi
  port="${local##*:}"
  flag=""
  if [ ${#EXPECTED_PORTS[@]} -gt 0 ] && ! is_expected "$port" && [[ "$local" != 127.* && "$local" != "[::1]"* ]]; then flag=" <- not an expected port"; fi
  printf '%-5s %-28s %-16s %-26s %-24s %s%s\n' "$proto" "$local" "${name:--}" "${unit:--}" "${pkg:--}" "${ver:--}" "$flag"
done <<< "$LISTEN"

h1 "RUNNING SERVICES"
systemctl list-units --no-legend --plain --type=service --state=running 2>/dev/null | awk '{ printf "  %s\n", $1 }' | column -c 120

# ------------------------------------------------------------------ 2. legacy services
# id | what and why | packages | units | ports | what to do
LEGACY='telnet|Telnet server - logins and passwords in cleartext|telnetd telnetd-ssl inetutils-telnetd telnet-server|telnet.socket telnetd.service telnet@.service|tcp/23|use SSH
rsh|rsh / rlogin / rexec - cleartext, host-trust logins|rsh-server rsh-redone-server|rsh.socket rlogin.socket rexec.socket|tcp/512 tcp/513 tcp/514|use SSH
tftp|TFTP server - no authentication at all|tftpd-hpa tftpd atftpd tftp-server|tftpd-hpa.service tftp.socket tftp.service atftpd.service|udp/69|remove unless the packet lists it
inetd|inetd / xinetd super-server - starts legacy services (echo, chargen, daytime...)|xinetd openbsd-inetd inetutils-inetd|xinetd.service inetd.service openbsd-inetd.service inetutils-inetd.service||run needed services directly
nis|NIS (yp) - shares password hashes in cleartext|nis ypserv ypbind yp-tools|ypserv.service ypbind.service yppasswdd.service ypxfrd.service||use LDAP / AD
talk|talk / ntalk|talkd talk-server inetutils-talkd|talk.socket ntalk.socket|udp/517 udp/518|remove
finger|finger daemon - leaks user names and login times|fingerd finger-server efingerd cfingerd|finger.socket fingerd.service|tcp/79|remove
rpcbind|rpcbind / portmapper - only needed for NFS or NIS, a common attack surface|rpcbind portmap|rpcbind.service rpcbind.socket portmap.service|tcp/111 udp/111|remove unless NFS is used
ftp|FTP server - passwords in cleartext|vsftpd proftpd proftpd-basic proftpd-core pure-ftpd|vsftpd.service proftpd.service pure-ftpd.service|tcp/21|use SFTP; keep only if scored
snmp|SNMP agent - v1/v2c community strings are cleartext passwords|snmpd|snmpd.service|udp/161|remove, or SNMPv3 only
avahi|Avahi mDNS / zeroconf - not needed on servers|avahi-daemon|avahi-daemon.service avahi-daemon.socket|udp/5353|remove on servers
cups|CUPS printing - not needed on servers, history of remote exploits|cups cups-daemon cups-browsed|cups.service cups.socket cups-browsed.service|tcp/631 udp/631|remove on servers
vnc|VNC / X11 remote desktop - weak or no authentication|x11vnc tigervnc-server tigervnc-standalone-server vnc4server tightvncserver|x11vnc.service vncserver@.service|tcp/5900 tcp/5901 tcp/6000|remove, use SSH
rsyncd|rsync daemon - often runs without authentication||rsync.service rsyncd.service|tcp/873|disable the daemon (keep the rsync tool)
nfs|NFS server - file shares with host-based trust|nfs-kernel-server|nfs-server.service nfs-kernel-server.service|tcp/2049|remove unless shares are needed
dhcpd|DHCP server|isc-dhcp-server dhcp-server kea-dhcp4-server|isc-dhcp-server.service dhcpd.service kea-dhcp4-server.service|udp/67|remove unless this box is the DHCP server'

h1 "LEGACY AND INSECURE SERVICES"
found_any=0
while IFS='|' read -r id what pkgs units ports advice; do
  have_pkgs=(); have_units=(); live_ports=(); scored=()
  for p in $pkgs; do grep -qxF "$p" <<< "$PKGS" && have_pkgs+=("$p"); done
  for u in $units; do grep -qxF "$u" <<< "$UNITS" && have_units+=("$u"); done
  for p in $ports; do listening_on "$p" && live_ports+=("$p"); is_expected "${p#*/}" && scored+=("$p"); done
  active=""; on=""
  for u in "${have_units[@]}"; do
    grep -qxF "$u" <<< "$ACTIVE" && active+="$u "
    grep -qxF "$u" <<< "$ENABLED" && on+="$u "
  done
  # A unit file that exists but is disabled and stopped doesn't count (e.g. rsync ships one);
  # an installed legacy server package does, even if it isn't running.
  [ ${#have_pkgs[@]} -eq 0 ] && [ -z "$active$on" ] && [ ${#live_ports[@]} -eq 0 ] && continue
  found_any=1
  if [ ${#scored[@]} -gt 0 ]; then
    warn "SCORED? $what - port ${scored[*]} is in EXPECTED_PORTS. Not touching it; harden it instead ($advice)."
    continue
  fi
  crit "$what"
  info "packages: ${have_pkgs[*]:-none}   enabled: ${on:-no}   running: ${active:-no}   listening: ${live_ports[*]:-no}"
  info "-> $advice"
  [ "$FIX" -eq 1 ] || continue
  if ask "Stop, disable and mask ${have_units[*]:-its services}?"; then
    for u in "${have_units[@]}"; do
      systemctl disable --now "$u" > /dev/null 2>&1 < /dev/null; systemctl mask "$u" > /dev/null 2>&1 < /dev/null
      info "disabled and masked $u (undo: systemctl unmask $u && systemctl enable --now $u)"
    done
    for p in "${live_ports[@]}"; do listening_on "$p" && warn "still listening on $p - check: ss -tulpn | grep ':${p#*/} '"; done
  fi
  if [ "$REMOVE" -eq 1 ] && [ ${#have_pkgs[@]} -gt 0 ] && ask "Uninstall ${have_pkgs[*]}?"; then
    case "$PM" in
      apt) DEBIAN_FRONTEND=noninteractive apt-get purge -y "${have_pkgs[@]}" < /dev/null ;;
      rpm) $DNF remove -y "${have_pkgs[@]}" < /dev/null ;;
    esac && info "removed ${have_pkgs[*]}"
  fi
done <<< "$LEGACY"

# Insecure settings of services that may legitimately be needed
if grep -qxF snmpd <<< "$PKGS" && grep -qsE '^\s*(rocommunity6?|rwcommunity6?|com2sec)\b.*\b(public|private)\b' /etc/snmp/snmpd.conf; then
  crit "SNMP uses the default community string public/private (/etc/snmp/snmpd.conf)"; found_any=1
fi
if command -v testparm > /dev/null && grep -qE '(^| )smbd?\.service' <<< "$ACTIVE"; then
  minp="$(testparm -s 2>/dev/null | awk -F= 'tolower($1) ~ /server min protocol/ { gsub(/ /, "", $2); print $2 }')"
  case "${minp^^}" in
    NT1|LANMAN1|LANMAN2|CORE|COREPLUS) crit "Samba allows SMB1 (server min protocol = $minp) - set 'server min protocol = SMB2_10'"; found_any=1 ;;
    *) ok "Samba minimum protocol: ${minp:-default (SMB2 or later)}" ;;
  esac
fi
# Databases and caches reachable from the network
while read -r proto _ _ _ local _ procinfo; do
  port="${local##*:}"; addr="${local%:*}"
  case "$port" in 6379|11211|27017|9200|5432|3306) ;; *) continue ;; esac
  [[ "$addr" == 127.* || "$addr" == "[::1]" ]] && continue
  is_expected "$port" && continue
  warn "$(sed -n 's/.*(("\([^"]*\)".*/\1/p' <<< "$procinfo") listens on $local (all/external addresses) - if only this box uses it, bind it to 127.0.0.1"
done <<< "$LISTEN"
[ "$found_any" -eq 0 ] && ok "No legacy services found"

# ------------------------------------------------------------------ 3. end of life
h1 "END-OF-LIFE SOFTWARE (no more security fixes; as of October 2026)"
. /etc/os-release 2>/dev/null
os_eol=""
case "${ID:-}" in
  ubuntu) case "${VERSION_ID:-}" in 1[0-9].*|20.04) os_eol="Ubuntu $VERSION_ID (standard support ended)";; esac ;;
  debian) [ "${VERSION_ID:-99}" -le 11 ] 2>/dev/null && os_eol="Debian $VERSION_ID" ;;
  centos) case "${VERSION_ID:-}" in [5-8]*) os_eol="CentOS $VERSION_ID";; esac ;;
  rhel|ol|rocky|almalinux) [ "${VERSION_ID%%.*}" -le 7 ] 2>/dev/null && os_eol="$NAME $VERSION_ID" ;;
  fedora) [ "${VERSION_ID:-99}" -lt 43 ] 2>/dev/null && os_eol="Fedora $VERSION_ID" ;;
esac
if [ -n "$os_eol" ]; then warn "Operating system is end-of-life: $os_eol - can't be fixed mid-competition; note it in reports and keep the box tightly firewalled"
else ok "Operating system: ${PRETTY_NAME:-unknown}"; fi

vmm() { grep -oE '[0-9]+\.[0-9]+' <<< "$1" | head -1; }
older() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ] && [ "$1" != "$2" ]; }   # older A B: A < B
if command -v php > /dev/null; then
  v="$(vmm "$(php -r 'echo PHP_VERSION;' 2>/dev/null)")"
  if older "$v" 8.2; then warn "PHP $v is end-of-life (8.1 ended Dec 2025) - upgrade with care, the web app must support it"
  elif [ "$v" = 8.2 ]; then info "PHP 8.2: security support ends 31 Dec 2026"; else ok "PHP $v"; fi
fi
for b in mysqld mariadbd; do
  p="$(command -v $b || ls /usr/sbin/$b 2>/dev/null)"; [ -n "$p" ] || continue
  s="$("$p" --version 2>/dev/null)"; v="$(vmm "$s")"
  if grep -qi mariadb <<< "$s"; then older "$v" 10.11 && warn "MariaDB $v is end-of-life (10.6 ended July 2026)" || ok "MariaDB $v"
  else older "$v" 8.4 && warn "MySQL $v is end-of-life (8.0 ended April 2026)" || ok "MySQL $v"; fi
  break
done
for b in apache2 httpd; do
  command -v $b > /dev/null || continue
  v="$(vmm "$($b -v 2>/dev/null | head -1)")"; older "$v" 2.4 && warn "Apache $v is end-of-life" || ok "Apache $v"; break
done
if command -v openssl > /dev/null; then
  v="$(vmm "$(openssl version)")"; older "$v" 3.0 && warn "OpenSSL $v is end-of-life (1.1.1 ended Sep 2023)" || ok "OpenSSL $v"
fi
command -v python2 > /dev/null && warn "Python 2 is installed (end-of-life since 2020) - check nothing important uses it"

# Web applications: version only - compare with the vendor's latest release
for r in "${WEB_ROOTS[@]}"; do
  [ -d "$r" ] || continue
  while IFS= read -r f; do
    case "$f" in
      */wp-includes/version.php) v="$(sed -n "s/^\$wp_version *= *'\([^']*\)'.*/\1/p" "$f")"; app="WordPress" ;;
      */program/include/iniset.php) v="$(sed -n "s/.*RCMAIL_VERSION', *'\([^']*\)'.*/\1/p" "$f")"; app="Roundcube" ;;
      */config/settings.inc.php) v="$(sed -n "s/.*_PS_VERSION_', *'\([^']*\)'.*/\1/p" "$f")"; app="PrestaShop" ;;
      */admin/index.php) v="$(sed -n "s/.*'VERSION', *'\([^']*\)'.*/\1/p" "$f")"; app="OpenCart" ;;
      *) continue ;;
    esac
    [ -n "$v" ] && info "Web app: $app $v ($f) - compare with the vendor's latest release"
  done < <(find "$r" -maxdepth 5 \( -path '*/wp-includes/version.php' -o -path '*/program/include/iniset.php' \
           -o -path '*/config/settings.inc.php' -o -path '*/admin/index.php' \) 2>/dev/null)
done

# ------------------------------------------------------------------ 4. updates
h1 "UPDATES FOR IMPORTANT SERVICES"
# Important = packages behind listening services + core security packages
IMPORTANT_RE='^(openssh-server|openssh|openssh-client|openssh-clients|apache2|apache2-bin|httpd|nginx|nginx-core|php[0-9.]*(-[a-z0-9]+)?|libapache2-mod-php[0-9.]*|mysql-server[0-9.-]*|mysql-community-server|mariadb-server[0-9.-]*|mariadb|postfix|dovecot-.*|dovecot|bind9|bind9-.*|bind|bind-libs|samba|samba-.*|openssl|libssl[0-9.]*|sudo|polkit|libpolkit-.*|policykit-1|pkexec|glibc|libc6|linux-image-.*|kernel|kernel-core|roundcube.*|vsftpd|curl|libcurl[0-9a-z-]*|xz-utils|xz|xz-libs|systemd|bash|wazuh-agent)$'
for p in $(while read -r _ _ _ _ _ _ procinfo; do
             pid="$(sed -n 's/.*pid=\([0-9]*\).*/\1/p' <<< "$procinfo")"; [ -n "$pid" ] || continue
             e="$(readlink "/proc/$pid/exe" 2>/dev/null)"; [ -n "$e" ] && pkg_of "$e"
           done <<< "$LISTEN" | sort -u); do
  IMPORTANT_RE="${IMPORTANT_RE%)\$}|$(sed 's/[.+]/\\&/g' <<< "$p"))\$"
done

UPD=""     # lines: package installed available security(yes/no)
case "$PM" in
  apt)
    if [ "$REFRESH" -eq 1 ]; then echo "Refreshing package lists..."; timeout 180 apt-get update -qq || warn "apt-get update failed (no internet?) - using the old lists"; fi
    newest="$(find /var/lib/apt/lists -maxdepth 1 -name '*Release' -printf '%T@\n' 2>/dev/null | sort -n | tail -1)"
    age=$(( ($(date +%s) - ${newest%.*}) / 3600 ))
    info "Package lists are about ${age}h old$([ "$age" -gt 24 ] && echo " - add --refresh for current results")"
    UPD="$(apt list --upgradable 2>/dev/null | awk -F'[/ ]' 'NR > 1 && $1 != "" {
             sec = ($2 ~ /-security/) ? "yes" : "no"; old = $0; sub(/.*upgradable from: /, "", old); sub(/\].*/, "", old)
             print $1, old, $3, sec }')" ;;
  rpm)
    cache=(-C); [ "$REFRESH" -eq 1 ] && { echo "Refreshing package metadata..."; timeout 300 $DNF -q makecache > /dev/null 2>&1 || warn "metadata refresh failed (no internet?)"; }
    sec="$($DNF "${cache[@]}" -q updateinfo list --security --available 2>/dev/null | awk '{ print $NF }' | sed -E 's/-[0-9][^-]*-[^-]*$//' | sort -u)"
    UPD="$($DNF "${cache[@]}" -q check-update 2>/dev/null | awk 'NF == 3 && $1 ~ /\./ { n = $1; sub(/\.[^.]*$/, "", n); print n, $2 }' |
      while read -r n v; do s=no; grep -qxF "$n" <<< "$sec" && s=yes; echo "$n $(pkg_ver "$n") $v $s"; done)"
    [ -z "$UPD" ] && [ "$REFRESH" -eq 0 ] && info "No cached update data - add --refresh (needs internet) for current results" ;;
  *) warn "Unknown package manager - can't check updates" ;;
esac

IMP="$(awk -v re="$IMPORTANT_RE" '$1 ~ re' <<< "$UPD")"
total=$(sed '/^$/d' <<< "$UPD" | wc -l)
if [ -z "$IMP" ]; then ok "No pending updates for important services ($total updates pending in total)"
else
  printf '%-34s %-30s %-30s %s\n' PACKAGE INSTALLED AVAILABLE SECURITY
  while read -r n o a s; do
    printf '%-34s %-30s %-30s %s\n' "$n" "$o" "$a" "$([ "$s" = yes ] && echo "${R}SECURITY${N}" || echo -)"
  done <<< "$IMP"
  warn "$(wc -l <<< "$IMP") important service update(s) pending ($total updates in total)"
fi

if [ "$UPDATE" -eq 1 ] && [ -n "$IMP" ]; then
  echo; echo "Updating can restart services and needs a working package source. Existing config files are kept."
  before="$(ss -Htuln | awk '{ print $1, $5 }' | sort -u)"
  updated=()
  while read -r n o a s; do
    case "$n" in linux-image-*|kernel|kernel-core) info "skipping kernel $n - needs a reboot; plan it with the captain"; continue ;; esac
    ask "Update $n $o -> $a?" || continue
    case "$PM" in
      apt) DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade -o Dpkg::Options::=--force-confold -o Dpkg::Options::=--force-confdef "$n" < /dev/null ;;
      rpm) $DNF -y upgrade "$n" < /dev/null ;;
    esac && updated+=("$n") || warn "update of $n failed"
  done <<< "$IMP"
  after="$(ss -Htuln | awk '{ print $1, $5 }' | sort -u)"
  gone="$(comm -23 <(echo "$before") <(echo "$after"))"
  [ -n "$gone" ] && warn "These listeners disappeared after updating - check the scored services NOW:" && echo "$gone"
  failed="$(systemctl --failed --no-legend --plain 2>/dev/null | awk '{ printf "%s ", $1 }')"
  [ -n "$failed" ] && warn "Failed units: $failed"
  FIMSH=/opt/ccdc/linux/fim.sh
  if [ ${#updated[@]} -gt 0 ] && [ -x "$FIMSH" ] && [ -f /root/.ccdc-fim/baseline ]; then
    files=()
    while IFS= read -r f; do [ -f "$f" ] && files+=("$f"); done < <(
      case "$PM" in apt) dpkg -L "${updated[@]}" ;; rpm) rpm -ql "${updated[@]}" ;; esac 2>/dev/null)
    if [ ${#files[@]} -gt 0 ] && ask "Record the ${#files[@]} updated package files in the file integrity baseline?"; then
      "$FIMSH" accept "${files[@]}" | tail -1
    fi
  fi
fi

# ------------------------------------------------------------------ summary
h1 "SUMMARY"
echo "Legacy/insecure: $CRIT   Warnings: $WARN   Log: $LOG"
[ "$CRIT" -gt 0 ] && [ "$FIX" -eq 0 ] && echo "Disable them: sudo $0 --fix   (add --remove to uninstall)"
[ -n "${IMP:-}" ] && [ "$UPDATE" -eq 0 ] && echo "Install important updates: sudo $0 --update   (one package at a time, asks first)"
[ "$CRIT" -gt 0 ] && exit 2
[ "$WARN" -gt 0 ] && exit 1
exit 0
