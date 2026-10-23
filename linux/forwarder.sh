#!/bin/bash
# Install the Splunk Universal Forwarder and send this box's logs to Splunk (SPLUNK:9997).
#
# Usage: sudo ./forwarder.sh [--package FILE] [--config FILE]
#   --package FILE  a splunkforwarder .deb / .rpm to install (default: newest one in
#                   ../installers/splunk/, otherwise downloaded from download.splunk.com and
#                   checked against Splunk's SHA-512)
#   --config FILE   default ../ccdc.conf (SPLUNK)
#
# - Forwarder version matches the 2026 Splunk server (10.0.2). Forwarders must be the same or
#   OLDER than the Splunk server - check this year's Splunk version before changing UF_VERSION.
# - The forwarder's local admin account gets a random password (in /root/ccdc/, root-only) - no
#   default credentials.
# - Sends: auth/secure, syslog/messages, kernel, audit, cron, mail and web server logs if present,
#   our own ccdc-* logs, and the systemd journal on boxes without rsyslog (Fedora). Runs as the
#   unprivileged user splunkfwd, given read access to those logs with group membership / ACLs.
# - Starts at boot (systemd unit SplunkForwarder).

set -u
UF_VERSION=10.0.2
UF_BUILD=e2d18b4767e9
UF_BASE="https://download.splunk.com/products/universalforwarder/releases/$UF_VERSION/linux"
HERE="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$HERE/../ccdc.conf"
PKG=""
SPLUNK_HOME=/opt/splunkforwarder
usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    --package) PKG="$2"; shift 2 ;;
    --config)  CONFIG="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)"; exit 1; }
SPLUNK=""
# shellcheck source=../ccdc.conf
[ -f "$CONFIG" ] && . "$CONFIG"
[ -n "$SPLUNK" ] || { echo "SPLUNK is not set in ccdc.conf"; exit 1; }
umask 077; mkdir -p /root/ccdc

if [ -x "$SPLUNK_HOME/bin/splunk" ]; then
  echo "The Splunk forwarder is already installed ($("$SPLUNK_HOME/bin/splunk" version 2>/dev/null | head -1))."
  echo "Outputs: $(grep -rhs '^server' "$SPLUNK_HOME"/etc/apps/*/local/outputs.conf "$SPLUNK_HOME"/etc/system/local/outputs.conf | tr '\n' ' ')"
  systemctl is-active SplunkForwarder 2>/dev/null
  exit 0
fi

# ------------------------------------------------------------------ package
if command -v dpkg > /dev/null && command -v apt-get > /dev/null; then KIND=deb; FILE="splunkforwarder-$UF_VERSION-$UF_BUILD-linux-amd64.deb"
elif command -v rpm > /dev/null; then KIND=rpm; FILE="splunkforwarder-$UF_VERSION-$UF_BUILD.x86_64.rpm"
else echo "Neither dpkg nor rpm found - install the .tgz by hand"; exit 1; fi
[ "$(uname -m)" = x86_64 ] || { echo "This box is $(uname -m); the packages here are x86_64"; exit 1; }

if [ -z "$PKG" ]; then
  PKG="$(ls -1 "$HERE"/../installers/splunk/splunkforwarder-*."$KIND" 2>/dev/null | sort -V | tail -1)"
fi
if [ -z "$PKG" ]; then
  PKG="/root/ccdc/$FILE"
  echo "Downloading $FILE from download.splunk.com ..."
  curl -fL --retry 2 -o "$PKG" "$UF_BASE/$FILE" && curl -fsL -o "$PKG.sha512" "$UF_BASE/$FILE.sha512" ||
    { echo "Download failed (proxy blocking download.splunk.com?). Copy the package here and use --package."; exit 1; }
fi
if [ -f "$PKG.sha512" ]; then
  exp="$(grep -oE '[0-9a-f]{128}' "$PKG.sha512" | head -1)"
  [ "$(sha512sum "$PKG" | cut -c1-128)" = "$exp" ] || { echo "SHA-512 mismatch for $PKG - not installing"; exit 1; }
  echo "SHA-512 verified: $(basename "$PKG")"
fi

echo "Installing $(basename "$PKG") ..."
case "$KIND" in
  deb) DEBIAN_FRONTEND=noninteractive dpkg -i "$PKG" ;;
  rpm) rpm -i "$PKG" ;;
esac || { echo "Package install failed"; exit 1; }
id splunkfwd > /dev/null 2>&1 || useradd -r -M -d "$SPLUNK_HOME" -s "$(command -v nologin || echo /sbin/nologin)" splunkfwd
# The package creates splunkfwd with a bash login shell - a service account doesn't need one
usermod -s "$(command -v nologin || echo /sbin/nologin)" splunkfwd

# ------------------------------------------------------------------ configuration
PW="$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 20)"
printf 'Splunk forwarder local admin on %s\nuser: admin\npassword: %s\n' "$(hostname)" "$PW" > /root/ccdc/splunkforwarder-admin.txt
chmod 600 /root/ccdc/splunkforwarder-admin.txt
mkdir -p "$SPLUNK_HOME/etc/system/local"
printf '[user_info]\nUSERNAME = admin\nPASSWORD = %s\n' "$PW" > "$SPLUNK_HOME/etc/system/local/user-seed.conf"

APP="$SPLUNK_HOME/etc/apps/ccdc_forwarder/local"
mkdir -p "$APP"
cat > "$APP/outputs.conf" <<EOF
[tcpout]
defaultGroup = ccdc

[tcpout:ccdc]
server = $SPLUNK:9997
EOF

add_monitor() {   # add_monitor PATH SOURCETYPE
  [ -e "$1" ] || return 0
  printf '[monitor://%s]\nsourcetype = %s\ndisabled = false\n\n' "$1" "$2" >> "$APP/inputs.conf"
  echo "  monitoring $1"
}
: > "$APP/inputs.conf"
add_monitor /var/log/auth.log        linux_secure
add_monitor /var/log/secure          linux_secure
add_monitor /var/log/syslog          syslog
add_monitor /var/log/messages        syslog
add_monitor /var/log/kern.log        syslog
add_monitor /var/log/cron            syslog
add_monitor /var/log/audit/audit.log linux_audit
add_monitor /var/log/mail.log        syslog
add_monitor /var/log/maillog         syslog
add_monitor /var/log/apache2         access_combined
add_monitor /var/log/httpd           access_combined
add_monitor /var/log/nginx           access_combined
add_monitor /var/log/mysql           mysqld_error
add_monitor /var/log/mariadb         mysqld_error
for f in /var/log/ccdc-*.log /var/log/webguard.log; do add_monitor "$f" ccdc; done
# No rsyslog (e.g. Fedora): read the systemd journal instead
if [ ! -e /var/log/messages ] && [ ! -e /var/log/syslog ]; then
  printf '[journald://ccdc]\nsourcetype = journald\ndisabled = false\n\n' >> "$APP/inputs.conf"
  echo "  monitoring the systemd journal (no rsyslog files on this box)"
fi

# Read access for the unprivileged forwarder user
for g in adm systemd-journal; do getent group "$g" > /dev/null && usermod -aG "$g" splunkfwd; done
if command -v setfacl > /dev/null; then
  for d in /var/log /var/log/audit /var/log/httpd /var/log/apache2 /var/log/nginx /var/log/mariadb /var/log/mysql; do
    [ -d "$d" ] || continue
    setfacl -m u:splunkfwd:rx "$d"; setfacl -d -m u:splunkfwd:r "$d"      # new (rotated) files inherit read access
    find "$d" -maxdepth 1 -type f -exec setfacl -m u:splunkfwd:r {} + 2>/dev/null
  done
else
  echo "WARN: setfacl not found - the forwarder may not be able to read /var/log/secure or audit.log"
fi
chown -R splunkfwd:splunkfwd "$SPLUNK_HOME"

# ------------------------------------------------------------------ start
"$SPLUNK_HOME/bin/splunk" enable boot-start -systemd-managed 1 -user splunkfwd -group splunkfwd \
  --accept-license --answer-yes --no-prompt > /dev/null || { echo "enable boot-start failed"; exit 1; }
systemctl start SplunkForwarder
sleep 8
if systemctl is-active --quiet SplunkForwarder; then echo "SplunkForwarder: running, starts at boot"
else echo "SplunkForwarder did not start: journalctl -u SplunkForwarder -n 30"; exit 1; fi
if ss -Htn state established "( dport = :9997 )" 2>/dev/null | grep -q .; then echo "Connected to $SPLUNK:9997"
else echo "Not connected to $SPLUNK:9997 yet - check Splunk receiving (Settings > Forwarding and receiving) and the firewalls"; fi
echo "Forwarder admin password: /root/ccdc/splunkforwarder-admin.txt"
echo "In Splunk: index=* host=$(hostname) earliest=-15m | stats count by source"
