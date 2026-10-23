#!/bin/bash
# Harden the scored services on a Linux box without breaking their checks.
#
# Usage: sudo ./secure.sh [all|web|ssh|mail|ftp|splunk] [--yes] [--force] [--enable-https] [--config FILE]
#   all (default)  every part whose service runs on this box
#   web     plain HTTP is answered with a redirect (302) to the same page over HTTPS (Apache or
#           nginx). Tested before and after: HTTP must end, with no loop, on the page HTTPS served
#           before - otherwise the change is undone. Pages that differ between HTTP and HTTPS
#           (the HTTP check compares the page) are refused unless --force.
#           --enable-https: turn on the distro's default HTTPS site if nothing listens on 443
#   ssh     SSH_SCORED=yes: no root login (unless root is in SCORED_USERS), no empty passwords,
#           no forwarding / tunnels, modern ciphers; password logins stay ON (the scorer uses them).
#           SSH_SCORED=no: offers to stop and disable sshd (we work from the VM consoles)
#   mail    Postfix: STARTTLS offered, TLS 1.2+, no VRFY, HELO required, no open relay, 587/465
#           with login if Dovecot SASL is set up. Dovecot: TLS on (993/995), TLS 1.2+. Plaintext
#           SMTP/POP3/IMAP logins keep working - the scorer may not use TLS. Roundcube installer
#           folder moved away.
#   ftp     vsftpd: no anonymous access, FTPS offered (not required), passive ports FTP_PASV,
#           transfer logging
#   splunk  NO account lockout (the red team could lock out the scorer's account), stronger
#           password rules, session timeout; restarts Splunk after asking
#
# Every part: backup -> change -> config check -> reload -> local test of the service. A failed
# check or test puts the old files back and reloads. Backups: /root/ccdc/secure-<time>/
# Log: /root/ccdc/secure-<time>.log. Exit: 0 done, 1 a part was undone or failed.
# After running it outside deploy.sh: sudo linux/fim.sh accept <changed files> (listed at the end).

set -u
PART="all"; YES=0; FORCE=0; ENABLE_HTTPS=0
CONFIG="$(dirname "$0")/../ccdc.conf"
usage() { sed -n '2,31p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
while [ $# -gt 0 ]; do
  case "$1" in
    all|web|ssh|mail|ftp|splunk) PART="$1" ;;
    --yes) YES=1 ;; --force) FORCE=1 ;; --enable-https) ENABLE_HTTPS=1 ;;
    --config) CONFIG="$2"; shift ;;
    *) usage ;;
  esac
  shift
done
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)"; exit 1; }
SCORED_USERS=(); WEB_CHECK_PATHS=(/); FTP_PASV="40000:40100"; INSIDE=""; EXTERNAL=""; SSH_SCORED=yes
# shellcheck source=../ccdc.conf
[ -f "$CONFIG" ] && . "$CONFIG"

TS="$(date +%Y%m%d-%H%M%S)"
BK="/root/ccdc/secure-$TS"
umask 077; mkdir -p "$BK"
LOG="/root/ccdc/secure-$TS.log"
exec > >(tee -a "$LOG") 2>&1

if [ -t 1 ] || [ -t 0 ]; then R=$'\e[31m'; Y=$'\e[33m'; G=$'\e[32m'; C=$'\e[36m'; N=$'\e[0m'; else R=; Y=; G=; C=; N=; fi
FAILED=0
bad()  { FAILED=$((FAILED + 1)); echo "${R}[FAIL]${N}   $*"; logger -t ccdc-secure -p auth.warning "FAIL: $*" 2>/dev/null; }
warn() { echo "${Y}[WARN]${N}   $*"; }
ok()   { echo "${G}[OK]${N}     $*"; }
info() { echo "         $*"; }
h1()   { printf '\n%s==================== %s ====================%s\n' "$C" "$1" "$N"; }
ask()  { [ "$YES" -eq 1 ] && return 0; local a; read -r -p "    $1 [y/N] " a < /dev/tty || a=""; [[ "$a" =~ ^[Yy] ]]; }
want() { [ "$PART" = all ] || [ "$PART" = "$1" ]; }

# ------------------------------------------------------------------ change tracking
# track FILE: back it up once (or remember it didn't exist) before changing it
CHANGED=(); ALL_CHANGED=()
track() {
  local f
  for f; do
    [[ " ${CHANGED[*]} " == *" $f "* ]] && continue
    CHANGED+=("$f"); ALL_CHANGED+=("$f")
    if [ -e "$f" ] || [ -L "$f" ]; then mkdir -p "$BK$(dirname "$f")" && cp -a "$f" "$BK$f"; fi
  done
}
begin() { CHANGED=(); h1 "$1"; }
# undo RELOAD_COMMAND...: put every tracked file of this part back, then reload
undo() {
  local f
  for f in "${CHANGED[@]}"; do
    if [ -e "$BK$f" ] || [ -L "$BK$f" ]; then rm -f "$f"; cp -a "$BK$f" "$f"; else rm -f "$f"; fi
  done
  [ $# -gt 0 ] && "$@" > /dev/null 2>&1
  warn "undone - the old configuration is back"
}

# set_kv FILE KEY VALUE: KEY=VALUE files (vsftpd), replace or append
set_kv() {
  if grep -qE "^[[:space:]]*#?[[:space:]]*$2=" "$1"; then
    sed -i -E "0,/^[[:space:]]*#?[[:space:]]*$2=.*/s||$2=$3|" "$1"
  else
    echo "$2=$3" >> "$1"
  fi
}

# ini_set FILE STANZA KEY VALUE (Splunk .conf files)
ini_set() {
  local f="$1"
  [ -f "$f" ] || : > "$f"
  awk -v s="[$2]" -v k="$3" -v v="$4" '
    function flush() { if (insec && !done) { print k " = " v; done = 1 } }
    { t = $0; gsub(/^[ \t]+|[ \t]+$/, "", t) }
    t ~ /^\[.*\]$/ { flush(); insec = (t == s); print; next }
    insec && index(t, k) == 1 && substr(t, length(k) + 1) ~ /^[ \t]*=/ { if (!done) print k " = " v; done = 1; next }
    { print }
    END { flush(); if (!done) { print ""; print s; print k " = " v } }' "$f" > "$f.ccdc-tmp" &&
    cat "$f.ccdc-tmp" > "$f" && rm -f "$f.ccdc-tmp"    # cat keeps owner and mode
}

# banner HOST PORT: first line the service sends
banner() { timeout 5 bash -c "exec 3<>/dev/tcp/$1/$2 && head -n1 <&3" 2>/dev/null | tr -d '\r'; }
# tls_ok PORT [starttls-proto]: a TLS handshake works
tls_ok() {
  local extra=(); [ -n "${2:-}" ] && extra=(-starttls "$2")
  timeout 10 openssl s_client -connect "127.0.0.1:$1" "${extra[@]}" -brief < /dev/null 2>&1 | grep -qi 'protocol version'
}
active() { local u; for u; do systemctl is-active --quiet "$u" 2>/dev/null && { echo "$u"; return 0; }; done; return 1; }

# A certificate for mail/FTP: the service's own, the distro's snakeoil one, or a new self-signed one
CERT=""; KEY=""
get_cert() {
  [ -n "$CERT" ] && return 0
  local pair
  for pair in "/etc/ssl/certs/ssl-cert-snakeoil.pem /etc/ssl/private/ssl-cert-snakeoil.key" \
              "/etc/pki/tls/certs/postfix.pem /etc/pki/tls/private/postfix.key" \
              "/etc/ssl/ccdc/server.crt /etc/ssl/ccdc/server.key"; do
    set -- $pair
    [ -s "$1" ] && [ -s "$2" ] && { CERT="$1"; KEY="$2"; return 0; }
  done
  mkdir -p /etc/ssl/ccdc && chmod 755 /etc/ssl/ccdc
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=$(hostname -f 2>/dev/null || hostname)" \
    -keyout /etc/ssl/ccdc/server.key -out /etc/ssl/ccdc/server.crt > /dev/null 2>&1 || return 1
  chmod 600 /etc/ssl/ccdc/server.key; chmod 644 /etc/ssl/ccdc/server.crt
  CERT=/etc/ssl/ccdc/server.crt; KEY=/etc/ssl/ccdc/server.key
  info "created a self-signed certificate: $CERT"
}

# ------------------------------------------------------------------ addresses
ip2int() { local IFS=.; read -r a b c d <<< "$1"; echo $(( (a << 24) + (b << 16) + (c << 8) + d )); }
in_cidr() {
  local bits="${2#*/}" m
  m=$(( bits == 0 ? 0 : (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF ))
  [ $(( $(ip2int "$1") & m )) -eq $(( $(ip2int "${2%/*}") & m )) ]
}
MYIP=""
for a in $(ip -o -4 addr show 2>/dev/null | awk '{ split($4, x, "/"); print x[1] }'); do
  [ -n "$INSIDE" ] && [[ "$INSIDE" == */* ]] && in_cidr "$a" "$INSIDE" && { MYIP="$a"; break; }
done
# The scorer asks for the page by our public address: test with that Host name, connecting locally
WEBHOST="${MYIP:-127.0.0.1}"
if [ -n "$MYIP" ] && [[ "$EXTERNAL" =~ ^172\.25\.([0-9]+)\. ]]; then WEBHOST="172.25.${BASH_REMATCH[1]}.${MYIP##*.}"; fi

# ============================================================================ web
web_fetch() {   # web_fetch URL [curl options]: through 127.0.0.1, whatever host name the URL has
  local url="$1"; shift
  curl -sk --max-time 15 --connect-to "$WEBHOST:80:127.0.0.1:80" --connect-to "$WEBHOST:443:127.0.0.1:443" "$@" "$url"
}
same_page() {   # same_page A B: identical, or (dynamic pages) same <title> and size within 10%
  cmp -s "$1" "$2" && return 0
  [ "${DYNAMIC:-0}" -eq 1 ] || return 1
  local t1 t2 s1 s2
  t1="$(grep -oi '<title>[^<]*' "$1" | head -1)"; t2="$(grep -oi '<title>[^<]*' "$2" | head -1)"
  s1=$(wc -c < "$1"); s2=$(wc -c < "$2")
  [ "$t1" = "$t2" ] && [ $(( s1 * 10 )) -ge $(( s2 * 9 )) ] && [ $(( s2 * 10 )) -ge $(( s1 * 9 )) ]
}

secure_web() {
  begin "WEB: HTTP -> HTTPS"
  local kind="" unit reload conf
  if unit="$(active httpd)"; then kind=apache-rh
  elif unit="$(active apache2)"; then kind=apache-deb
  elif unit="$(active nginx)"; then kind=nginx
  else info "no Apache or nginx running - skipped"; return 0; fi
  reload=(systemctl reload "$unit")
  info "web server: $unit; testing as http(s)://$WEBHOST (connected locally)"

  if ! ss -Hltn 2>/dev/null | grep -qE ':443\b'; then
    if [ "$ENABLE_HTTPS" -eq 1 ] && [ "$kind" = apache-deb ]; then
      track /etc/apache2/mods-enabled/ssl.load /etc/apache2/mods-enabled/ssl.conf \
            /etc/apache2/mods-enabled/socache_shmcb.load /etc/apache2/sites-enabled/default-ssl.conf
      a2enmod -q ssl > /dev/null && a2ensite -q default-ssl > /dev/null && apache2ctl -t 2>/dev/null &&
        systemctl reload apache2 && sleep 1 && ok "turned on the default HTTPS site (snakeoil certificate)"
    elif [ "$ENABLE_HTTPS" -eq 1 ] && [ "$kind" = apache-rh ]; then
      track /etc/httpd/conf.d/ssl.conf
      rpm -q mod_ssl > /dev/null 2>&1 || dnf -y install mod_ssl < /dev/null > /dev/null 2>&1
      apachectl -t 2>/dev/null && systemctl restart httpd && sleep 1 && ok "turned on HTTPS (mod_ssl, self-signed certificate)"
    fi
    if ! ss -Hltn 2>/dev/null | grep -qE ':443\b'; then
      bad "nothing listens on 443 - a redirect would break HTTP. Set up HTTPS first (or --enable-https)"
      [ ${#CHANGED[@]} -gt 0 ] && undo "${reload[@]}"
      return 1
    fi
  fi

  # Before: what HTTP and HTTPS serve now (twice, to spot pages that change on every load)
  local i=0 p code h0 s0 loc final rc
  local -a S0=()      # HTTPS status per path, before the change
  DYNAMIC=0
  mkdir -p "$BK/web"
  for p in "${WEB_CHECK_PATHS[@]}"; do
    i=$((i + 1))
    h0="$(web_fetch "http://$WEBHOST$p" -o "$BK/web/http$i" -w '%{http_code}')"
    loc="$(web_fetch "http://$WEBHOST$p" -o /dev/null -w '%{redirect_url}')"
    if [[ "$h0" =~ ^30 ]] && [[ "$loc" == https://* ]]; then ok "$p: HTTP already redirects to HTTPS"; return 0; fi
    s0="$(web_fetch "https://$WEBHOST$p" -o "$BK/web/https$i" -w '%{http_code}')"
    web_fetch "https://$WEBHOST$p" -o "$BK/web/https$i.b"
    web_fetch "http://$WEBHOST$p" -o "$BK/web/http$i.b"
    cmp -s "$BK/web/https$i" "$BK/web/https$i.b" && cmp -s "$BK/web/http$i" "$BK/web/http$i.b" || DYNAMIC=1
    S0[$i]="$s0"
    info "$p: HTTP $h0, HTTPS $s0"
    if [ "$h0" = 000 ] || [ "$s0" = 000 ]; then
      bad "$p: the site doesn't answer locally over $([ "$h0" = 000 ] && echo HTTP || echo HTTPS) - fix that first, nothing changed"
      return 1
    fi
    if [ "$s0" != "$h0" ]; then
      bad "$p: HTTPS answers $s0 but HTTP answers $h0 - after a redirect the HTTP check would get $s0. Not redirecting."
      return 1
    fi
    if ! same_page "$BK/web/http$i" "$BK/web/https$i"; then
      if [ "$FORCE" -eq 1 ]; then
        warn "$p: HTTPS serves a different page than HTTP - redirecting anyway (--force)"
      else
        bad "$p: HTTPS serves a different page than HTTP. The HTTP check compares the page, so after a"
        info "redirect it would likely fail. Not redirecting (--force to do it anyway; diff: $BK/web/http$i $BK/web/https$i)"
        return 1
      fi
    fi
  done
  [ "$DYNAMIC" -eq 1 ] && warn "the page changes on every load - comparing title and size only; check it in a browser too"

  # Change
  case "$kind" in
    apache-rh|apache-deb)
      if [ "$kind" = apache-rh ]; then conf=/etc/httpd/conf.d/zz-ccdc-https-redirect.conf
      else conf=/etc/apache2/conf-available/ccdc-https-redirect.conf; fi
      track "$conf"
      cat > "$conf" <<'EOF'
# CCDC (linux/secure.sh): answer plain HTTP with a redirect to the same URL over HTTPS.
# Undo: remove this file (Debian/Ubuntu: a2disconf ccdc-https-redirect) and reload the web server.
<If "%{HTTPS} != 'on'">
    RewriteEngine On
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=302,L]
</If>
EOF
      chmod 644 "$conf"
      if [ "$kind" = apache-deb ]; then
        track /etc/apache2/conf-enabled/ccdc-https-redirect.conf /etc/apache2/mods-enabled/rewrite.load
        a2enmod -q rewrite > /dev/null && a2enconf -q ccdc-https-redirect > /dev/null
        apache2ctl -t > /dev/null 2>&1 || { bad "apache2 config check failed: $(apache2ctl -t 2>&1 | head -3)"; undo "${reload[@]}"; return 1; }
      else
        httpd -M 2>/dev/null | grep -q rewrite_module || { bad "mod_rewrite is not loaded in httpd"; undo; return 1; }
        apachectl -t > /dev/null 2>&1 || { bad "httpd config check failed: $(apachectl -t 2>&1 | head -3)"; undo "${reload[@]}"; return 1; }
      fi ;;
    nginx)
      local f files=()
      while IFS= read -r f; do files+=("$f"); done < <(
        grep -rlE '^[[:space:]]*listen[[:space:]]+([^ ;]*:)?80[ ;]' /etc/nginx 2>/dev/null | xargs -r -d '\n' realpath | sort -u)
      [ ${#files[@]} -eq 0 ] && { bad "no nginx server block listens on port 80"; return 1; }
      track "${files[@]}"
      for f in "${files[@]}"; do
        sed -i -E '/^[[:space:]]*listen[[:space:]]+([^ ;]*:)?80[ ;]/a\    if ($scheme = http) { return 302 https://$host$request_uri; }   # CCDC secure.sh' "$f"
      done
      nginx -t > /dev/null 2>&1 || { bad "nginx config check failed: $(nginx -t 2>&1 | head -3)"; undo "${reload[@]}"; return 1; } ;;
  esac
  "${reload[@]}" || { bad "reload of $unit failed"; undo "${reload[@]}"; return 1; }
  sleep 1

  # After: HTTP redirects to the same URL on HTTPS and ends on the same page, no loop
  i=0
  for p in "${WEB_CHECK_PATHS[@]}"; do
    i=$((i + 1))
    read -r code loc <<< "$(web_fetch "http://$WEBHOST$p" -o /dev/null -w '%{http_code} %{redirect_url}')"
    if [[ ! "$code" =~ ^30 ]] || [[ "$loc" != "https://$WEBHOST$p"* ]]; then
      bad "$p: HTTP answered $code ${loc:-} instead of a redirect to https://$WEBHOST$p"; undo "${reload[@]}"; return 1
    fi
    final="$(web_fetch "http://$WEBHOST$p" -L --max-redirs 5 -o "$BK/web/after$i" -w '%{http_code}')"; rc=$?
    [ "$rc" -eq 47 ] && { bad "$p: redirect loop (the site sends HTTPS back to HTTP - check its base URL setting)"; undo "${reload[@]}"; return 1; }
    if [ "$final" != "${S0[$i]}" ] || ! same_page "$BK/web/after$i" "$BK/web/https$i"; then
      bad "$p: after the redirect the page is not what HTTPS served before (status $final)"; undo "${reload[@]}"; return 1
    fi
    ok "$p: HTTP -> 302 -> $loc -> same page as before"
  done
  ok "HTTP now redirects to HTTPS. Watch Quotient: if the HTTP check goes down, the scorer doesn't follow"
  if [ "$kind" = nginx ]; then
    info "redirects - undo: delete the lines marked '# CCDC secure.sh' in ${files[*]}, then nginx -t && systemctl reload nginx"
  else
    info "redirects - undo: rm $conf$([ "$kind" = apache-deb ] && echo ' (a2disconf ccdc-https-redirect first)'), then systemctl reload $unit"
  fi
}

# ============================================================================ ssh
secure_ssh() {
  begin "SSH"
  local sshd unit main=/etc/ssh/sshd_config dropin=/etc/ssh/sshd_config.d/00-ccdc.conf target
  sshd="$(command -v sshd || echo /usr/sbin/sshd)"
  [ -x "$sshd" ] && [ -f "$main" ] || { info "no OpenSSH server - skipped"; return 0; }
  unit="$(active ssh sshd)" || { info "sshd is not running - skipped"; return 0; }
  if [ "${SSH_SCORED:-yes}" != yes ] || [ "${CCDC_ROLE:-}" = workstation ]; then
    # Not scored (workstations can't be: no inbound public address) and we use the consoles:
    # nothing needs sshd, so the safest sshd is none
    warn "sshd runs, but SSH isn't scored here and we manage boxes from the console"
    if ask "Stop and disable sshd? (undo: systemctl enable --now $unit)"; then
      systemctl disable --now "$unit" > /dev/null 2>&1 && systemctl disable --now "${unit}.socket" > /dev/null 2>&1
      ok "sshd stopped and disabled"
    fi
    return 0
  fi

  local root_scored=0 u
  for u in "${SCORED_USERS[@]}"; do [ "$u" = root ] && root_scored=1; done
  # Keep only algorithms this OpenSSH build has (sshd -t fails on unknown ones)
  pick() { local have; have=" $(ssh -Q "$1" 2>/dev/null | tr '\n' ' ') "; shift
           local out="" a; for a; do [[ "$have" == *" $a "* ]] && out+="${out:+,}$a"; done; echo "$out"; }
  local ciphers macs kex
  ciphers="$(pick cipher chacha20-poly1305@openssh.com aes256-gcm@openssh.com aes128-gcm@openssh.com aes256-ctr aes192-ctr aes128-ctr)"
  macs="$(pick mac hmac-sha2-512-etm@openssh.com hmac-sha2-256-etm@openssh.com umac-128-etm@openssh.com hmac-sha2-512 hmac-sha2-256)"
  kex="$(pick kex sntrup761x25519-sha512@openssh.com curve25519-sha256 curve25519-sha256@libssh.org ecdh-sha2-nistp521 ecdh-sha2-nistp384 ecdh-sha2-nistp256 diffie-hellman-group18-sha512 diffie-hellman-group16-sha512 diffie-hellman-group14-sha256)"

  local block
  block="# CCDC (linux/secure.sh) - first value wins in sshd, so this file must come first.
# Password logins stay on: the scoring engine logs in with a password.
$([ "$root_scored" -eq 1 ] && echo "# PermitRootLogin unchanged: root is in SCORED_USERS" || echo "PermitRootLogin no")
PermitEmptyPasswords no
PasswordAuthentication yes
HostbasedAuthentication no
IgnoreRhosts yes
PermitUserEnvironment no
AuthorizedKeysFile .ssh/authorized_keys
MaxAuthTries 4
LoginGraceTime 30
MaxStartups 10:30:60
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
GatewayPorts no
LogLevel VERBOSE
${ciphers:+Ciphers $ciphers}
${macs:+MACs $macs}
${kex:+KexAlgorithms $kex}"

  if grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$main"; then
    target="$dropin"; track "$dropin"
    printf '%s\n' "$block" > "$dropin"; chmod 600 "$dropin"
  else
    target="$main"; track "$main"
    { printf '# BEGIN CCDC secure.sh\n%s\n# END CCDC secure.sh\n' "$block"; sed '/^# BEGIN CCDC secure.sh/,/^# END CCDC secure.sh/d' "$BK$main"; } > "$main"
  fi
  "$sshd" -t 2> "$BK/sshd-t.txt" || { bad "sshd config check failed: $(head -3 "$BK/sshd-t.txt")"; undo; return 1; }
  systemctl reload "$unit" || { bad "reload of $unit failed"; undo systemctl reload "$unit"; return 1; }
  sleep 1
  local port b=""
  for port in $("$sshd" -T 2>/dev/null | awk '$1 == "port" { print $2 }'); do
    b="$(banner 127.0.0.1 "$port")"
    [[ "$b" == SSH-* ]] || { bad "sshd doesn't answer on port $port after the reload"; undo systemctl reload "$unit"; return 1; }
  done
  ok "sshd hardened ($target) and answering: $b"
  [ "$root_scored" -eq 0 ] && info "root can't log in over SSH any more (console logins are not affected)"
}

# ============================================================================ mail
secure_postfix() {
  command -v postconf > /dev/null && active postfix > /dev/null || { info "Postfix not running - skipped"; return 0; }
  track /etc/postfix/main.cf /etc/postfix/master.cf
  local c k lvl mynet relay
  c="$(postconf -h smtpd_tls_cert_file)"; k="$(postconf -h smtpd_tls_key_file)"
  if [ ! -s "$c" ] || [ ! -s "$k" ]; then get_cert || { bad "no TLS certificate"; undo; return 1; }; c="$CERT"; k="$KEY"; fi
  lvl="$(postconf -h smtpd_tls_security_level)"
  [ "$lvl" = encrypt ] || lvl=may          # offer STARTTLS, don't require it (the scorer may not use it)
  postconf -e "smtpd_tls_cert_file=$c" "smtpd_tls_key_file=$k" "smtpd_tls_security_level=$lvl" \
    'smtpd_tls_protocols=!SSLv2, !SSLv3, !TLSv1, !TLSv1.1' 'smtpd_tls_mandatory_protocols=!SSLv2, !SSLv3, !TLSv1, !TLSv1.1' \
    'smtp_tls_security_level=may' 'smtpd_tls_loglevel=1' 'disable_vrfy_command=yes' 'smtpd_helo_required=yes' \
    'smtpd_banner=$myhostname ESMTP'
  mynet="$(postconf -h mynetworks)"
  if [[ " $mynet " =~ [[:space:],]0\.0\.0\.0/0[[:space:],] ]] || [[ "$mynet" == *"::/0"* ]]; then
    warn "mynetworks was '$mynet' (an open relay) - set to localhost only"
    postconf -e 'mynetworks=127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128'
  fi
  relay="$(postconf -h smtpd_relay_restrictions) $(postconf -h smtpd_recipient_restrictions)"
  if [[ "$relay" != *unauth_destination* ]]; then
    warn "no reject/defer_unauth_destination - mail could be relayed anywhere; set the Postfix default"
    postconf -e 'smtpd_relay_restrictions=permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination'
  fi
  # Submission (587, STARTTLS) and smtps (465) need a login: only with Dovecot SASL in place
  if [ "$(postconf -h smtpd_sasl_type)" = dovecot ] && [ -S "/var/spool/postfix/$(postconf -h smtpd_sasl_path)" ]; then
    local svc
    for svc in submission smtps; do
      postconf -M "$svc/inet" 2>/dev/null | grep -q . && continue
      postconf -M "$svc/inet=$svc inet n - - - - smtpd"
      postconf -P "$svc/inet/syslog_name=postfix/$svc" "$svc/inet/smtpd_sasl_auth_enable=yes" \
        "$svc/inet/smtpd_client_restrictions=permit_sasl_authenticated,reject"
      if [ "$svc" = smtps ]; then postconf -P "$svc/inet/smtpd_tls_wrappermode=yes"
      else postconf -P "$svc/inet/smtpd_tls_security_level=encrypt"; fi
      info "enabled $svc ($([ "$svc" = smtps ] && echo 465 || echo 587), TLS + login)"
    done
  else
    info "587/465 not enabled: Postfix has no Dovecot SASL login set up"
  fi
  postfix check 2> "$BK/postfix-check.txt" || { bad "postfix check failed: $(head -3 "$BK/postfix-check.txt")"; undo systemctl reload postfix; return 1; }
  systemctl reload postfix || { bad "postfix reload failed"; undo systemctl restart postfix; return 1; }
  sleep 2
  local b
  b="$(banner 127.0.0.1 25)"
  [[ "$b" == 220* ]] || { bad "SMTP doesn't answer on 25 after the change"; undo systemctl restart postfix; return 1; }
  tls_ok 25 smtp && ok "SMTP 25: $b, STARTTLS works" || warn "SMTP 25 answers but STARTTLS failed - check $c"
  info "Plaintext SMTP still works. AUTH without TLS (smtpd_tls_auth_only) left as it was: $(postconf -h smtpd_tls_auth_only)"
}

secure_dovecot() {
  command -v doveconf > /dev/null && active dovecot > /dev/null || { info "Dovecot not running - skipped"; return 0; }
  local ver f=/etc/dovecot/conf.d/99-ccdc.conf ssl cert key
  ver="$(dovecot --version 2>/dev/null)"
  [[ "$ver" == 2.3* ]] || { warn "Dovecot $ver: settings differ from 2.3 - do TLS by hand (doveconf -n | grep ssl)"; return 0; }
  grep -qE '^[[:space:]]*!include[[:space:]]+conf\.d/\*\.conf' /etc/dovecot/dovecot.conf || f=/etc/dovecot/dovecot.conf
  track "$f"
  ssl="$(doveconf -h ssl 2>/dev/null)"
  cert="$(doveconf -h ssl_cert 2>/dev/null | sed 's/^<//')"; key="$(doveconf -h ssl_key 2>/dev/null | sed 's/^<//')"
  if [ ! -s "$cert" ] || [ ! -s "$key" ]; then get_cert || { bad "no TLS certificate"; return 1; }; cert="$CERT"; key="$KEY"; fi
  [ "$f" = /etc/dovecot/dovecot.conf ] || : > "$f"     # our own file: rewrite it on every run
  {
    [ "$f" = /etc/dovecot/dovecot.conf ] && echo
    echo "# CCDC (linux/secure.sh): TLS on 993/995 and STARTTLS; plaintext logins unchanged"
    [ "$ssl" = required ] || echo "ssl = yes"
    echo "ssl_cert = <$cert"
    echo "ssl_key = <$key"
    echo "ssl_min_protocol = TLSv1.2"
    echo "ssl_prefer_server_ciphers = yes"
  } >> "$f"
  doveconf -n > /dev/null 2> "$BK/doveconf.txt" || { bad "dovecot config check failed: $(head -3 "$BK/doveconf.txt")"; undo systemctl reload dovecot; return 1; }
  systemctl reload dovecot || { bad "dovecot reload failed"; undo systemctl restart dovecot; return 1; }
  sleep 2
  local b
  for p in 110 143; do
    ss -Hltn | grep -qE ":$p\b" || continue
    b="$(banner 127.0.0.1 "$p")"
    [[ "$b" == "+OK"* || "$b" == "* OK"* ]] || { bad "port $p doesn't answer after the change"; undo systemctl restart dovecot; return 1; }
    ok "port $p: $b"
  done
  for p in 993 995; do
    if tls_ok "$p"; then ok "port $p: TLS works"; else warn "port $p: no TLS service (inet_listener imaps/pop3s port = 0?)"; fi
  done
  info "disable_plaintext_auth = $(doveconf -h disable_plaintext_auth) (left as it was: 'yes' refuses logins without TLS)"
}

secure_roundcube() {
  local d
  for d in /usr/share/roundcube/installer /var/lib/roundcube/installer /var/www/*/installer /var/www/html/*/installer; do
    [ -f "$d/index.php" ] && [ -f "$d/check.php" ] || continue
    warn "Roundcube installer folder: $d (lets anyone re-run the setup)"
    if ask "Move it to $BK$d?"; then mkdir -p "$BK$(dirname "$d")" && mv "$d" "$BK$d" && ok "moved"; fi
  done
}

secure_mail() {
  begin "MAIL: SMTP, POP3, IMAP, webmail"
  secure_postfix
  CHANGED=()
  secure_dovecot
  CHANGED=()
  secure_roundcube
  info "Webmail over HTTPS: the web part (secure.sh web) redirects HTTP to HTTPS"
}

# ============================================================================ ftp
secure_ftp() {
  begin "FTP"
  local conf
  for conf in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf ""; do [ -f "$conf" ] && break; done
  if [ -z "$conf" ] || ! active vsftpd > /dev/null; then
    active proftpd pure-ftpd > /dev/null && warn "proftpd / pure-ftpd: not handled here - turn off anonymous logins by hand"
    info "vsftpd not running - skipped"; return 0
  fi
  track "$conf"
  get_cert || { bad "no TLS certificate"; return 1; }
  grep -qE '^rsa_cert_file=' "$conf" && [ -s "$(sed -n 's/^rsa_cert_file=//p' "$conf")" ] || { set_kv "$conf" rsa_cert_file "$CERT"; set_kv "$conf" rsa_private_key_file "$KEY"; }
  local kv
  for kv in anonymous_enable=NO anon_upload_enable=NO anon_mkdir_write_enable=NO anon_other_write_enable=NO \
            ssl_enable=YES allow_anon_ssl=NO force_local_logins_ssl=NO force_local_data_ssl=NO require_ssl_reuse=NO \
            ssl_tlsv1=YES ssl_sslv2=NO ssl_sslv3=NO ssl_ciphers=HIGH pasv_enable=YES "pasv_min_port=${FTP_PASV%%:*}" \
            "pasv_max_port=${FTP_PASV##*:}" xferlog_enable=YES log_ftp_protocol=YES hide_ids=YES ls_recurse_enable=NO; do
    set_kv "$conf" "${kv%%=*}" "${kv#*=}"
  done
  systemctl restart vsftpd || { bad "vsftpd failed to start: $(journalctl -u vsftpd -n 3 --no-pager -o cat)"; undo systemctl restart vsftpd; return 1; }
  sleep 1
  local b; b="$(banner 127.0.0.1 21)"
  [[ "$b" == 220* ]] || { bad "FTP doesn't answer on 21"; undo systemctl restart vsftpd; return 1; }
  ok "vsftpd: $b - no anonymous, FTPS offered, passive ports $FTP_PASV"
  info "Open 21 and $FTP_PASV in the firewalls: FTP_SCORED=yes in ccdc.conf (fw.sh) and PA_INBOUND"
  info "\"<HOST>:tcp/21,${FTP_PASV/:/-}\". If the scorer uses an anonymous login, set anonymous_enable=YES again."
}

# ============================================================================ splunk
secure_splunk() {
  begin "SPLUNK: query and management (8089)"
  local sh=/opt/splunk
  [ -x "$sh/bin/splunk" ] || { info "no Splunk server in $sh - skipped"; return 0; }
  local loc="$sh/etc/system/local"
  track "$loc/authentication.conf" "$loc/web.conf"
  ini_set "$loc/authentication.conf" splunk_auth lockoutUsers false        # red team can't lock out the scorer
  ini_set "$loc/authentication.conf" splunk_auth minPasswordLength 14
  ini_set "$loc/authentication.conf" splunk_auth minPasswordDigit 1
  ini_set "$loc/authentication.conf" splunk_auth minPasswordUppercase 1
  ini_set "$loc/authentication.conf" splunk_auth minPasswordLowercase 1
  ini_set "$loc/web.conf" settings tools.sessions.timeout 60
  local owner; owner="$(stat -c %U "$sh/etc")"
  chown "$owner": "$loc"/*.conf 2>/dev/null
  ok "set: no account lockout, password rules (new passwords), 60 min web sessions"
  info "TLS on 8089 left at Splunk's own default (no SSL / TLS 1.0 / 1.1 in Splunk 9 and 10)"
  info "allowRemoteLogin (8089 logins) left as it is: $(grep -h allowRemoteLogin "$loc/server.conf" 2>/dev/null || echo default)"
  info "Splunk web stays plain HTTP on 8000 (it can't serve both; the scorer's query check may use it)"
  if ! ask "Restart Splunk now to apply? Both Splunk checks are down for 1-2 minutes"; then
    info "Not restarted - the settings apply at the next Splunk restart"; return 0
  fi
  restart_splunk() { if systemctl cat Splunkd > /dev/null 2>&1; then systemctl restart Splunkd; else "$sh/bin/splunk" restart > /dev/null; fi; }
  restart_splunk
  local n mg web
  for n in $(seq 1 36); do
    mg="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 https://127.0.0.1:8089/services/server/info)"
    web="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1:8000/)"
    [ "$web" = 000 ] && web="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 https://127.0.0.1:8000/)"   # web SSL on
    [[ "$mg" =~ ^(200|401)$ ]] && [[ "$web" =~ ^(200|303)$ ]] && break
    sleep 5
  done
  if [[ "$mg" =~ ^(200|401)$ ]] && [[ "$web" =~ ^(200|303)$ ]]; then
    ok "Splunk back up: 8089 answers $mg (login required), 8000 answers $web"
  else
    bad "Splunk not answering after restart (8089: $mg, 8000: $web)"; undo; restart_splunk; return 1
  fi
}

# ------------------------------------------------------------------ run
echo "secure.sh on $(hostname) - $(date) - part: $PART"
want web && secure_web
want ssh && secure_ssh
want mail && secure_mail
want ftp && secure_ftp
want splunk && secure_splunk

h1 "SUMMARY"
if [ ${#ALL_CHANGED[@]} -gt 0 ]; then
  info "Changed files (backups in $BK):"
  printf '           %s\n' "${ALL_CHANGED[@]}"
  info "If fim.sh already runs on this box: sudo linux/fim.sh accept <file> for each of them"
fi
[ "$FAILED" -eq 0 ] && ok "done - now check Quotient: every service still up?" || bad "$FAILED part(s) failed or were undone - see above"
[ "$FAILED" -eq 0 ]
