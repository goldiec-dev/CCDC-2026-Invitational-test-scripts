#!/bin/bash
# rsyslog (mail logs) + Dovecot + Postfix; the container stops (and restarts) if one of them dies
rm -f /run/rsyslogd.pid
[ -x /usr/sbin/rsyslogd ] && /usr/sbin/rsyslogd -f /etc/rsyslog-ccdc.conf
# The image's Postfix helpers have the image's group IDs; the mounted user database has the host's
postfix set-permissions > /dev/null 2>&1
postfix check || { echo "postfix check failed"; exit 1; }
if [ -x /usr/sbin/dovecot ]; then /usr/sbin/dovecot || { echo "dovecot failed to start"; exit 1; }; fi
postfix start || { echo "postfix failed to start"; exit 1; }
stop() { postfix stop; [ -x /usr/bin/doveadm ] && doveadm stop 2> /dev/null; exit 0; }
trap stop TERM INT
while sleep 10 & wait $!; do
  pgrep -x master > /dev/null || { echo "postfix died"; exit 1; }
  if [ -x /usr/sbin/dovecot ]; then pgrep -x dovecot > /dev/null || { echo "dovecot died"; exit 1; }; fi
done
