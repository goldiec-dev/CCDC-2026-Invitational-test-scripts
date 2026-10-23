#!/bin/sh
mkdir -p /var/run/vsftpd/empty /usr/share/empty
for c in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do [ -f "$c" ] && exec vsftpd "$c"; done
echo "no vsftpd.conf"; exit 1
