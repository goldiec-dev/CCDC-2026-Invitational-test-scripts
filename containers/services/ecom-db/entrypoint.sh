#!/bin/sh
# The host's data directory and config, the same server version, as the mysql user
for d in /run/mysqld /run/mariadb; do mkdir -p "$d" && chown mysql:mysql "$d" 2>/dev/null; done
for b in /usr/libexec/mariadbd /usr/libexec/mysqld /usr/sbin/mariadbd /usr/sbin/mysqld; do
  [ -x "$b" ] && exec "$b" --user=mysql
done
echo "no MariaDB/MySQL server binary in the image"; exit 1
