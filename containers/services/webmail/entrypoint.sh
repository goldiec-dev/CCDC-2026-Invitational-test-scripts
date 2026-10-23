#!/bin/bash
# Apache in the foreground with the host's own Apache configuration
. /etc/apache2/envvars
mkdir -p "$APACHE_RUN_DIR" "$APACHE_LOCK_DIR" "$APACHE_LOG_DIR"
rm -f "$APACHE_PID_FILE"
exec apache2 -DFOREGROUND
