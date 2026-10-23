#!/bin/bash
# Start the host's Splunk as its usual user, stop it cleanly when the container stops
SH=/opt/splunk
U="$(stat -c %U "$SH/etc")"
sp() { if [ "$U" = root ]; then "$SH/bin/splunk" "$@"; else runuser -u "$U" -- "$SH/bin/splunk" "$@"; fi; }
sp start --accept-license --answer-yes --no-prompt || { echo "splunk start failed"; exit 1; }
stop() { sp stop; exit 0; }
trap stop TERM INT
while sleep 15 & wait $!; do
  pgrep -f "splunkd" > /dev/null || { echo "splunkd died"; exit 1; }
done
