#!/bin/sh
# php-fpm (if this box uses it) in the background, httpd in the foreground
mkdir -p /run/httpd /run/php-fpm
if command -v php-fpm > /dev/null 2>&1 && [ -f /etc/php-fpm.conf ]; then
  php-fpm --daemonize || { echo "php-fpm failed to start"; exit 1; }
fi
exec httpd -DFOREGROUND
