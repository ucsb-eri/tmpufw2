#!/bin/sh
set -eu
cd "$(dirname "$0")"
test "$(id -u)" = 0 || { echo 'Run with sudo' >&2; exit 1; }
test -x /usr/sbin/ufw || { echo 'Install ufw first' >&2; exit 1; }
command -v python3 >/dev/null
if ! python3 -c 'import parsedatetime' 2>/dev/null; then
  echo 'Optional: apt install python3-parsedatetime for expressions such as tomorrow'
fi
command -v systemctl >/dev/null
install -m 0755 tmpufw.py /usr/local/sbin/tmpufw
install -d -m 0700 /var/lib/tmpufw
install -d -m 0755 /etc/tmpufw
python3 configure_config.py
install -m 0644 systemd/tmpufw-clean.service /etc/systemd/system/
python3 configure_timer.py
systemctl daemon-reload
systemctl enable --now tmpufw-clean.timer
systemctl restart tmpufw-clean.timer
echo 'Installed. No firewall rules were changed.'
