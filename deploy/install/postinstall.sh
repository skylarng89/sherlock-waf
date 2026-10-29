#!/bin/sh
# Runs after the package is installed or upgraded (deb and rpm).
set -eu

if ! getent group sherlock >/dev/null 2>&1; then
	groupadd --system sherlock
fi
if ! getent passwd sherlock >/dev/null 2>&1; then
	useradd --system --gid sherlock --home-dir /var/lib/sherlock --shell /usr/sbin/nologin --comment "Sherlock WAF" sherlock
fi

install -d -m 0700 -o sherlock -g sherlock /var/lib/sherlock
install -d -m 0750 -o root -g sherlock /etc/sherlock
if [ ! -e /etc/sherlock/sherlock.env ]; then
	install -m 0640 -o root -g sherlock /usr/share/sherlock-waf/sherlock.env /etc/sherlock/sherlock.env
fi

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true
	systemctl enable sherlock.service >/dev/null 2>&1 || true
	# A restart picks up a new binary; on a first install this is the start.
	systemctl restart sherlock.service || true
fi

cat <<'MSG'

Sherlock WAF is installed.

  1. Create the first administrator:   sudo -u sherlock sherlock user create --admin <name>
     (or open the dashboard and use the one-time token in /var/lib/sherlock/setup-token)
  2. Open the control plane:            https://127.0.0.1:9443  (the certificate is self-signed;
     its fingerprint is in `journalctl -u sherlock`)

MSG
