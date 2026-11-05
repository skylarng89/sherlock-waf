#!/bin/sh
# Runs before the package is removed (not on upgrade).
set -eu
case "${1:-}" in
	remove | 0)
		if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
			systemctl stop sherlock.service || true
			systemctl disable sherlock.service >/dev/null 2>&1 || true
		fi
		;;
esac
