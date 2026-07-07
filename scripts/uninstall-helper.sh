#!/usr/bin/env bash
set -euo pipefail

LABEL="io.github.madeye.lianyaohu.helper"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"

sudo launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
sudo rm -f "$PLIST"
sudo rm -f /usr/local/libexec/lianyaohu-helper
sudo rm -f /var/run/lianyaohu-helper.sock

echo "uninstalled ${LABEL}"
