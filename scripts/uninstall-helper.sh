#!/usr/bin/env bash
set -euo pipefail

LABEL="io.github.madeye.lianyaohu.helper"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
GROUP_NAME="_lianyaohu"
GROUP_GID="2000000"

sudo launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
sudo rm -f "$PLIST"
sudo rm -f /usr/local/libexec/lianyaohu-helper
sudo rm -f /var/run/lianyaohu-helper.sock

if sudo dscl . -read "/Groups/${GROUP_NAME}" PrimaryGroupID >/tmp/lianyaohu-group.$$ 2>/dev/null; then
  existing_gid="$(awk '/PrimaryGroupID:/ {print $2; exit}' /tmp/lianyaohu-group.$$)"
  rm -f /tmp/lianyaohu-group.$$
  if [[ "$existing_gid" == "$GROUP_GID" ]]; then
    sudo dscl . -delete "/Groups/${GROUP_NAME}" >/dev/null 2>&1 || true
  fi
else
  rm -f /tmp/lianyaohu-group.$$
fi

echo "uninstalled ${LABEL}"
