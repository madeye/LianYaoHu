#!/usr/bin/env bash
set -euo pipefail

LABEL="io.github.madeye.lianyaohu.helper"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
SERVICE="/etc/systemd/system/${LABEL}.service"
GROUP_NAME="_lianyaohu"
GROUP_GID="2000000"
OS="$(uname -s)"

tmp_group="$(mktemp)"
trap 'rm -f "$tmp_group"' EXIT

if [[ "$OS" == "Linux" ]]; then
  sudo systemctl disable --now "${LABEL}.service" >/dev/null 2>&1 || true
  sudo rm -f "$SERVICE"
  sudo systemctl daemon-reload >/dev/null 2>&1 || true
  sudo rm -f /usr/local/libexec/lianyaohu
  sudo rm -f /var/run/lianyaohu-helper.sock

  if getent group "$GROUP_NAME" >"$tmp_group" 2>/dev/null; then
    existing_gid="$(awk -F: '{print $3; exit}' "$tmp_group")"
    if [[ "$existing_gid" == "$GROUP_GID" ]]; then
      sudo groupdel "$GROUP_NAME" >/dev/null 2>&1 || true
    fi
  fi

  echo "uninstalled ${LABEL}"
  exit 0
fi

if [[ "$OS" != "Darwin" ]]; then
  echo "unsupported OS: ${OS}" >&2
  exit 1
fi

sudo launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
sudo rm -f "$PLIST"
sudo rm -f /usr/local/libexec/lianyaohu
sudo rm -f /usr/local/libexec/lianyaohu-helper
sudo rm -f /var/run/lianyaohu-helper.sock

if sudo dscl . -read "/Groups/${GROUP_NAME}" PrimaryGroupID >"$tmp_group" 2>/dev/null; then
  existing_gid="$(awk '/PrimaryGroupID:/ {print $2; exit}' "$tmp_group")"
  if [[ "$existing_gid" == "$GROUP_GID" ]]; then
    sudo dscl . -delete "/Groups/${GROUP_NAME}" >/dev/null 2>&1 || true
  fi
fi

echo "uninstalled ${LABEL}"
