#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LABEL="io.github.madeye.lianyaohu.helper"
BIN="/usr/local/libexec/lianyaohu-helper"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
GROUP_NAME="_lianyaohu"
GROUP_GID="2000000"

cargo build --release -p lianyaohu-helper

sudo install -d -m 755 /usr/local/libexec
sudo install -m 755 "$ROOT/target/release/lianyaohu-helper" "$BIN"

if sudo dscl . -read "/Groups/${GROUP_NAME}" PrimaryGroupID >/tmp/lianyaohu-group.$$ 2>/dev/null; then
  existing_gid="$(awk '/PrimaryGroupID:/ {print $2; exit}' /tmp/lianyaohu-group.$$)"
  rm -f /tmp/lianyaohu-group.$$
  if [[ "$existing_gid" != "$GROUP_GID" ]]; then
    echo "${GROUP_NAME} exists with gid ${existing_gid}, expected ${GROUP_GID}" >&2
    exit 1
  fi
else
  rm -f /tmp/lianyaohu-group.$$
  conflicting_group="$(sudo dscl . -list /Groups PrimaryGroupID | awk -v gid="$GROUP_GID" '$2 == gid {print $1; exit}')"
  if [[ -n "$conflicting_group" ]]; then
    echo "gid ${GROUP_GID} is already assigned to group ${conflicting_group}" >&2
    exit 1
  fi
  sudo dscl . -create "/Groups/${GROUP_NAME}"
  sudo dscl . -create "/Groups/${GROUP_NAME}" PrimaryGroupID "$GROUP_GID"
  sudo dscl . -create "/Groups/${GROUP_NAME}" Password "*"
  sudo dscl . -create "/Groups/${GROUP_NAME}" RealName "LianYaoHu sandbox network group"
  sudo dscl . -create "/Groups/${GROUP_NAME}" IsHidden 1
fi

tmp_plist="$(mktemp)"
cat >"$tmp_plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${BIN}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>/var/log/lianyaohu-helper.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/lianyaohu-helper.err.log</string>
</dict>
</plist>
PLIST

sudo install -m 644 "$tmp_plist" "$PLIST"
rm -f "$tmp_plist"

sudo launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
sudo launchctl bootstrap system "$PLIST"
sudo launchctl enable "system/${LABEL}"
sudo launchctl kickstart -k "system/${LABEL}"

echo "installed ${LABEL}"
