#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LABEL="io.github.madeye.lianyaohu.helper"
BIN="/usr/local/libexec/lianyaohu"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
SERVICE="/etc/systemd/system/${LABEL}.service"
GROUP_NAME="_lianyaohu"
GROUP_GID="2000000"
OS="$(uname -s)"

if [[ -n "${LIANYAOHU_HELPER_BINARY:-}" ]]; then
  HELPER_BINARY="$LIANYAOHU_HELPER_BINARY"
elif [[ -x "$ROOT/bin/lianyaohu" && ! -f "$ROOT/Cargo.toml" ]]; then
  HELPER_BINARY="$ROOT/bin/lianyaohu"
elif [[ -x "$ROOT/bin/lyh" && ! -f "$ROOT/Cargo.toml" ]]; then
  HELPER_BINARY="$ROOT/bin/lyh"
else
  cargo build --release -p lianyaohu-app
  HELPER_BINARY="$ROOT/target/release/lianyaohu"
fi

if [[ "$OS" == "Linux" ]]; then
  sudo install -d -m 755 /usr/local/libexec
  sudo install -m 755 "$HELPER_BINARY" "$BIN"

  if getent group "$GROUP_NAME" >/tmp/lianyaohu-group.$$ 2>/dev/null; then
    existing_gid="$(awk -F: '{print $3; exit}' /tmp/lianyaohu-group.$$)"
    rm -f /tmp/lianyaohu-group.$$
    if [[ "$existing_gid" != "$GROUP_GID" ]]; then
      echo "${GROUP_NAME} exists with gid ${existing_gid}, expected ${GROUP_GID}" >&2
      exit 1
    fi
  else
    rm -f /tmp/lianyaohu-group.$$
    conflicting_group="$(getent group "$GROUP_GID" 2>/dev/null | awk -F: '{print $1; exit}' || true)"
    if [[ -n "$conflicting_group" ]]; then
      echo "gid ${GROUP_GID} is already assigned to group ${conflicting_group}" >&2
      exit 1
    fi
    sudo groupadd -g "$GROUP_GID" "$GROUP_NAME"
  fi

  tmp_service="$(mktemp)"
  cat >"$tmp_service" <<SERVICE
[Unit]
Description=LianYaoHu root firewall helper
After=network-online.target

[Service]
Type=simple
ExecStart=${BIN} helper
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
SERVICE

  sudo install -m 644 "$tmp_service" "$SERVICE"
  rm -f "$tmp_service"

  sudo systemctl daemon-reload
  sudo systemctl enable --now "${LABEL}.service"
  sudo systemctl restart "${LABEL}.service"
  for _ in {1..50}; do
    if [[ -S /var/run/lianyaohu-helper.sock ]]; then
      break
    fi
    sleep 0.1
  done
  if [[ ! -S /var/run/lianyaohu-helper.sock ]]; then
    sudo systemctl status --no-pager "${LABEL}.service" || true
    echo "helper socket did not appear: /var/run/lianyaohu-helper.sock" >&2
    exit 1
  fi

  echo "installed ${LABEL}"
  exit 0
fi

if [[ "$OS" != "Darwin" ]]; then
  echo "unsupported OS: ${OS}" >&2
  exit 1
fi

sudo install -d -m 755 /usr/local/libexec
sudo install -m 755 "$HELPER_BINARY" "$BIN"
# Remove the split-binary helper from installs that predate the merged binary.
sudo rm -f /usr/local/libexec/lianyaohu-helper

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
    <string>helper</string>
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
