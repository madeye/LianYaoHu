#!/usr/bin/env bash
# LianYaoHu one-line uninstaller.
#
#   curl -fsSL https://raw.githubusercontent.com/madeye/LianYaoHu/main/scripts/uninstall.sh | bash
#
# Tears down the root helper (LaunchDaemon on macOS, systemd service on Linux)
# and the hidden `_lianyaohu` group, then removes the `lianyaohu` and `lyh`
# binaries.
#
# Options (pass after `bash -s --` when piping):
#   --bin-dir DIR   Where the binaries were installed (default: /usr/local/bin).
#   --keep-helper   Leave the root helper in place; remove the binaries only.
#
# Environment overrides: LIANYAOHU_BIN_DIR, LIANYAOHU_REPO (default
# madeye/LianYaoHu), LIANYAOHU_REF (branch/tag for the helper teardown script,
# default main).
set -euo pipefail

REPO="${LIANYAOHU_REPO:-madeye/LianYaoHu}"
REF="${LIANYAOHU_REF:-main}"
BIN_DIR="${LIANYAOHU_BIN_DIR:-/usr/local/bin}"
REMOVE_HELPER=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-dir) BIN_DIR="${2:?--bin-dir requires a path}"; shift 2 ;;
    --keep-helper) REMOVE_HELPER=0; shift ;;
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }
have curl || { echo "uninstall: curl is required" >&2; exit 1; }

as_root() {
  if [[ -w "$BIN_DIR" ]]; then
    "$@"
  elif have sudo; then
    sudo "$@"
  else
    echo "uninstall: cannot write to ${BIN_DIR} and sudo is unavailable" >&2
    return 1
  fi
}

if [[ "$REMOVE_HELPER" == "1" ]]; then
  echo "uninstall: removing the root helper (may prompt for sudo)"
  # Reuse the canonical helper-teardown script so this stays in one place.
  helper_script="$(mktemp)"
  trap 'rm -f "$helper_script"' EXIT
  if curl -fsSL "https://raw.githubusercontent.com/${REPO}/${REF}/scripts/uninstall-helper.sh" \
      -o "$helper_script"; then
    bash "$helper_script" || echo "uninstall: helper teardown reported an error; continuing"
  else
    echo "uninstall: could not fetch uninstall-helper.sh; skipping helper teardown" >&2
  fi
else
  echo "uninstall: keeping the root helper (--keep-helper)"
fi

echo "uninstall: removing binaries from ${BIN_DIR}"
as_root rm -f "${BIN_DIR}/lianyaohu" "${BIN_DIR}/lyh"

echo "uninstall: done"
