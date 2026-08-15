#!/usr/bin/env bash
# LianYaoHu one-line uninstaller.
#
#   curl -fsSL https://lyh.maxlv.net/uninstall.sh | bash
#
# Tears down the root helper (LaunchDaemon on macOS, systemd service on Linux)
# and the hidden `_lianyaohu` group, then removes the `lianyaohu` and `lyh`
# binaries.
#
# Options (pass after `bash -s --` when piping):
#   --bin-dir DIR   Where the binaries were installed (default: /usr/local/bin).
#   --keep-helper   Leave the root helper in place; remove the binaries only.
#
# The helper teardown prefers the script the installed package shipped
# (/usr/local/libexec/lianyaohu-uninstall-helper.sh). When that is absent it
# fetches the teardown script pinned to a release tag; if no tag resolves it
# aborts rather than executing a moving branch tip.
#
# Environment overrides: LIANYAOHU_BIN_DIR, LIANYAOHU_REPO (default
# madeye/LianYaoHu), LIANYAOHU_REF (tag for the helper teardown script,
# default: the latest release tag; setting it forces the remote fetch).
set -euo pipefail

REPO="${LIANYAOHU_REPO:-madeye/LianYaoHu}"
REF="${LIANYAOHU_REF:-}"
BIN_DIR="${LIANYAOHU_BIN_DIR:-/usr/local/bin}"
REMOVE_HELPER=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin-dir) BIN_DIR="${2:?--bin-dir requires a path}"; shift 2 ;;
    --keep-helper) REMOVE_HELPER=0; shift ;;
    -h|--help) sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done

die() { echo "uninstall: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
have curl || die "curl is required"

LOCAL_TEARDOWN="/usr/local/libexec/lianyaohu-uninstall-helper.sh"

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
  if [[ -z "$REF" && -f "$LOCAL_TEARDOWN" ]]; then
    # Prefer the teardown script the installed package shipped: it matches the
    # installed helper and involves no network fetch at all.
    echo "uninstall: using the locally installed teardown script ${LOCAL_TEARDOWN}"
    bash "$LOCAL_TEARDOWN" || echo "uninstall: helper teardown reported an error; continuing"
  else
    # Pin the remote teardown script to a release tag rather than executing
    # whatever is on a branch tip at run time. Never fall back to a branch:
    # if no tag resolves, abort instead of running unpinned root-affecting
    # code (set LIANYAOHU_REF to a tag to override).
    if [[ -z "$REF" ]]; then
      location="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
        "https://github.com/${REPO}/releases/latest" 2>/dev/null || true)"
      REF="${location##*/}"
      [[ "$REF" == v* ]] || die "could not resolve the latest release tag for ${REPO}; \
refusing to run an unpinned teardown script. Set LIANYAOHU_REF to a release tag, or run \
scripts/uninstall-helper.sh from an extracted release package."
    fi
    helper_script="$(mktemp)"
    trap 'rm -f "$helper_script"' EXIT
    curl -fsSL "https://raw.githubusercontent.com/${REPO}/${REF}/scripts/uninstall-helper.sh" \
      -o "$helper_script" \
      || die "could not fetch uninstall-helper.sh at ${REF}; \
re-run with --keep-helper to remove the binaries only"
    bash "$helper_script" || echo "uninstall: helper teardown reported an error; continuing"
  fi
else
  echo "uninstall: keeping the root helper (--keep-helper)"
fi

echo "uninstall: removing binaries from ${BIN_DIR}"
as_root rm -f "${BIN_DIR}/lianyaohu" "${BIN_DIR}/lyh"

echo "uninstall: done"
