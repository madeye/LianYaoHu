#!/usr/bin/env bash
# LianYaoHu one-line installer.
#
#   curl -fsSL https://lyh.maxlv.net/install.sh | bash
#
# Downloads the latest release for this platform, verifies its SHA-256, installs
# the `lianyaohu` and `lyh` binaries into a PATH directory, and installs the
# root firewall helper (LaunchDaemon on macOS, systemd service on Linux).
#
# Options (pass after `bash -s --` when piping, e.g.
#   curl -fsSL .../install.sh | bash -s -- --no-helper):
#   --version vX.Y.Z   Install a specific release tag (default: latest).
#   --bin-dir DIR      Where to install the binaries (default: /usr/local/bin).
#   --no-helper        Install the binaries only; skip the root helper.
#
# Environment overrides: LIANYAOHU_VERSION, LIANYAOHU_BIN_DIR,
# LIANYAOHU_NO_HELPER=1, LIANYAOHU_REPO (default madeye/LianYaoHu).
set -euo pipefail

REPO="${LIANYAOHU_REPO:-madeye/LianYaoHu}"
VERSION="${LIANYAOHU_VERSION:-latest}"
BIN_DIR="${LIANYAOHU_BIN_DIR:-/usr/local/bin}"
INSTALL_HELPER=1
[[ -n "${LIANYAOHU_NO_HELPER:-}" ]] && INSTALL_HELPER=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="${2:?--version requires a tag}"; shift 2 ;;
    --bin-dir) BIN_DIR="${2:?--bin-dir requires a path}"; shift 2 ;;
    --no-helper) INSTALL_HELPER=0; shift ;;
    -h|--help) sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 64 ;;
  esac
done

die() { echo "install: $*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

have curl || die "curl is required"
have tar || die "tar is required"

os="$(uname -s)"
arch="$(uname -m)"
case "${os}/${arch}" in
  Darwin/arm64) target="aarch64-apple-darwin" ;;
  Linux/x86_64) target="x86_64-unknown-linux-gnu" ;;
  *)
    die "no prebuilt release for ${os}/${arch}; build from source with \
'cargo install --path crates/lianyaohu-app' (see ${REPO})"
    ;;
esac

# Resolve the release tag. GitHub redirects /releases/latest to the tagged URL;
# read the tag from the Location header so we avoid a JSON dependency.
if [[ "$VERSION" == "latest" ]]; then
  location="$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
    "https://github.com/${REPO}/releases/latest")" \
    || die "could not reach GitHub to resolve the latest release"
  VERSION="${location##*/}"
  [[ "$VERSION" == v* ]] || die "could not parse latest release tag from '${location}'"
fi
version_number="${VERSION#v}"

package="lianyaohu-${version_number}-${target}"
base_url="https://github.com/${REPO}/releases/download/${VERSION}"

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT

echo "install: downloading ${package}.tar.gz (${VERSION})"
curl -fsSL "${base_url}/${package}.tar.gz" -o "${workdir}/${package}.tar.gz" \
  || die "download failed: ${base_url}/${package}.tar.gz"
curl -fsSL "${base_url}/${package}.tar.gz.sha256" -o "${workdir}/${package}.tar.gz.sha256" \
  || die "checksum download failed"

echo "install: verifying checksum"
(
  cd "$workdir"
  if have sha256sum; then
    sha256sum -c "${package}.tar.gz.sha256"
  elif have shasum; then
    shasum -a 256 -c "${package}.tar.gz.sha256"
  else
    die "need sha256sum or shasum to verify the download"
  fi
) >/dev/null || die "checksum verification failed"

tar -C "$workdir" -xzf "${workdir}/${package}.tar.gz"
stage="${workdir}/${package}"
[[ -x "${stage}/bin/lianyaohu" && -x "${stage}/bin/lyh" ]] \
  || die "release package is missing the expected binaries"

# Install with sudo only when the destination is not writable by this user.
as_root() {
  if [[ -w "$BIN_DIR" ]] || { [[ ! -e "$BIN_DIR" ]] && [[ -w "$(dirname "$BIN_DIR")" ]]; }; then
    "$@"
  elif have sudo; then
    sudo "$@"
  else
    die "cannot write to ${BIN_DIR} and sudo is unavailable"
  fi
}

echo "install: installing binaries into ${BIN_DIR}"
as_root install -d -m 755 "$BIN_DIR"
as_root install -m 755 "${stage}/bin/lianyaohu" "${BIN_DIR}/lianyaohu"
as_root install -m 755 "${stage}/bin/lyh" "${BIN_DIR}/lyh"

if [[ "$INSTALL_HELPER" == "1" ]]; then
  echo "install: installing the root helper (may prompt for sudo)"
  LIANYAOHU_HELPER_BINARY="${stage}/bin/lianyaohu" bash "${stage}/scripts/install-helper.sh"
else
  echo "install: skipping root helper (--no-helper); firewall enforcement needs it"
fi

echo "install: done — ${VERSION} installed to ${BIN_DIR}/lianyaohu (alias: lyh)"
case ":${PATH}:" in
  *":${BIN_DIR}:"*) : ;;
  *) echo "install: note: ${BIN_DIR} is not on your PATH; add it to use 'lianyaohu'/'lyh' directly" ;;
esac
