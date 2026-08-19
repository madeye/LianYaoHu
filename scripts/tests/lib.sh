#!/usr/bin/env bash
# Shared helpers for the shell-script test suites in this directory.
#
# Sourced, never executed. Written for bash 3.2 so the suites run on the
# stock /bin/bash of macOS (which is what `curl ... | bash` uses there).
#
# A suite defines `test_*` functions and calls `run_tests` last. Each test runs
# in a subshell with `set -e`, a fresh $TEST_WORKDIR, and its output captured
# and printed only on failure.

# Resolve the repository root from this file's location.
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$TESTS_DIR/../.." && pwd)"
export TESTS_DIR REPO_ROOT

# A deliberately small PATH: it holds the stubs plus the system utilities the
# scripts under test legitimately use, and excludes /usr/local/bin and
# /opt/homebrew/bin so a real `cosign` on the developer's machine cannot make
# the "cosign is not installed" cases pass for the wrong reason.
SANDBOX_SYSTEM_PATH="/usr/bin:/bin:/usr/sbin:/sbin"

fail() {
  echo "ASSERTION FAILED: $*" >&2
  exit 1
}

assert_eq() {
  # assert_eq <expected> <actual> <message>
  [[ "$1" == "$2" ]] || fail "$3: expected '$1', got '$2'"
}

assert_contains() {
  # assert_contains <haystack> <needle> <message>
  case "$1" in
    *"$2"*) : ;;
    *) fail "$3: expected to find '$2' in:
$1" ;;
  esac
}

assert_not_contains() {
  case "$1" in
    *"$2"*) fail "$3: did not expect to find '$2' in:
$1" ;;
    *) : ;;
  esac
}

assert_file_contains() {
  # assert_file_contains <file> <fixed-string> <message>
  # Reports the path rather than dumping the whole file.
  grep -qF -- "$2" "$1" || fail "$3: expected '$2' in $1"
}

assert_file_exists() {
  [[ -e "$1" ]] || fail "${2:-expected file to exist}: $1"
}

assert_file_absent() {
  [[ ! -e "$1" ]] || fail "${2:-expected file to be absent}: $1"
}

assert_success() {
  # assert_success <status> <message> [output]
  [[ "$1" == "0" ]] || fail "$2: expected success, got exit status $1
${3:-}"
}

assert_failure() {
  # assert_failure <status> <message> [output]
  [[ "$1" != "0" ]] || fail "$2: expected a non-zero exit status
${3:-}"
}

# The Sigstore identity install.sh enforces, read out of install.sh itself (so
# nothing here can drift from what installs actually require) with ${REPO}
# expanded for the given repository.
install_identity_regexp() {
  # REPO is what the extracted "${REPO}" placeholder expands to in the eval.
  # shellcheck disable=SC2034
  local REPO="$1" raw
  raw="$(grep -o -- '--certificate-identity-regexp "[^"]*"' "$REPO_ROOT/scripts/install.sh" | head -1)"
  raw="${raw#--certificate-identity-regexp \"}"
  raw="${raw%\"}"
  [[ -n "$raw" ]] || fail "could not find --certificate-identity-regexp in scripts/install.sh"
  eval "printf '%s' \"$raw\""
}

# The release target triple install.sh derives from uname, mirroring its logic.
host_target() {
  case "$(uname -s)/$(uname -m)" in
    Darwin/arm64) echo "aarch64-apple-darwin" ;;
    Linux/x86_64) echo "x86_64-unknown-linux-gnu" ;;
    *) return 1 ;;
  esac
}

sha256_of_file_line() {
  # Emit "<digest>  <name>" for a file, using whichever tool exists.
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi
}

# --- per-test fixtures -----------------------------------------------------

# Create the stub PATH directory and the stub state directory used by the
# curl/cosign stubs. Sets STUB_BIN, STUB_STATE, SANDBOX_PATH and BIN_DIR.
setup_stubs() {
  # Never inherit the caller's configuration: a developer (or CI) with these
  # set in the environment must not change what the tests exercise.
  unset LIANYAOHU_VERSION LIANYAOHU_BIN_DIR LIANYAOHU_NO_HELPER LIANYAOHU_REPO
  unset LIANYAOHU_REQUIRE_SIGNATURE LIANYAOHU_SKIP_SIGNATURE LIANYAOHU_REF
  unset LIANYAOHU_LOCAL_TEARDOWN
  STUB_BIN="$TEST_WORKDIR/bin"
  STUB_STATE="$TEST_WORKDIR/state"
  BIN_DIR="$TEST_WORKDIR/install-bin"
  mkdir -p "$STUB_BIN" "$STUB_STATE/files" "$BIN_DIR"
  : >"$STUB_STATE/curl.log"
  : >"$STUB_STATE/cosign.log"
  cp "$TESTS_DIR/stubs/curl" "$STUB_BIN/curl"
  chmod 755 "$STUB_BIN/curl"
  SANDBOX_PATH="$STUB_BIN:$SANDBOX_SYSTEM_PATH"
  export LYH_STUB_STATE="$STUB_STATE"
}

# Put the cosign stub on the stub PATH. Optional argument: the exit status the
# stub should return (default 0).
enable_cosign_stub() {
  cp "$TESTS_DIR/stubs/cosign" "$STUB_BIN/cosign"
  chmod 755 "$STUB_BIN/cosign"
  echo "${1:-0}" >"$STUB_STATE/cosign_exit"
}

# Make the fake "latest release" redirect resolve to a tag.
set_latest_tag() {
  printf '%s' "https://github.com/madeye/LianYaoHu/releases/tag/$1" >"$STUB_STATE/latest_location"
}

# Build a release tarball + checksum the curl stub will serve.
# Usage: make_release_fixture <version-number>   e.g. make_release_fixture 9.9.9
make_release_fixture() {
  local version="$1" target pkg root
  target="$(host_target)"
  pkg="lianyaohu-${version}-${target}"
  root="$TEST_WORKDIR/fixture"
  rm -rf "$root"
  mkdir -p "$root/$pkg/bin" "$root/$pkg/scripts"
  printf '#!/bin/sh\necho "lianyaohu fixture"\n' >"$root/$pkg/bin/lianyaohu"
  printf '#!/bin/sh\necho "lyh fixture"\n' >"$root/$pkg/bin/lyh"
  chmod 755 "$root/$pkg/bin/lianyaohu" "$root/$pkg/bin/lyh"
  cat >"$root/$pkg/scripts/install-helper.sh" <<'HELPER'
#!/usr/bin/env bash
# Fixture stand-in for the real root helper installer: records that it ran and
# which binary install.sh pointed it at, and touches nothing on the system.
echo "${LIANYAOHU_HELPER_BINARY:-<unset>}" >>"${LYH_STUB_STATE}/helper.log"
HELPER
  chmod 755 "$root/$pkg/scripts/install-helper.sh"
  tar -C "$root" -czf "$STUB_STATE/files/${pkg}.tar.gz" "$pkg"
  (
    cd "$STUB_STATE/files"
    sha256_of_file_line "${pkg}.tar.gz" >"${pkg}.tar.gz.sha256"
  )
  RELEASE_PKG="$pkg"
}

# Pretend the release also carries a Sigstore bundle asset.
add_bundle_fixture() {
  printf 'fixture cosign bundle\n' >"$STUB_STATE/files/${RELEASE_PKG}.tar.gz.cosign.bundle"
}

# Run a repository script with the sandboxed PATH and capture combined output
# into $OUTPUT and the exit status into $STATUS.
run_script() {
  local script="$1"
  shift
  set +e
  # OUTPUT/STATUS are read by the calling test.
  # shellcheck disable=SC2034
  OUTPUT="$(PATH="$SANDBOX_PATH" "$script" "$@" 2>&1)"
  # shellcheck disable=SC2034
  STATUS=$?
  set -e
}

curl_log() { cat "$STUB_STATE/curl.log"; }
cosign_log() { cat "$STUB_STATE/cosign.log"; }

# --- runner ----------------------------------------------------------------

run_tests() {
  local suite names name status pass=0 failed=0 out
  suite="$(basename "$0")"
  names="$(declare -F | awk '{print $3}' | grep '^test_' | sort)"
  if [[ -z "$names" ]]; then
    echo "$suite: no test_* functions defined" >&2
    exit 1
  fi
  for name in $names; do
    if [[ -n "${TEST_FILTER:-}" ]]; then
      case "$name" in
        *"$TEST_FILTER"*) : ;;
        *) continue ;;
      esac
    fi
    TEST_WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/lyh-shtest.XXXXXX")"
    out="$TEST_WORKDIR/.test-output"
    set +e
    (
      set -e
      cd "$TEST_WORKDIR"
      "$name"
    ) >"$out" 2>&1
    status=$?
    set -e
    if [[ "$status" == "0" ]]; then
      pass=$((pass + 1))
      printf 'ok   %s :: %s\n' "$suite" "$name"
    else
      failed=$((failed + 1))
      printf 'FAIL %s :: %s\n' "$suite" "$name"
      sed 's/^/       /' "$out"
    fi
    if [[ -n "${KEEP_TEST_WORKDIR:-}" ]]; then
      printf '     workdir kept: %s\n' "$TEST_WORKDIR"
    else
      rm -rf "$TEST_WORKDIR"
    fi
  done
  printf '%s: %d passed, %d failed\n' "$suite" "$pass" "$failed"
  [[ "$failed" == "0" ]]
}
