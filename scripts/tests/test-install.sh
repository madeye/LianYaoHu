#!/usr/bin/env bash
# End-to-end tests for scripts/install.sh.
#
# The real script runs unmodified: `curl` and `cosign` are shadowed by stubs on
# a sandboxed PATH, the release tarball is a fixture built at test time, and the
# binaries are installed into a temporary --bin-dir (so no sudo, and nothing
# touches the system).
set -euo pipefail

# shellcheck source=scripts/tests/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

INSTALL_SH="$REPO_ROOT/scripts/install.sh"
IDENTITY_REGEXP='^https://github.com/madeye/LianYaoHu/\.github/workflows/release\.yml@refs/tags/'
OIDC_ISSUER='https://token.actions.githubusercontent.com'

if ! host_target >/dev/null; then
  echo "SKIP test-install.sh: no release target for $(uname -s)/$(uname -m)"
  exit 0
fi

prepare() {
  # Common fixture: release v9.9.9 exists and is downloadable.
  setup_stubs
  make_release_fixture 9.9.9
}

test_installs_binaries_and_resolves_the_latest_tag() {
  prepare
  set_latest_tag v9.9.9

  run_script "$INSTALL_SH" --bin-dir "$BIN_DIR" --no-helper
  assert_success "$STATUS" "install should succeed" "$OUTPUT"

  assert_file_exists "$BIN_DIR/lianyaohu" "lianyaohu binary installed"
  assert_file_exists "$BIN_DIR/lyh" "lyh alias installed"
  [[ -x "$BIN_DIR/lianyaohu" && -x "$BIN_DIR/lyh" ]] || fail "installed binaries must be executable"

  # The tag resolved from the redirect must be the one actually downloaded.
  assert_contains "$(curl_log)" \
    "https://github.com/madeye/LianYaoHu/releases/download/v9.9.9/${RELEASE_PKG}.tar.gz" \
    "downloads the resolved tag's asset"
}

test_warns_when_cosign_is_missing() {
  prepare

  run_script "$INSTALL_SH" --version v9.9.9 --bin-dir "$BIN_DIR" --no-helper
  assert_success "$STATUS" "checksum-only install should succeed" "$OUTPUT"
  assert_contains "$OUTPUT" "cosign is not installed" "warns loudly about the missing verifier"
  assert_contains "$OUTPUT" "integrity only, not authenticity" "explains what the checksum does not prove"
}

test_missing_cosign_is_fatal_when_a_signature_is_required() {
  prepare
  export LIANYAOHU_REQUIRE_SIGNATURE=1

  run_script "$INSTALL_SH" --version v9.9.9 --bin-dir "$BIN_DIR" --no-helper
  assert_failure "$STATUS" "install must refuse to proceed unverified" "$OUTPUT"
  assert_contains "$OUTPUT" "cosign is not installed" "explains why it refused"
  assert_file_absent "$BIN_DIR/lianyaohu" "nothing may be installed"
}

test_verifies_the_signature_with_the_tag_anchored_identity() {
  prepare
  add_bundle_fixture
  enable_cosign_stub 0

  run_script "$INSTALL_SH" --version v9.9.9 --bin-dir "$BIN_DIR" --no-helper
  assert_success "$STATUS" "a verifying signature must install" "$OUTPUT"

  local log
  log="$(cosign_log)"
  assert_contains "$log" "verify-blob" "cosign is asked to verify the blob"
  assert_contains "$log" "$IDENTITY_REGEXP" "identity is pinned to this repo's release workflow on a tag ref"
  assert_contains "$log" "--certificate-oidc-issuer $OIDC_ISSUER" "issuer is pinned to GitHub Actions OIDC"
  assert_contains "$log" "${RELEASE_PKG}.tar.gz.cosign.bundle" "verifies against the downloaded bundle"
  assert_file_exists "$BIN_DIR/lianyaohu" "binaries are installed after verification"
}

test_identity_regexp_follows_the_repo_override() {
  prepare
  add_bundle_fixture
  enable_cosign_stub 0
  export LIANYAOHU_REPO="example/Fork"

  run_script "$INSTALL_SH" --version v9.9.9 --bin-dir "$BIN_DIR" --no-helper
  assert_success "$STATUS" "install from a fork should succeed" "$OUTPUT"
  assert_contains "$(cosign_log)" \
    '^https://github.com/example/Fork/\.github/workflows/release\.yml@refs/tags/' \
    "the pinned identity follows LIANYAOHU_REPO"
}

test_failing_signature_aborts_the_install() {
  prepare
  add_bundle_fixture
  enable_cosign_stub 1

  run_script "$INSTALL_SH" --version v9.9.9 --bin-dir "$BIN_DIR" --no-helper
  assert_failure "$STATUS" "a present-but-invalid signature must abort" "$OUTPUT"
  assert_contains "$OUTPUT" "signature verification failed" "says why it aborted"
  assert_file_absent "$BIN_DIR/lianyaohu" "nothing may be installed"
  assert_file_absent "$BIN_DIR/lyh" "nothing may be installed"
}

test_missing_bundle_warns_but_installs() {
  prepare
  enable_cosign_stub 0

  run_script "$INSTALL_SH" --version v9.9.9 --bin-dir "$BIN_DIR" --no-helper
  assert_success "$STATUS" "an unsigned release still installs by default" "$OUTPUT"
  assert_contains "$OUTPUT" "no Sigstore signature bundle" "warns that the release is unsigned"
  assert_contains "$OUTPUT" "LIANYAOHU_REQUIRE_SIGNATURE=1" "points at the strict mode"
  assert_eq "" "$(cosign_log)" "cosign is not asked to verify a bundle that does not exist"
}

test_missing_bundle_is_fatal_when_a_signature_is_required() {
  prepare
  enable_cosign_stub 0
  export LIANYAOHU_REQUIRE_SIGNATURE=1

  run_script "$INSTALL_SH" --version v9.9.9 --bin-dir "$BIN_DIR" --no-helper
  assert_failure "$STATUS" "strict mode must refuse an unsigned release" "$OUTPUT"
  assert_contains "$OUTPUT" "no signature bundle to verify" "says why it refused"
  assert_file_absent "$BIN_DIR/lianyaohu" "nothing may be installed"
}

test_skip_signature_opt_out_bypasses_cosign() {
  prepare
  add_bundle_fixture
  enable_cosign_stub 1 # would fail if it were ever called
  export LIANYAOHU_SKIP_SIGNATURE=1

  run_script "$INSTALL_SH" --version v9.9.9 --bin-dir "$BIN_DIR" --no-helper
  assert_success "$STATUS" "the explicit opt-out installs without verifying" "$OUTPUT"
  assert_contains "$OUTPUT" "LIANYAOHU_SKIP_SIGNATURE=1" "the opt-out is announced"
  assert_eq "" "$(cosign_log)" "cosign must not run at all"
  assert_not_contains "$(curl_log)" "cosign.bundle" "no bundle is even downloaded"
}

test_tampered_tarball_fails_the_checksum() {
  prepare
  # Replace the tarball after its checksum was computed.
  printf 'tampered\n' >>"$STUB_STATE/files/${RELEASE_PKG}.tar.gz"

  run_script "$INSTALL_SH" --version v9.9.9 --bin-dir "$BIN_DIR" --no-helper
  assert_failure "$STATUS" "a corrupted download must abort" "$OUTPUT"
  assert_contains "$OUTPUT" "checksum verification failed" "says why it aborted"
  assert_file_absent "$BIN_DIR/lianyaohu" "nothing may be installed"
}

test_missing_release_asset_fails() {
  prepare
  rm -f "$STUB_STATE/files/${RELEASE_PKG}.tar.gz"

  run_script "$INSTALL_SH" --version v9.9.9 --bin-dir "$BIN_DIR" --no-helper
  assert_failure "$STATUS" "a missing asset must abort" "$OUTPUT"
  assert_contains "$OUTPUT" "download failed" "says why it aborted"
}

test_unresolvable_latest_tag_fails() {
  prepare
  rm -f "$STUB_STATE/latest_location"

  run_script "$INSTALL_SH" --bin-dir "$BIN_DIR" --no-helper
  assert_failure "$STATUS" "an unresolvable 'latest' must abort" "$OUTPUT"
  assert_contains "$OUTPUT" "could not reach GitHub" "says why it aborted"
}

test_installs_the_root_helper_from_the_package() {
  prepare

  run_script "$INSTALL_SH" --version v9.9.9 --bin-dir "$BIN_DIR"
  assert_success "$STATUS" "the default install runs the packaged helper installer" "$OUTPUT"
  assert_file_exists "$STUB_STATE/helper.log" "the packaged install-helper.sh ran"
  assert_contains "$(cat "$STUB_STATE/helper.log")" "/bin/lianyaohu" \
    "the helper installer is pointed at the freshly extracted binary"
}

test_unknown_option_is_rejected() {
  prepare

  run_script "$INSTALL_SH" --definitely-not-an-option
  assert_eq "64" "$STATUS" "unknown options exit with EX_USAGE"
  assert_contains "$OUTPUT" "unknown option" "explains the rejection"
}

run_tests
