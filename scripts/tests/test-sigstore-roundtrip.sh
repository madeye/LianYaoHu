#!/usr/bin/env bash
# Tests for scripts/tests/sigstore-roundtrip.sh — the CI round trip itself.
#
# CI runs that script against the real, pinned cosign; these tests run it
# against a miniature cosign stub so the assertions can be checked offline and
# on every platform. They matter because an inverted or vacuous assertion in
# the round trip would make the CI job pass no matter what, which is precisely
# the gap this whole change is closing.
set -euo pipefail

# shellcheck source=scripts/tests/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

ROUNDTRIP_SH="$REPO_ROOT/scripts/tests/sigstore-roundtrip.sh"
CI_IDENTITY="https://github.com/madeye/LianYaoHu/.github/workflows/ci.yml@refs/heads/main"
RELEASE_TAG_IDENTITY="https://github.com/madeye/LianYaoHu/.github/workflows/release.yml@refs/tags/v1.0.0"

prepare() {
  setup_stubs
  cp "$TESTS_DIR/stubs/cosign-sigstore" "$STUB_BIN/cosign"
  chmod 755 "$STUB_BIN/cosign"
  ROUNDTRIP_DIR="$TEST_WORKDIR/roundtrip"
  export GITHUB_REPOSITORY="madeye/LianYaoHu"
  export GITHUB_RUN_ID="12345"
  export GITHUB_RUN_ATTEMPT="1"
}

# Sign as the given identity, then run the verify half.
sign_and_verify_as() {
  local identity="$1"
  export LYH_STUB_SIGNING_IDENTITY="$identity"
  export GITHUB_WORKFLOW_REF="${identity#https://github.com/}"
  run_script "$ROUNDTRIP_SH" sign "$ROUNDTRIP_DIR"
  assert_success "$STATUS" "signing the fixture must succeed" "$OUTPUT"
  run_script "$ROUNDTRIP_SH" verify "$ROUNDTRIP_DIR"
}

test_round_trip_passes_for_a_normal_ci_run() {
  prepare
  sign_and_verify_as "$CI_IDENTITY"
  assert_success "$STATUS" "the round trip must pass for a CI-signed fixture" "$OUTPUT"
  assert_contains "$OUTPUT" "downloaded bundle verifies against the identity that signed it" \
    "the positive assertion ran"
  assert_contains "$OUTPUT" "a non-tag CI identity is refused" "the install.sh identity pin was exercised"
  assert_contains "$OUTPUT" "a tampered blob is refused" "tampering was exercised"
  assert_contains "$OUTPUT" "a wrong OIDC issuer is refused" "the issuer pin was exercised"
  assert_contains "$OUTPUT" "all round-trip assertions passed" "the suite reports success"
}

test_round_trip_fails_if_install_sh_would_accept_a_non_release_identity() {
  prepare
  # Pretend install.sh's pin has been loosened so that this CI run's own
  # identity satisfies it: the round trip must go red, not green.
  sign_and_verify_as "$RELEASE_TAG_IDENTITY"
  assert_failure "$STATUS" "an identity that satisfies the install pin must fail the round trip" "$OUTPUT"
  assert_contains "$OUTPUT" "verified but must NOT have" "the negative assertion is real, not vacuous"
}

test_round_trip_fails_when_the_bundle_does_not_verify() {
  prepare
  export LYH_STUB_SIGNING_IDENTITY="$CI_IDENTITY"
  export GITHUB_WORKFLOW_REF="${CI_IDENTITY#https://github.com/}"
  run_script "$ROUNDTRIP_SH" sign "$ROUNDTRIP_DIR"
  assert_success "$STATUS" "signing the fixture must succeed" "$OUTPUT"

  # Corrupt the published blob, as a tampered artifact download would be.
  printf 'tampered in transit\n' >>"$ROUNDTRIP_DIR/lianyaohu-roundtrip-fixture.tar.gz"

  run_script "$ROUNDTRIP_SH" verify "$ROUNDTRIP_DIR"
  assert_failure "$STATUS" "a corrupted download must fail the round trip" "$OUTPUT"
  assert_contains "$OUTPUT" "should have verified but did not" "the positive assertion is real"
}

test_verify_requires_the_downloaded_artifact() {
  prepare
  mkdir -p "$ROUNDTRIP_DIR"

  run_script "$ROUNDTRIP_SH" verify "$ROUNDTRIP_DIR"
  assert_failure "$STATUS" "a missing artifact must fail loudly" "$OUTPUT"
  assert_contains "$OUTPUT" "missing downloaded fixture" "says what is missing"
}

test_usage_is_rejected() {
  prepare

  run_script "$ROUNDTRIP_SH" sign
  assert_eq "64" "$STATUS" "missing arguments exit with EX_USAGE"
  assert_contains "$OUTPUT" "usage:" "prints usage"
}

run_tests
