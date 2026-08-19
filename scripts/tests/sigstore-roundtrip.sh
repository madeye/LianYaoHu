#!/usr/bin/env bash
# Sigstore sign -> publish -> download -> verify round trip, run by CI.
#
#   scripts/tests/sigstore-roundtrip.sh sign   <dir>   # in a job with id-token: write
#   scripts/tests/sigstore-roundtrip.sh verify <dir>   # in a later job, after download
#
# `sign` signs a fixture blob with the same pinned cosign the release workflow
# uses and records the identity this workflow run signs as. The directory is
# then published as a workflow artifact and downloaded by the verify job, so
# the bundle really makes the round trip instead of staying in one step's
# working directory.
#
# `verify` asserts, using the real cosign:
#   1. the downloaded bundle verifies against the identity that signed it;
#   2. it does NOT verify against the identity install.sh enforces — CI never
#      runs as release.yml on a refs/tags/ ref, which is exactly the release
#      that once shipped signed as @refs/heads/... and could not be installed;
#   3. a tampered blob does not verify, even with the correct identity;
#   4. a wrong OIDC issuer does not verify.
set -euo pipefail

# shellcheck source=scripts/tests/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

OIDC_ISSUER="https://token.actions.githubusercontent.com"
FIXTURE_NAME="lianyaohu-roundtrip-fixture.tar.gz"

usage() {
  echo "usage: $0 {sign|verify} <dir>" >&2
  exit 64
}

command -v cosign >/dev/null 2>&1 || {
  echo "sigstore-roundtrip: cosign is required" >&2
  exit 1
}

command="${1:-}"
dir="${2:-}"
[[ -n "$command" && -n "$dir" ]] || usage

blob="$dir/$FIXTURE_NAME"
bundle="$blob.cosign.bundle"
identity_file="$dir/identity.txt"

do_sign() {
  mkdir -p "$dir"
  printf 'LianYaoHu Sigstore round-trip fixture\nrun=%s\nattempt=%s\n' \
    "${GITHUB_RUN_ID:-local}" "${GITHUB_RUN_ATTEMPT:-0}" >"$blob"

  cosign sign-blob --yes --bundle "$bundle" "$blob"

  # Fulcio binds the certificate to the workflow's own ref; GITHUB_WORKFLOW_REF
  # is that same "<owner>/<repo>/<path>@<ref>" string.
  local workflow_ref="${GITHUB_WORKFLOW_REF:-}"
  [[ -n "$workflow_ref" ]] || {
    echo "sigstore-roundtrip: GITHUB_WORKFLOW_REF is unset (this needs GitHub Actions)" >&2
    exit 1
  }
  printf 'https://github.com/%s\n' "$workflow_ref" >"$identity_file"
  echo "sigstore-roundtrip: signed ${FIXTURE_NAME} as https://github.com/${workflow_ref}"
}

# Print the certificate's SAN so a surprising identity is self-diagnosing.
show_certificate_identity() {
  command -v jq >/dev/null 2>&1 || return 0
  command -v openssl >/dev/null 2>&1 || return 0
  local cert
  cert="$(jq -r '.cert // empty' "$bundle" 2>/dev/null | base64 -d 2>/dev/null || true)"
  [[ -n "$cert" ]] || return 0
  echo "sigstore-roundtrip: certificate SAN:"
  printf '%s\n' "$cert" | openssl x509 -noout -text 2>/dev/null |
    grep -A1 "Subject Alternative Name" | sed 's/^/  /' || true
}

verify_blob() {
  # verify_blob <target-blob> <identity-flag> <identity> <issuer>
  cosign verify-blob \
    --bundle "$bundle" \
    "$2" "$3" \
    --certificate-oidc-issuer "$4" \
    "$1"
}

expect_pass() {
  local label="$1"
  shift
  local output status
  set +e
  output="$("$@" 2>&1)"
  status=$?
  set -e
  if [[ "$status" != "0" ]]; then
    echo "FAIL: ${label} should have verified but did not:" >&2
    printf '%s\n' "$output" >&2
    show_certificate_identity >&2
    return 1
  fi
  echo "ok   ${label}"
}

expect_fail() {
  local label="$1"
  shift
  local output status
  set +e
  output="$("$@" 2>&1)"
  status=$?
  set -e
  if [[ "$status" == "0" ]]; then
    echo "FAIL: ${label} verified but must NOT have:" >&2
    printf '%s\n' "$output" >&2
    show_certificate_identity >&2
    return 1
  fi
  echo "ok   ${label} (rejected as expected)"
}

do_verify() {
  [[ -f "$blob" ]] || {
    echo "sigstore-roundtrip: missing downloaded fixture $blob" >&2
    exit 1
  }
  [[ -f "$bundle" ]] || {
    echo "sigstore-roundtrip: missing downloaded bundle $bundle" >&2
    exit 1
  }
  local identity
  identity="$(cat "$identity_file")"
  echo "sigstore-roundtrip: verifying against signing identity ${identity}"

  local release_identity_regexp
  release_identity_regexp="$(install_identity_regexp "${GITHUB_REPOSITORY:-madeye/LianYaoHu}")"
  echo "sigstore-roundtrip: install.sh enforces ${release_identity_regexp}"

  local status=0

  expect_pass "downloaded bundle verifies against the identity that signed it" \
    verify_blob "$blob" --certificate-identity "$identity" "$OIDC_ISSUER" || status=1

  expect_fail "a non-tag CI identity is refused by install.sh's identity pin" \
    verify_blob "$blob" --certificate-identity-regexp "$release_identity_regexp" "$OIDC_ISSUER" ||
    status=1

  expect_fail "a wrong OIDC issuer is refused" \
    verify_blob "$blob" --certificate-identity "$identity" "https://accounts.google.com" || status=1

  # Tamper with the downloaded artifact, keeping the real bundle.
  local tampered="$dir/tampered-$FIXTURE_NAME"
  cp "$blob" "$tampered"
  printf 'tampered\n' >>"$tampered"
  expect_fail "a tampered blob is refused by its own valid bundle" \
    verify_blob "$tampered" --certificate-identity "$identity" "$OIDC_ISSUER" || status=1
  rm -f "$tampered"

  if [[ "$status" != "0" ]]; then
    echo "sigstore-roundtrip: FAILED" >&2
    exit 1
  fi
  echo "sigstore-roundtrip: all round-trip assertions passed"
}

case "$command" in
  sign) do_sign ;;
  verify) do_verify ;;
  *) usage ;;
esac
