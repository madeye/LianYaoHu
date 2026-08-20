#!/usr/bin/env bash
# Tests for the Sigstore identity install.sh pins, and for the release-side
# facts that identity depends on.
#
# The regexp is read out of scripts/install.sh rather than restated here, so
# these tests fail if the enforced pattern ever loosens.
set -euo pipefail

# shellcheck source=scripts/tests/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

INSTALL_SH="$REPO_ROOT/scripts/install.sh"
RELEASE_YML="$REPO_ROOT/.github/workflows/release.yml"
CI_YML="$REPO_ROOT/.github/workflows/ci.yml"

assert_identity_accepted() {
  local regexp="$1" identity="$2"
  [[ "$identity" =~ $regexp ]] || fail "identity should verify but does not: $identity"
}

assert_identity_rejected() {
  local regexp="$1" identity="$2"
  if [[ "$identity" =~ $regexp ]]; then
    fail "identity must NOT verify but does: $identity"
  fi
}

test_identity_regexp_accepts_only_tagged_release_workflow_runs() {
  local re
  re="$(install_identity_regexp madeye/LianYaoHu)"
  local prefix="https://github.com/madeye/LianYaoHu/.github/workflows"

  assert_identity_accepted "$re" "${prefix}/release.yml@refs/tags/v0.1.0"
  assert_identity_accepted "$re" "${prefix}/release.yml@refs/tags/v1.2.3-rc.1"

  # The #50 failure mode: a release dispatched from a branch.
  assert_identity_rejected "$re" "${prefix}/release.yml@refs/heads/main"
  assert_identity_rejected "$re" "${prefix}/release.yml@refs/heads/release"
  assert_identity_rejected "$re" "${prefix}/release.yml@refs/pull/12/merge"
  # Any other workflow in this repo, on a tag, must not be able to sign.
  assert_identity_rejected "$re" "${prefix}/ci.yml@refs/tags/v0.1.0"
  # Another repository's release workflow.
  assert_identity_rejected "$re" "https://github.com/evil/LianYaoHu/.github/workflows/release.yml@refs/tags/v0.1.0"
  assert_identity_rejected "$re" "https://github.com/madeye/LianYaoHu-evil/.github/workflows/release.yml@refs/tags/v0.1.0"
  # Not anchored at the start would let a prefix smuggle a different host in.
  assert_identity_rejected "$re" "https://evil.example/https://github.com/madeye/LianYaoHu/.github/workflows/release.yml@refs/tags/v1"
  # The literal dots must stay escaped, or '.' would match any character.
  assert_identity_rejected "$re" "https://github.com/madeye/LianYaoHu/Xgithub/workflows/releaseXyml@refs/tags/v0.1.0"
  # A tag ref, not merely the string 'refs/tags'.
  assert_identity_rejected "$re" "${prefix}/release.yml@refs/tagsv0.1.0"
}

test_identity_regexp_is_scoped_to_the_configured_repo() {
  local re
  re="$(install_identity_regexp example/Fork)"
  assert_identity_accepted "$re" "https://github.com/example/Fork/.github/workflows/release.yml@refs/tags/v1.0.0"
  assert_identity_rejected "$re" "https://github.com/madeye/LianYaoHu/.github/workflows/release.yml@refs/tags/v1.0.0"
}

test_the_pinned_workflow_file_exists() {
  # The identity names a workflow file by path; renaming that file without
  # updating install.sh would make every signed release unverifiable.
  assert_file_exists "$RELEASE_YML" "install.sh pins .github/workflows/release.yml"
}

test_release_workflow_signs_the_asset_install_sh_downloads() {
  assert_file_contains "$RELEASE_YML" "cosign sign-blob" "the release workflow signs the tarball"
  # release.yml builds the bundle name as "${asset}.cosign.bundle", where the
  # asset is the .tar.gz install.sh downloads. These needles are the literal
  # shell text of those two files, so they must not expand here.
  # shellcheck disable=SC2016
  assert_file_contains "$RELEASE_YML" '${asset}.cosign.bundle' \
    "the bundle asset name is the one install.sh fetches"
  # shellcheck disable=SC2016
  assert_file_contains "$INSTALL_SH" '${package}.tar.gz.cosign.bundle' \
    "install.sh downloads the published bundle name"
}

test_release_workflow_uses_the_shared_tag_guard() {
  assert_file_contains "$RELEASE_YML" "scripts/release-tag.sh" \
    "the tag guard must stay in the tested script rather than being re-inlined"
}

test_ci_and_release_pin_the_same_cosign() {
  local release_pin ci_pin
  release_pin="$(grep -o 'sigstore/cosign-installer@[0-9a-f]\{40\}' "$RELEASE_YML" | sort -u)"
  ci_pin="$(grep -o 'sigstore/cosign-installer@[0-9a-f]\{40\}' "$CI_YML" | sort -u)"
  [[ -n "$release_pin" ]] || fail "release.yml must pin cosign-installer to a commit SHA"
  [[ -n "$ci_pin" ]] || fail "ci.yml must pin cosign-installer to a commit SHA"
  assert_eq "$release_pin" "$ci_pin" \
    "the sign/verify round trip must exercise the same cosign the release uses"
}

run_tests
