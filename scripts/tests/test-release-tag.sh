#!/usr/bin/env bash
# Tests for scripts/release-tag.sh — the guard that refuses to build and sign a
# release from anything but a tag ref.
#
# This is the exact failure class that bricked a past release: a
# workflow_dispatch run from a branch signs as `@refs/heads/<branch>`, which
# can never satisfy install.sh's `@refs/tags/` identity pin, so every
# cosign-equipped install of that release hard-fails.
set -euo pipefail

# shellcheck source=scripts/tests/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

RELEASE_TAG_SH="$REPO_ROOT/scripts/release-tag.sh"

# Run release-tag.sh with a clean environment plus the given VAR=VALUE pairs.
# Sets OUTPUT (combined output), STATUS and GH_OUTPUT (the step outputs file).
run_release_tag() {
  local gh_output="$TEST_WORKDIR/github-output"
  : >"$gh_output"
  set +e
  OUTPUT="$(env -u GITHUB_REF -u GITHUB_REF_NAME -u DISPATCH_TAG \
    "GITHUB_OUTPUT=$gh_output" "$@" "$RELEASE_TAG_SH" 2>&1)"
  STATUS=$?
  set -e
  GH_OUTPUT="$(cat "$gh_output")"
}

test_accepts_a_tag_push() {
  run_release_tag GITHUB_REF=refs/tags/v0.1.0 GITHUB_REF_NAME=v0.1.0
  assert_success "$STATUS" "a tag push must be accepted" "$OUTPUT"
  assert_contains "$GH_OUTPUT" "tag=v0.1.0" "exports the tag"
  assert_contains "$GH_OUTPUT" "version=0.1.0" "exports the version without the v"
}

test_accepts_a_two_component_and_prerelease_tag() {
  run_release_tag GITHUB_REF=refs/tags/v1.2 GITHUB_REF_NAME=v1.2
  assert_success "$STATUS" "v1.2 must be accepted" "$OUTPUT"
  assert_contains "$GH_OUTPUT" "version=1.2" "exports the version"

  run_release_tag GITHUB_REF=refs/tags/v1.2.3-rc.1 GITHUB_REF_NAME=v1.2.3-rc.1
  assert_success "$STATUS" "a prerelease tag must be accepted" "$OUTPUT"
  assert_contains "$GH_OUTPUT" "version=1.2.3-rc.1" "exports the prerelease version"
}

test_refuses_a_branch_ref() {
  run_release_tag GITHUB_REF=refs/heads/main GITHUB_REF_NAME=main
  assert_failure "$STATUS" "a branch ref must be refused" "$OUTPUT"
  assert_contains "$OUTPUT" "::error::" "emits a workflow error annotation"
  assert_contains "$OUTPUT" "must run from a tag ref" "says why it refused"
  assert_eq "" "$GH_OUTPUT" "no tag is exported"
}

test_refuses_a_pull_request_ref() {
  run_release_tag GITHUB_REF=refs/pull/12/merge GITHUB_REF_NAME=12/merge
  assert_failure "$STATUS" "a pull-request ref must be refused" "$OUTPUT"
  assert_contains "$OUTPUT" "must run from a tag ref" "says why it refused"
}

test_refuses_a_missing_ref() {
  run_release_tag
  assert_failure "$STATUS" "an empty ref must be refused" "$OUTPUT"
  assert_contains "$OUTPUT" "must run from a tag ref" "says why it refused"
}

test_refuses_a_dispatch_tag_that_does_not_match_the_ref() {
  run_release_tag GITHUB_REF=refs/tags/v0.1.0 GITHUB_REF_NAME=v0.1.0 DISPATCH_TAG=v0.2.0
  assert_failure "$STATUS" "a mismatched dispatch input must be refused" "$OUTPUT"
  assert_contains "$OUTPUT" "does not match the run's tag ref" "says why it refused"
  assert_eq "" "$GH_OUTPUT" "no tag is exported"
}

test_accepts_a_dispatch_tag_that_matches_the_ref() {
  run_release_tag GITHUB_REF=refs/tags/v0.1.0 GITHUB_REF_NAME=v0.1.0 DISPATCH_TAG=v0.1.0
  assert_success "$STATUS" "a matching dispatch input must be accepted" "$OUTPUT"
  assert_contains "$GH_OUTPUT" "tag=v0.1.0" "exports the tag"
}

test_refuses_a_ref_name_that_contradicts_the_ref() {
  run_release_tag GITHUB_REF=refs/tags/v0.1.0 GITHUB_REF_NAME=v9.9.9
  assert_failure "$STATUS" "an inconsistent ref name must be refused" "$OUTPUT"
  assert_contains "$OUTPUT" "does not match GITHUB_REF" "says why it refused"
}

test_refuses_a_malformed_tag() {
  local bad
  # Note: a dotted suffix such as v1.2.3.4 is accepted on purpose — the tag
  # pattern allows prerelease/post suffixes like v1.2.3-rc.1 and v1.2.3.post1.
  for bad in v vX.Y 1.2.3 v1 "v1.2.3 rm -rf" "v1.2.3/../evil"; do
    run_release_tag "GITHUB_REF=refs/tags/${bad}" "GITHUB_REF_NAME=${bad}"
    assert_failure "$STATUS" "tag '${bad}' must be refused" "$OUTPUT"
    assert_contains "$OUTPUT" "Release tag must look like" "says why it refused '${bad}'"
  done
}

run_tests
