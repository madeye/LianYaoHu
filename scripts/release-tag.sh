#!/usr/bin/env bash
# Resolve and validate the release tag for .github/workflows/release.yml.
#
# This guard lives in a script (rather than inline in the workflow) so it can
# be unit-tested: see scripts/tests/test-release-tag.sh.
#
# Why it exists: Sigstore/Fulcio derives the signing certificate's identity
# from the workflow's *own* ref (GITHUB_REF), not from whatever ref is checked
# out. install.sh pins that identity to
# `.../release.yml@refs/tags/`, so a release run on a branch ref would sign as
# `@refs/heads/<branch>` and every cosign-equipped install of that release
# would hard-fail. Refuse to build and sign from anything but a tag ref.
#
# Inputs (environment):
#   GITHUB_REF       the run's own ref, e.g. refs/tags/v0.1.0 (required)
#   GITHUB_REF_NAME  short ref name; derived from GITHUB_REF when unset
#   DISPATCH_TAG     workflow_dispatch tag input, empty for tag pushes
#   GITHUB_OUTPUT    file to append `tag=`/`version=` to (default: stdout)
set -euo pipefail

ref="${GITHUB_REF:-}"
dispatch_tag="${DISPATCH_TAG:-}"
output="${GITHUB_OUTPUT:-/dev/stdout}"

# GitHub renders `::error::` workflow commands from a step's stdout.
fail() {
  echo "::error::$*"
  exit 1
}

if [[ "$ref" != refs/tags/* ]]; then
  fail "Release must run from a tag ref, got '${ref}'." \
    "For workflow_dispatch, select the tag itself as the run's ref."
fi

tag="${GITHUB_REF_NAME:-${ref#refs/tags/}}"

if [[ "$tag" != "${ref#refs/tags/}" ]]; then
  fail "GITHUB_REF_NAME '${tag}' does not match GITHUB_REF '${ref}'"
fi

if [[ -n "$dispatch_tag" && "$dispatch_tag" != "$tag" ]]; then
  fail "Dispatched tag input '${dispatch_tag}' does not match the run's tag ref '${tag}'"
fi

if [[ ! "$tag" =~ ^v[0-9]+(\.[0-9]+){1,2}([.-][0-9A-Za-z.-]+)?$ ]]; then
  fail "Release tag must look like v0.1.0, got '${tag}'"
fi

{
  echo "tag=${tag}"
  echo "version=${tag#v}"
} >>"$output"
