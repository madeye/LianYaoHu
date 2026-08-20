#!/usr/bin/env bash
# Run every shell-script test suite in this directory.
#
#   scripts/tests/run.sh                 # all suites
#   scripts/tests/run.sh test-install.sh # one suite
#   TEST_FILTER=signature scripts/tests/run.sh
#
# The suites use only stubs and temporary directories: they install nothing,
# touch no system path and make no network calls.
set -euo pipefail

tests_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

suites=()
if [[ $# -gt 0 ]]; then
  for arg in "$@"; do
    case "$arg" in
      /*) suites+=("$arg") ;;
      *) suites+=("$tests_dir/$arg") ;;
    esac
  done
else
  for suite in "$tests_dir"/test-*.sh; do
    suites+=("$suite")
  done
fi

status=0
for suite in "${suites[@]}"; do
  [[ -f "$suite" ]] || {
    echo "run: no such suite: $suite" >&2
    exit 1
  }
  echo "== $(basename "$suite")"
  if ! bash "$suite"; then
    status=1
  fi
done

if [[ "$status" == "0" ]]; then
  echo "== all shell test suites passed"
else
  echo "== shell test suites FAILED" >&2
fi
exit "$status"
