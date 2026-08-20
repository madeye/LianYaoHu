#!/usr/bin/env bash
# install.sh and uninstall.sh print their own header comment as --help, using a
# hard-coded line range. Editing the header without moving the range silently
# truncates (or over-prints) the help. These tests pin the two together.
set -euo pipefail

# shellcheck source=scripts/tests/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

# The full header comment block, minus the shebang, with the comment markers
# stripped exactly the way the scripts strip them.
header_block() {
  awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$1"
}

assert_help_matches_header() {
  local script="$1"
  setup_stubs
  run_script "$script" --help
  assert_success "$STATUS" "$(basename "$script") --help must succeed" "$OUTPUT"
  assert_eq "$(header_block "$script")" "$OUTPUT" \
    "$(basename "$script") --help must print its whole header comment"
}

test_install_help_matches_its_header() {
  assert_help_matches_header "$REPO_ROOT/scripts/install.sh"
}

test_uninstall_help_matches_its_header() {
  assert_help_matches_header "$REPO_ROOT/scripts/uninstall.sh"
}

run_tests
