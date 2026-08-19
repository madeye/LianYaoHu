#!/usr/bin/env bash
# End-to-end tests for scripts/uninstall.sh.
#
# `curl` is shadowed by a stub, the "binaries" live in a temporary --bin-dir
# (writable, so no sudo), and the helper teardown script is redirected to a
# fixture via LIANYAOHU_LOCAL_TEARDOWN — nothing on the system is touched.
set -euo pipefail

# shellcheck source=scripts/tests/lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

UNINSTALL_SH="$REPO_ROOT/scripts/uninstall.sh"

prepare() {
  setup_stubs
  # Pretend the binaries are installed.
  printf '#!/bin/sh\n' >"$BIN_DIR/lianyaohu"
  printf '#!/bin/sh\n' >"$BIN_DIR/lyh"
  chmod 755 "$BIN_DIR/lianyaohu" "$BIN_DIR/lyh"
  # A local teardown script that records that it ran, and where from.
  LOCAL_TEARDOWN="$TEST_WORKDIR/local-teardown.sh"
  cat >"$LOCAL_TEARDOWN" <<'TEARDOWN'
#!/usr/bin/env bash
echo "local teardown ran" >>"${LYH_STUB_STATE}/teardown.log"
TEARDOWN
  chmod 755 "$LOCAL_TEARDOWN"
  # The teardown script the stubbed curl serves for a remote fetch.
  cat >"$STUB_STATE/files/uninstall-helper.sh" <<'REMOTE'
#!/usr/bin/env bash
echo "remote teardown ran" >>"${LYH_STUB_STATE}/teardown.log"
REMOTE
  : >"$STUB_STATE/teardown.log"
}

assert_binaries_removed() {
  assert_file_absent "$BIN_DIR/lianyaohu" "the lianyaohu binary must be removed"
  assert_file_absent "$BIN_DIR/lyh" "the lyh alias must be removed"
}

test_prefers_the_locally_installed_teardown_script() {
  prepare
  export LIANYAOHU_LOCAL_TEARDOWN="$LOCAL_TEARDOWN"

  run_script "$UNINSTALL_SH" --bin-dir "$BIN_DIR"
  assert_success "$STATUS" "uninstall should succeed" "$OUTPUT"
  assert_contains "$(cat "$STUB_STATE/teardown.log")" "local teardown ran" \
    "the shipped teardown script runs"
  assert_eq "" "$(curl_log)" "the local path involves no network fetch at all"
  assert_binaries_removed
}

test_ref_override_forces_the_pinned_remote_fetch() {
  prepare
  export LIANYAOHU_LOCAL_TEARDOWN="$LOCAL_TEARDOWN"
  export LIANYAOHU_REF="v1.2.3"

  run_script "$UNINSTALL_SH" --bin-dir "$BIN_DIR"
  assert_success "$STATUS" "uninstall should succeed" "$OUTPUT"
  assert_contains "$(curl_log)" \
    "https://raw.githubusercontent.com/madeye/LianYaoHu/v1.2.3/scripts/uninstall-helper.sh" \
    "the teardown script is fetched at the pinned ref"
  assert_contains "$(cat "$STUB_STATE/teardown.log")" "remote teardown ran" \
    "the fetched teardown script runs"
  assert_not_contains "$(cat "$STUB_STATE/teardown.log")" "local teardown ran" \
    "LIANYAOHU_REF forces the remote fetch"
  assert_binaries_removed
}

test_resolves_the_latest_tag_for_the_remote_fetch() {
  prepare
  set_latest_tag v9.9.9

  run_script "$UNINSTALL_SH" --bin-dir "$BIN_DIR"
  assert_success "$STATUS" "uninstall should succeed" "$OUTPUT"
  assert_contains "$(curl_log)" \
    "https://raw.githubusercontent.com/madeye/LianYaoHu/v9.9.9/scripts/uninstall-helper.sh" \
    "the fetch is pinned to the resolved release tag"
  assert_contains "$(cat "$STUB_STATE/teardown.log")" "remote teardown ran" \
    "the fetched teardown script runs"
  assert_binaries_removed
}

test_aborts_instead_of_running_an_unpinned_branch_script() {
  prepare
  # No latest_location fixture: the tag cannot be resolved.

  run_script "$UNINSTALL_SH" --bin-dir "$BIN_DIR"
  assert_failure "$STATUS" "an unresolvable tag must abort the uninstall" "$OUTPUT"
  assert_contains "$OUTPUT" "refusing to run an unpinned teardown script" "says why it aborted"
  assert_not_contains "$(curl_log)" "raw.githubusercontent.com" \
    "no teardown script is fetched from a branch tip"
  assert_eq "" "$(cat "$STUB_STATE/teardown.log")" "no teardown script runs"
  assert_file_exists "$BIN_DIR/lianyaohu" "the install is left intact for a retry"
}

test_non_tag_latest_redirect_is_refused() {
  prepare
  # A redirect that does not end in a tag (e.g. a login/interstitial page).
  printf '%s' "https://github.com/login" >"$STUB_STATE/latest_location"

  run_script "$UNINSTALL_SH" --bin-dir "$BIN_DIR"
  assert_failure "$STATUS" "a non-tag redirect must abort the uninstall" "$OUTPUT"
  assert_contains "$OUTPUT" "refusing to run an unpinned teardown script" "says why it aborted"
  assert_not_contains "$(curl_log)" "raw.githubusercontent.com" "nothing unpinned is fetched"
}

test_keep_helper_removes_only_the_binaries() {
  prepare
  export LIANYAOHU_LOCAL_TEARDOWN="$LOCAL_TEARDOWN"

  run_script "$UNINSTALL_SH" --bin-dir "$BIN_DIR" --keep-helper
  assert_success "$STATUS" "uninstall should succeed" "$OUTPUT"
  assert_contains "$OUTPUT" "keeping the root helper" "announces that the helper stays"
  assert_eq "" "$(cat "$STUB_STATE/teardown.log")" "no teardown script runs"
  assert_binaries_removed
}

test_a_failing_teardown_still_removes_the_binaries() {
  prepare
  printf '#!/usr/bin/env bash\nexit 3\n' >"$LOCAL_TEARDOWN"
  export LIANYAOHU_LOCAL_TEARDOWN="$LOCAL_TEARDOWN"

  run_script "$UNINSTALL_SH" --bin-dir "$BIN_DIR"
  assert_success "$STATUS" "a partial teardown must not strand the binaries" "$OUTPUT"
  assert_contains "$OUTPUT" "helper teardown reported an error; continuing" "reports the partial failure"
  assert_binaries_removed
}

test_unfetchable_teardown_script_aborts() {
  prepare
  set_latest_tag v9.9.9
  rm -f "$STUB_STATE/files/uninstall-helper.sh"

  run_script "$UNINSTALL_SH" --bin-dir "$BIN_DIR"
  assert_failure "$STATUS" "a failed fetch must abort" "$OUTPUT"
  assert_contains "$OUTPUT" "could not fetch uninstall-helper.sh at v9.9.9" "says why it aborted"
  assert_contains "$OUTPUT" "--keep-helper" "suggests the binaries-only path"
}

test_unknown_option_is_rejected() {
  prepare

  run_script "$UNINSTALL_SH" --definitely-not-an-option
  assert_eq "64" "$STATUS" "unknown options exit with EX_USAGE"
  assert_contains "$OUTPUT" "unknown option" "explains the rejection"
}

run_tests
