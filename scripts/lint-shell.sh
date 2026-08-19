#!/usr/bin/env bash
# Syntax-check (bash -n) and lint (shellcheck) every shell script in the repo.
#
#   scripts/lint-shell.sh                     # shellcheck is optional
#   scripts/lint-shell.sh --require-shellcheck # fail when shellcheck is missing
#
# CI runs this with --require-shellcheck so a missing linter cannot silently
# turn the job into a no-op.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

require_shellcheck=0
case "${1:-}" in
  --require-shellcheck) require_shellcheck=1 ;;
  "") ;;
  *) echo "usage: $0 [--require-shellcheck]" >&2; exit 64 ;;
esac

# Every tracked file that is a shell script: by extension, or by shebang (the
# test stubs are named after the commands they shadow, e.g. scripts/tests/stubs/curl).
files=()
while IFS= read -r path; do
  [[ -f "$path" ]] || continue
  case "$path" in
    *.sh)
      files+=("$path")
      continue
      ;;
  esac
  first=""
  IFS= read -r first <"$path" || true
  case "$first" in
    '#!'*bash* | '#!'*/sh | '#!'*env\ sh) files+=("$path") ;;
  esac
done < <(git ls-files --cached --others --exclude-standard)

if [[ ${#files[@]} -eq 0 ]]; then
  echo "lint-shell: no shell scripts found" >&2
  exit 1
fi

echo "lint-shell: checking ${#files[@]} shell scripts"

status=0
for file in "${files[@]}"; do
  if ! bash -n "$file"; then
    echo "lint-shell: syntax error in ${file}" >&2
    status=1
  fi
done

if command -v shellcheck >/dev/null 2>&1; then
  # -x follows `source`d files so the test helpers are analysed too.
  if ! shellcheck -x "${files[@]}"; then
    status=1
  fi
elif [[ "$require_shellcheck" == "1" ]]; then
  echo "lint-shell: shellcheck is required but not installed" >&2
  status=1
else
  echo "lint-shell: NOTE: shellcheck is not installed; ran 'bash -n' only" >&2
fi

if [[ "$status" == "0" ]]; then
  echo "lint-shell: ok"
fi
exit "$status"
