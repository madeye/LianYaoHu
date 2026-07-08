#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 <version> [target] [build-dir] [dist-dir]" >&2
}

version="${1:-}"
if [[ -z "$version" ]]; then
  usage
  exit 64
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
target="${2:-$(rustc -vV | awk '/host:/ {print $2}')}"
build_dir="${3:-target/release}"
dist_dir="${4:-dist}"

case "$build_dir" in
  /*) build_path="$build_dir" ;;
  *) build_path="$root/$build_dir" ;;
esac

case "$dist_dir" in
  /*) dist_path="$dist_dir" ;;
  *) dist_path="$root/$dist_dir" ;;
esac

package_name="lianyaohu-${version}-${target}"
stage_path="$dist_path/$package_name"
archive_path="$dist_path/${package_name}.tar.gz"

rm -rf "$stage_path"
mkdir -p "$stage_path/bin" "$stage_path/scripts" "$dist_path"

if [[ ! -x "$build_path/lianyaohu" ]]; then
  echo "missing executable: $build_path/lianyaohu" >&2
  exit 1
fi
install -m 755 "$build_path/lianyaohu" "$stage_path/bin/lianyaohu"

# Ship the short `lyh` alias alongside the canonical binary when the build
# produced one (the Cargo [[bin]] target always should).
if [[ -x "$build_path/lyh" ]]; then
  install -m 755 "$build_path/lyh" "$stage_path/bin/lyh"
fi

install -m 755 "$root/scripts/install-helper.sh" "$stage_path/scripts/install-helper.sh"
install -m 755 "$root/scripts/uninstall-helper.sh" "$stage_path/scripts/uninstall-helper.sh"
install -m 644 "$root/README.md" "$stage_path/README.md"
install -m 644 "$root/LICENSE" "$stage_path/LICENSE"

cat >"$stage_path/RELEASE.md" <<EOF
# LianYaoHu ${version}

This package was built for ${target}.

Contents:

- bin/lianyaohu (CLI and root helper daemon in one binary; the daemon runs as \`lianyaohu helper\`)
- bin/lyh     (short alias for bin/lianyaohu; identical binary)
- scripts/install-helper.sh
- scripts/uninstall-helper.sh

Install the helper from this extracted package:

\`\`\`sh
scripts/install-helper.sh
\`\`\`

Run the CLI from the package or copy \`bin/lianyaohu\` (or its short alias \`bin/lyh\`) into your PATH.
EOF

rm -f "$archive_path" "$archive_path.sha256"
COPYFILE_DISABLE=1 tar -C "$dist_path" -czf "$archive_path" "$package_name"
(
  cd "$dist_path"
  shasum -a 256 "${package_name}.tar.gz" >"${package_name}.tar.gz.sha256"
)

echo "$archive_path"
