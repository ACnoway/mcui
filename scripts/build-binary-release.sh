#!/usr/bin/env bash
set -euo pipefail
umask 022

if [[ $# != 1 ]]; then
  printf 'Usage: %s NEW_OUTPUT_DIRECTORY\n' "$0" >&2
  exit 2
fi
output=$(realpath -m -- "$1")
cd "$(dirname "$0")/.."
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
mkdir -- "$output"
bash scripts/build-master-release.sh "$work/master"
bash scripts/build-runtime-release.sh "$work/runtime"
for arch in amd64 arm64; do
  master="$work/master/image"
  tar -czf "$output/mcui-master-linux-$arch.tar.gz" \
    -C "$master/$arch" mcui-panel -C "$master" web
  install -m 0644 -- "$work/runtime/mcui-runtime-linux-$arch.zip" "$output/mcui-agent-linux-$arch.zip"
done
(
  cd "$output"
  sha256sum -- mcui-master-linux-*.tar.gz mcui-agent-linux-*.zip > SHA256SUMS-binaries
)
