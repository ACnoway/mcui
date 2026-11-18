#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 1 ]]; then
  printf 'Usage: %s OUTPUT_INSTALLER\n' "$0" >&2
  exit 2
fi
output=$(realpath -m -- "$1")
if [[ -e $output || -L $output ]]; then
  printf 'Installer output already exists\n' >&2
  exit 1
fi
cd "$(dirname "$0")/.."
build=$(mktemp -d)
trap 'rm -rf -- "$build"' EXIT
mkdir "$build/units"
for arch in amd64 arm64; do
  mkdir "$build/$arch"
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o "$build/$arch/mcui-agent" ./cmd/agent
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o "$build/$arch/mcui-helper" ./cmd/mcui-helper
done
cp deploy/systemd/mcui-agent.service deploy/systemd/mcui-helper.service deploy/systemd/mcui-agent-task-runtime.conf "$build/units/"
cp deploy/agent-installer.sh "$build/install.sh"
tar -czf - -C "$build" amd64 arm64 units >>"$build/install.sh"
(
  set -o noclobber
  cat "$build/install.sh" >"$output"
)
sha256sum -- "$output"
