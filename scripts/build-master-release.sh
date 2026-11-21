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
mkdir "$work/image"
for arch in amd64 arm64; do
  mkdir "$work/image/$arch"
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o "$work/image/$arch/mcui-panel" ./cmd/panel
done
pnpm --dir web install --frozen-lockfile
pnpm --dir web build
cp -R web/dist "$work/image/web"
cp deploy/master/installer.sh "$work/install-mcui-master.sh"
cp deploy/master/mcui-master.service "$work/image/"
tar -czf - -C "$work/image" amd64 arm64 web mcui-master.service >>"$work/install-mcui-master.sh"
cp "$work/install-mcui-master.sh" "$output/"
cp -R "$work/image" "$output/"
(
  cd "$output"
  sha256sum install-mcui-master.sh > SHA256SUMS
)
