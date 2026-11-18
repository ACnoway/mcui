#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 1 ]]; then
  printf 'Usage: %s NEW_OUTPUT_DIRECTORY\n' "$0" >&2
  exit 2
fi

output=$(realpath -m -- "$1")
if [[ -e $output || -L $output ]]; then
  printf 'Release output already exists\n' >&2
  exit 1
fi
stage=$(mktemp -d -- "$(dirname "$output")/.mcui-runtime-build.XXXXXX")
trap 'rm -rf -- "$stage"' EXIT
mkdir "$stage/release"
cd "$(dirname "$0")/.."
for arch in amd64 arm64; do
  mkdir "$stage/$arch"
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o "$stage/$arch/mcui-agent" ./cmd/agent
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o "$stage/$arch/mcui-helper" ./cmd/mcui-helper
  python3 - "$stage/$arch" "$stage/release/mcui-runtime-linux-$arch.zip" <<'PY'
import pathlib
import sys
import zipfile

source = pathlib.Path(sys.argv[1])
with zipfile.ZipFile(sys.argv[2], "x") as archive:
    for name in ("mcui-agent", "mcui-helper"):
        info = zipfile.ZipInfo(name)
        info.create_system = 3
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100555 << 16
        with archive.open(info, "w") as entry, (source / name).open("rb") as binary:
            while chunk := binary.read(1024 * 1024):
                entry.write(chunk)
PY
done
(
  cd "$stage/release"
  sha256sum -- ./*.zip > SHA256SUMS
)
mv -T --no-clobber -- "$stage/release" "$output"
test ! -e "$stage/release"
cat "$output/SHA256SUMS"
