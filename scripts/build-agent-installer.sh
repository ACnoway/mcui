#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 1 && ( $# != 7 || $2 != --xray-bootstrap ) ]]; then
  printf 'Usage: %s OUTPUT_INSTALLER [--xray-bootstrap KEY_ID INSTALL_PUBLIC_KEY RELEASE_PUBLIC_KEY MANIFEST SIGNATURE]\n' "$0" >&2
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
if [[ $# == 7 ]]; then
  [[ $3 =~ ^[A-Za-z0-9._:-]{1,128}$ ]] || { printf 'Invalid Xray signing key ID\n' >&2; exit 1; }
  mkdir "$build/xray-bootstrap"
  install -m 0644 -- "$4" "$build/xray-bootstrap/xray-install.pub"
  install -m 0644 -- "$5" "$build/xray-bootstrap/release.pub"
  install -m 0644 -- "$6" "$build/xray-bootstrap/manifest.json"
  install -m 0644 -- "$7" "$build/xray-bootstrap/manifest.json.sig"
  go run ./cmd/mcui-manifest verify -public-key "$build/xray-bootstrap/release.pub" \
    -manifest "$build/xray-bootstrap/manifest.json" -signature "$build/xray-bootstrap/manifest.json.sig" \
    -distinct-public-key "$build/xray-bootstrap/xray-install.pub"
  printf 'MCUI_XRAY_INSTALL_KEY_ID=%s\n' "$3" >"$build/xray-bootstrap/xray-install.env"
  cat >>"$build/xray-bootstrap/xray-install.env" <<'EOF'
MCUI_XRAY_INSTALL_PUBLIC_KEY=/etc/mcui-agent/xray-install.pub
MCUI_XRAY_RELEASE_PUBLIC_KEY=/etc/mcui-agent/release.pub
MCUI_NODE_CLOCK_SOCKET=1
EOF
  cp deploy/agent-xray-bootstrap.sh "$build/xray-bootstrap/install.sh"
  cp deploy/xray-network.sh "$build/xray-bootstrap/xray-network.sh"
  cp deploy/systemd/mcui-helper-xray-install.conf deploy/systemd/mcui-xray*.service \
    deploy/systemd/mcui-xray-panel-network.conf deploy/systemd/mcui-node-clock.socket \
    deploy/systemd/mcui-node-clock@.service "$build/units/"
fi
for arch in amd64 arm64; do
  mkdir "$build/$arch"
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o "$build/$arch/mcui-agent" ./cmd/agent
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o "$build/$arch/mcui-helper" ./cmd/mcui-helper
  if [[ $# == 7 ]]; then
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o "$build/$arch/mcui-xray" ./cmd/mcui-xray
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o "$build/$arch/mcui-manifest" ./cmd/mcui-manifest
  fi
done
cp deploy/systemd/mcui-agent.service deploy/systemd/mcui-helper.service deploy/systemd/mcui-agent-task-runtime.conf "$build/units/"
cp deploy/agent-installer.sh "$build/install.sh"
members=(amd64 arm64 units)
if [[ $# == 7 ]]; then
  members+=(xray-bootstrap)
fi
tar -czf - -C "$build" "${members[@]}" >>"$build/install.sh"
(
  set -o noclobber
  cat "$build/install.sh" >"$output"
)
sha256sum -- "$output"
