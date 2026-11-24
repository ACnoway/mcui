#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
  printf 'Usage: %s OUTPUT_INSTALLER [--managed-core RELEASE_PUBLIC_KEY | --xray-bootstrap KEY_ID INSTALL_PUBLIC_KEY RELEASE_PUBLIC_KEY MANIFEST SIGNATURE] [--runtime-bootstrap VERSION RELEASE_PUBLIC_KEY UPDATE_PUBLIC_KEY]\n' "$0" >&2
  exit 2
}
(( $# >= 1 )) || usage
output=$(realpath -m -- "$1")
shift
xray=()
managed_core=
runtime=()
while (( $# )); do
  case "$1" in
    --xray-bootstrap)
      (( $# >= 6 && ${#xray[@]} == 0 )) && [[ -z $managed_core ]] || usage
      xray=("$2" "$3" "$4" "$5" "$6")
      shift 6 ;;
    --managed-core)
      (( $# >= 2 && ${#xray[@]} == 0 )) && [[ -z $managed_core && -n $2 ]] || usage
      managed_core=$2
      shift 2 ;;
    --runtime-bootstrap)
      (( $# >= 4 && ${#runtime[@]} == 0 )) || usage
      runtime=("$2" "$3" "$4")
      shift 4 ;;
    *) usage ;;
  esac
done
if [[ -e $output || -L $output ]]; then
  printf 'Installer output already exists\n' >&2
  exit 1
fi
cd "$(dirname "$0")/.."
build=$(mktemp -d)
trap 'rm -rf -- "$build"' EXIT
mkdir "$build/units"
if [[ $managed_core ]] || (( ${#xray[@]} )); then
  mkdir "$build/xray-bootstrap"
  if [[ $managed_core ]]; then
    install -m 0644 -- "$managed_core" "$build/xray-bootstrap/release.pub"
    touch "$build/xray-bootstrap/managed"
  else
    [[ ${xray[0]} =~ ^[A-Za-z0-9._:-]{1,128}$ ]] || { printf 'Invalid Xray signing key ID\n' >&2; exit 1; }
    install -m 0644 -- "${xray[1]}" "$build/xray-bootstrap/xray-install.pub"
    install -m 0644 -- "${xray[2]}" "$build/xray-bootstrap/release.pub"
    install -m 0644 -- "${xray[3]}" "$build/xray-bootstrap/manifest.json"
    install -m 0644 -- "${xray[4]}" "$build/xray-bootstrap/manifest.json.sig"
    go run ./cmd/mcui-manifest verify -public-key "$build/xray-bootstrap/release.pub" \
      -manifest "$build/xray-bootstrap/manifest.json" -signature "$build/xray-bootstrap/manifest.json.sig" \
      -distinct-public-key "$build/xray-bootstrap/xray-install.pub"
    printf 'MCUI_XRAY_INSTALL_KEY_ID=%s\n' "${xray[0]}" >"$build/xray-bootstrap/xray-install.env"
  fi
  cat >"$build/xray-bootstrap/xray-install.defaults" <<'EOF'
MCUI_XRAY_INSTALL_PUBLIC_KEY=/etc/mcui-agent/xray-install.pub
MCUI_XRAY_RELEASE_PUBLIC_KEY=/etc/mcui-agent/release.pub
MCUI_NODE_CLOCK_SOCKET=1
EOF
  if [[ -z $managed_core ]]; then
    cat "$build/xray-bootstrap/xray-install.defaults" >>"$build/xray-bootstrap/xray-install.env"
  fi
  cp deploy/agent-xray-bootstrap.sh "$build/xray-bootstrap/install.sh"
  cp deploy/xray-network.sh "$build/xray-bootstrap/xray-network.sh"
  cp deploy/systemd/mcui-helper-xray-install.conf deploy/systemd/mcui-xray*.service \
    deploy/systemd/mcui-xray-panel-network.conf deploy/systemd/mcui-node-clock.socket \
    deploy/systemd/mcui-node-clock@.service "$build/units/"
fi
if (( ${#runtime[@]} )); then
  [[ ${runtime[0]} =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || { printf 'Invalid paired runtime version\n' >&2; exit 1; }
  mkdir "$build/runtime-bootstrap"
  printf '%s\n' "${runtime[0]}" >"$build/runtime-bootstrap/version"
  install -m 0644 -- "${runtime[1]}" "$build/runtime-bootstrap/release.pub"
  install -m 0644 -- "${runtime[2]}" "$build/runtime-bootstrap/update.pub"
  cp deploy/systemd/mcui-runtime-{recover,update,remote}.service deploy/systemd/mcui-runtime-remote.timer \
    deploy/systemd/mcui-{agent,helper}-paired-runtime.conf "$build/units/"
fi
for arch in amd64 arm64; do
  mkdir "$build/$arch"
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o "$build/$arch/mcui-agent" ./cmd/agent
  CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o "$build/$arch/mcui-helper" ./cmd/mcui-helper
  if [[ -d $build/xray-bootstrap ]]; then
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o "$build/$arch/mcui-xray" ./cmd/mcui-xray
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o "$build/$arch/mcui-manifest" ./cmd/mcui-manifest
  fi
  if (( ${#runtime[@]} )); then
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o "$build/$arch/mcui-runtime" ./cmd/mcui-runtime
  fi
done
cp deploy/systemd/mcui-agent.service deploy/systemd/mcui-helper.service deploy/systemd/mcui-agent-task-runtime.conf "$build/units/"
cp deploy/agent-installer.sh "$build/install.sh"
members=(amd64 arm64 units)
if [[ -d $build/xray-bootstrap ]]; then
  members+=(xray-bootstrap)
fi
if (( ${#runtime[@]} )); then
  members+=(runtime-bootstrap)
fi
tar -czf - -C "$build" "${members[@]}" >>"$build/install.sh"
(
  set -o noclobber
  cat "$build/install.sh" >"$output"
)
sha256sum -- "$output"
