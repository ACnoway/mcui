#!/usr/bin/env bash
set -euo pipefail
umask 022

if [[ $# != 2 || $(bash "$(dirname "$0")/release-channel.sh" "$2") != stable ]]; then
  printf 'Usage: %s NEW_OUTPUT_DIRECTORY vMAJOR.MINOR.PATCH\n' "$0" >&2
  exit 2
fi
output=$(realpath -m -- "$1")
tag=$2
cd "$(dirname "$0")/.."

bash scripts/build-master-release.sh "$output"
bash scripts/build-agent-installer.sh "$output/install-mcui-agent.sh" --managed-core
installer_sha=$(sha256sum -- "$output/install-mcui-agent.sh")
printf '%s %s\n' "$tag" "${installer_sha%% *}" >"$output/image/release/agent-release"
install -m 0644 -- compose.yaml compose.https.yaml "$output/"
(
  cd "$output"
  sha256sum -- install-mcui-agent.sh install-mcui-master.sh compose.yaml compose.https.yaml > SHA256SUMS
)
