#!/usr/bin/env bash
set -euo pipefail
umask 022

if [[ $# != 2 ]]; then
  printf 'Usage: %s NEW_OUTPUT_DIRECTORY vMAJOR.MINOR.PATCH[-alpha.N|-beta.N]\n' "$0" >&2
  exit 2
fi
output=$(realpath -m -- "$1")
tag=$2
bash "$(dirname "$0")/release-channel.sh" "$tag" >/dev/null
cd "$(dirname "$0")/.."

bash scripts/build-master-release.sh "$output"
bash scripts/build-agent-installer.sh "$output/install-mcui-agent.sh" --managed-core
installer_sha=$(sha256sum -- "$output/install-mcui-agent.sh")
printf '%s %s\n' "$tag" "${installer_sha%% *}" >"$output/image/release/agent-release"
sed "s#ghcr.io/acnoway/mcui-master:latest#ghcr.io/acnoway/mcui-master:$tag#g" compose.yaml >"$output/compose.yaml"
install -m 0644 -- compose.https.yaml "$output/"
install -m 0755 -- deploy/master/install-compose.sh "$output/install-mcui-compose.sh"
install -m 0755 -- deploy/master/setup-host-clock.sh "$output/setup-host-clock.sh"
(
  cd "$output"
  sha256sum -- install-mcui-agent.sh install-mcui-master.sh install-mcui-compose.sh setup-host-clock.sh compose.yaml compose.https.yaml > SHA256SUMS
)
