#!/usr/bin/env bash
set -euo pipefail
umask 022

if [[ $# != 5 || ! $2 =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf 'Usage: %s NEW_OUTPUT_DIRECTORY vMAJOR.MINOR.PATCH RELEASE_PUBLIC_KEY MANIFEST SIGNATURE\n' "$0" >&2
  exit 2
fi
output=$(realpath -m -- "$1")
tag=$2
key=$(realpath -- "$3")
manifest=$(realpath -- "$4")
signature=$(realpath -- "$5")
cd "$(dirname "$0")/.."

go run ./cmd/mcui-manifest verify -public-key "$key" -manifest "$manifest" -signature "$signature"
bash scripts/build-master-release.sh "$output"
bash scripts/build-agent-installer.sh "$output/install-mcui-agent.sh" --managed-core "$key"
installer_sha=$(sha256sum -- "$output/install-mcui-agent.sh")
printf '%s %s\n' "$tag" "${installer_sha%% *}" >"$output/image/release/agent-release"
install -m 0644 -- "$key" "$output/image/release/release.pub"
install -m 0644 -- compose.yaml compose.https.yaml "$output/"
(
  cd "$output"
  sha256sum -- install-mcui-agent.sh install-mcui-master.sh compose.yaml compose.https.yaml > SHA256SUMS
)
