#!/usr/bin/env bash
set -euo pipefail
[[ $(id -u) == 0 ]] || { printf '%s\n' 'Run the verified Compose installer as root' >&2; exit 1; }
command -v docker >/dev/null && docker compose version >/dev/null || { printf '%s\n' 'Docker Compose is required' >&2; exit 1; }
script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
[[ -f $script_dir/setup-host-clock.sh ]] || { printf '%s\n' 'Missing setup-host-clock.sh from the same release' >&2; exit 1; }
docker compose "$@" config --quiet
bash "$script_dir/setup-host-clock.sh"
docker compose "$@" up -d
