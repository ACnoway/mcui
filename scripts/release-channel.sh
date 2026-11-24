#!/usr/bin/env bash
set -euo pipefail

number='(0|[1-9][0-9]*)'
tag_pattern="^v$number\.$number\.$number(-(alpha|beta)\.[1-9][0-9]*)?$"
if [[ $# != 1 || ! $1 =~ $tag_pattern ]]; then
  printf 'Expected vMAJOR.MINOR.PATCH, vMAJOR.MINOR.PATCH-alpha.N or vMAJOR.MINOR.PATCH-beta.N (N >= 1)\n' >&2
  exit 2
fi

printf '%s\n' "${BASH_REMATCH[5]:-stable}"
