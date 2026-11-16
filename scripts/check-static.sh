#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

unformatted="$(find cmd internal -type f -name '*.go' -print0 | xargs -0 gofmt -l)"
if [[ -n "$unformatted" ]]; then
  printf 'Go files need gofmt:\n%s\n' "$unformatted" >&2
  exit 1
fi

go vet ./...
go test ./...
node scripts/verify-protocol-vectors.mjs

if ! command -v pnpm >/dev/null 2>&1; then
  echo 'pnpm is required for the web build' >&2
  exit 1
fi
pnpm --dir web install --frozen-lockfile
pnpm --dir web build
