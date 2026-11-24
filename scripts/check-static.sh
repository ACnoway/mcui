#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! go version | grep -Fq 'go version go1.27.4 '; then
  echo 'Go 1.27.4 is required' >&2
  exit 1
fi
if [[ "$(node --version)" != 'v26.13.1' ]]; then
  echo 'Node.js 26.13.1 is required' >&2
  exit 1
fi
if ! command -v pnpm >/dev/null 2>&1 || [[ "$(pnpm --version)" != '12.17.0' ]]; then
  echo 'pnpm 12.17.0 is required' >&2
  exit 1
fi

unformatted="$(find cmd internal -type f -name '*.go' -print0 | xargs -0 gofmt -l)"
if [[ -n "$unformatted" ]]; then
  printf 'Go files need gofmt:\n%s\n' "$unformatted" >&2
  exit 1
fi

go vet ./...
go build ./...
go test ./...
GOOS=linux GOARCH=amd64 go build ./...
GOOS=linux GOARCH=arm64 go build ./...
node scripts/verify-protocol-vectors.mjs
node scripts/verify-protocol-v2-vectors.mjs
for script in scripts/*.sh deploy/agent-installer.sh deploy/agent-xray-bootstrap.sh deploy/xray-network.sh deploy/master/installer.sh; do
  bash -n "$script"
done

pnpm --dir web install --frozen-lockfile
pnpm --dir web build
git diff --exit-code -- go.mod go.sum web/pnpm-lock.yaml
