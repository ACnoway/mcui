# MCUI Master and empty Agent

MCUI is a multi-Core control plane in staged development. The repository contains the Master panel, a Core-free Agent, and a signed task path with a privileged Helper and isolated signers. Opt-in Xray installation is the first remote lifecycle operation. The first demo target is the complete Xray workflow.

## Current stage

Phase 0/1 engineering work is complete and formal exit evidence remains outstanding. Phase 2 connects scoped status-task creation, external signing, Token-authenticated pull/ACK, durable Agent intake, pending-task cancellation, expired-task skip, a peer-credential-checked Helper socket, and an HTTPS Master lease checkpoint. The remotely executable action is a fixed read-only service status query. [Phase 0/1 status](docs/phase-0-1-implementation.md) · [Phase 2 progress](docs/phase-2-progress.md) · [Phase 2 operations](docs/phase-2-operations.md)

Phase 3 includes the official Core release catalog, Master backup cache and local `mcui-xray` lifecycle. A scoped operator can reserve a sequence after MFA, submit the operator-signed request and independently signed Xray installation task, and dispatch it through the checkpoint. The current install path verifies TUF metadata. The planned production path uses a single Ed25519-signed artifact manifest on GitHub Releases. The manifest migration, further remote lifecycle operations and the Agent/Helper update supervisor are pending. Debian amd64 receives runtime validation and Linux arm64 receives build validation. [Phase 3 progress](docs/phase-3-progress.md) · [Install authorization](docs/phase-3-approval.md) · [Operations](docs/phase-3-operations.md) · [Artifact releases](docs/phase-3-release.md)

## Development checks

The baseline pins Go 1.27.4, Node.js 26.13.1, and pnpm 12.17.0; see [development baseline](docs/development-baseline.md). From the repository root:

```sh
go vet ./...
go test ./...
node scripts/verify-protocol-vectors.mjs
node scripts/verify-protocol-v2-vectors.mjs
cd web
pnpm install --frozen-lockfile
pnpm build
```

## Local panel mode

HTTP mode is loopback-only and for panel development. It cannot enroll Agents. Build the UI, then run:

```sh
go run ./cmd/panel -listen 127.0.0.1:8080 -db ./data/mcui.db -web ./web/dist
```

Provide a one-time `MCUI_BOOTSTRAP_TOKEN` through a trusted local mechanism, then initialize the first administrator in the panel with a 12+ character password and a Base32 TOTP secret. The bootstrap account is a global `security_admin`; the UI can provision scoped auditor and operator accounts.

## TLS panel and Agent enrollment

In the TLS panel, a scoped security administrator creates a node and generates a one-time install command after MFA. The command verifies the approved installer SHA-256 before running it. The installer configures the Agent and the status-only Helper, then redeems the code over HTTPS. See [Agent deployment and migration](docs/phase-1-operations.md) for release metadata, trust provisioning, and service setup.

The Agent uses the system CA store or an explicit locally trusted CA. Its node Token is stored in a private identity file and authenticates heartbeat, task delivery, and ACK. Re-enrollment preserves the node ID and ledgers. The old Token expires as soon as the replacement is redeemed.

SQLite migrations cover the previous certificate-backed and serialized database formats. The supported backup utility creates a verified snapshot or a separate restore candidate. See the [phased workflow](docs/phased-development-workflow.md) for the remaining release gates.

## Components

- `cmd/panel`: TLS-capable Master panel/API server; loopback-only development HTTP mode
- `cmd/agent`: Core-free Agent enrollment, Token-authenticated heartbeat, and status-task client
- `cmd/mcui-helper`: root-owned Linux status Helper with a fixed Unix socket and systemd query mapping
- `cmd/mcui-signerd`: isolated loopback-only status-task signing process
- `internal/store`: versioned SQLite schema and legacy-state migration
- `internal/master`: bootstrap, MFA sessions, scoped node management and Token enrollment
- `internal/protocol`: signed-message schema validation and canonicalization, including status-only V2
- `internal/taskauth`, `internal/taskcontrol`, `internal/tasksigner`: signed status verification, V1 cancel/skip verification and signing for the restricted Phase 2 controls, plus isolated task signing
- `internal/taskledger`, `internal/taskslots`, `internal/taskdispatch`, `internal/agenttasks`: durable status-task intake, delivery, ACK, and Helper checkpoint flow
- `internal/helper`: Linux-only peer credential and task verification boundary; runs fixed read-only status queries and fails closed on uncertain ledger state
- `internal/checkpoint`: experimental transition model requiring an independently trusted authority and durable local journal
- `internal/checkpointstore`, `internal/checkpointjournal`: experimental SQLite authority and journal primitives; not independently deployed, authenticated or connected to runtime
- `internal/corecatalog`: read-only official GitHub release metadata for Xray, sing-box, and mita; entries are discovery data and do not authorize installation
- `web`: Vue administration panel
