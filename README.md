# MCUI Master and empty Agent

MCUI is a multi-Core control plane in staged development. The repository contains the Master panel, a Core-free Agent, and a Phase 2 status-only signed task path with a privileged Helper and isolated signer process. Core installation and configuration operations remain unavailable. The first demo target is the complete Xray workflow; installation guidance and Docker builds follow that demo, before adding other Cores.

## Current stage

Phase 0/1 repository engineering work is complete, while formal exit evidence remains outstanding; see [Phase 0/1 implementation status](docs/phase-0-1-implementation.md). Phase 2 now connects scoped status-task creation, external signing, mTLS pull/ACK, durable Agent intake, a peer-credential-checked Helper socket, and an HTTPS Master lease checkpoint. The only exposed action is a fixed read-only service status query. Its implementation and remaining gates are tracked in [the Phase 2 progress record](docs/phase-2-progress.md); deployment configuration is in [Phase 2 operations](docs/phase-2-operations.md). Cancellation/skip delivery, an independent external time source, failure/recovery drills, and formal security acceptance remain open. A successful build does not constitute phase exit or production approval.

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

Agent enrollment requires a TLS-enabled Master, an operator-provisioned Master server certificate, a pre-trusted CA file on the Agent, and a separate node-client CA. Private key files must be readable only by the Master account. See [Phase 1 operations](docs/phase-1-operations.md) for the exact flags and trust responsibilities.

The Agent takes `-master https://<master-host>:<port>`, `-server-ca <trusted-master-ca.pem>`, and on first registration `-invite-file <restricted-file>`. It generates an Ed25519 private key locally, submits a CSR, and persists its client certificate and key under `/var/lib/mcui-agent/identity.json` (or the `MCUI_AGENT_STATE` override). It authenticates heartbeats and certificate rotation with mTLS; it has no bearer-token runtime mode.

## Security boundary

- The Master exposes login, bootstrap, scoped node inventory/detail, audit, invitation, disable, mTLS enrollment, heartbeat, certificate rotation, and optional status-task create/list/detail and Agent delivery/ACK routes. A narrow HTTPS Helper checkpoint accepts only the exact currently leased status task. The signer API is loopback-only and accepts only `core.status` task messages.
- TLS mode uses TLS 1.3 and validates Agent client certificates against the configured node CA. Configure it directly; reverse-proxy TLS termination is not supported by this baseline.
- Existing nodes from the legacy bearer-token schema are marked for re-enrollment during migration. Legacy bearer-token hashes are not carried into the normalized schema.
- SQLite entities are stored in versioned tables. The migration is covered by code tests; a snapshot and non-overwriting restore-candidate tool is available; production backup and disaster recovery have not been completed or rehearsed.
- The node CA private key is loaded by the Master to issue/rotate node certificates. Keep it separate from the Master TLS key and from all future task/release signing keys. Offline key custody and disaster recovery remain design decisions.
- This is not production release approval. See [Phase 0/1 status](docs/phase-0-1-implementation.md), the [phased workflow](docs/phased-development-workflow.md), and the design documents for open gates.

## Components

- `cmd/panel`: TLS-capable Master panel/API server; loopback-only development HTTP mode
- `cmd/agent`: Core-free Agent enrollment, mTLS heartbeat/rotation, and status-task client
- `cmd/mcui-helper`: root-owned Linux status Helper with a fixed Unix socket and systemd query mapping
- `cmd/mcui-signerd`: isolated loopback-only status-task signing process
- `internal/store`: versioned SQLite schema and legacy-state migration
- `internal/master`: bootstrap, MFA sessions, scoped reads, invites, disable, and mTLS identity endpoints
- `internal/protocol`: signed-message schema validation and canonicalization, including status-only V2
- `internal/taskauth`, `internal/taskcontrol`, `internal/tasksigner`: status verification, V1 cancel/skip verification primitives, and a narrow status signer; cancel/skip verification is not connected to runtime
- `internal/taskledger`, `internal/taskslots`, `internal/taskdispatch`, `internal/agenttasks`: durable status-task intake, delivery, ACK, and Helper checkpoint flow
- `internal/helper`: Linux-only peer credential and task verification boundary; runs fixed read-only status queries and fails closed on uncertain ledger state
- `internal/checkpoint`: experimental transition model requiring an independently trusted authority and durable local journal
- `internal/checkpointstore`, `internal/checkpointjournal`: experimental SQLite authority and journal primitives; not independently deployed, authenticated or connected to runtime
- `web`: Vue administration panel
