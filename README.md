# MCUI Master and empty Agent

MCUI is a multi-Core control plane in staged development. This repository currently contains the Master panel, a Core-free Agent identity client, and Phase 0 protocol schema/vector work. It does not contain task delivery, a Helper, Core installation, or Core configuration operations.

## Current stage

Phase 0 design preparation and Phase 1 implementation are in progress. The work and its evidence are tracked in [Phase 0/1 implementation status](docs/phase-0-1-implementation.md). Human security review, the supported platform/Core matrix, backup recovery, and clean Linux deployment evidence remain release gates.

## Development checks

The baseline selects Go 1.24.4 and pnpm 12.15.0; see [development baseline](docs/development-baseline.md). From the repository root:

```sh
go vet ./...
go test ./...
node scripts/verify-protocol-vectors.mjs
cd web
pnpm install --frozen-lockfile
pnpm build
```

## Local panel mode

HTTP mode is loopback-only and for panel development. It cannot enroll Agents. Build the UI, then run:

```sh
go run ./cmd/panel -listen 127.0.0.1:8080 -db ./data/mcui.db -web ./web/dist
```

Provide a one-time `MCUI_BOOTSTRAP_TOKEN` through a trusted local mechanism, then initialize the first administrator in the panel with a 12+ character password and a Base32 TOTP secret. The bootstrap account is a global `security_admin`; scoped administrator provisioning is not yet available in the UI.

## TLS panel and Agent enrollment

Agent enrollment requires a TLS-enabled Master, an operator-provisioned Master server certificate, a pre-trusted CA file on the Agent, and a separate node-client CA. Private key files must be readable only by the Master account. See [Phase 1 operations](docs/phase-1-operations.md) for the exact flags and trust responsibilities.

The Agent takes `-master https://<master-host>:<port>`, `-server-ca <trusted-master-ca.pem>`, and on first registration `-invite-file <restricted-file>`. It generates an Ed25519 private key locally, submits a CSR, and persists its client certificate and key under `/var/lib/mcui-agent/identity.json` (or the `MCUI_AGENT_STATE` override). It authenticates heartbeats and certificate rotation with mTLS; it has no bearer-token runtime mode.

## Security boundary

- The Master exposes login, bootstrap, scoped node inventory/detail, audit, invitation, disable, mTLS enrollment, heartbeat, and certificate rotation endpoints. No task polling, task signing, Helper, or Core operation route exists.
- TLS mode uses TLS 1.3 and validates Agent client certificates against the configured node CA. Configure it directly; reverse-proxy TLS termination is not supported by this baseline.
- Existing nodes from the legacy bearer-token schema are marked for re-enrollment during migration. Legacy bearer-token hashes are not carried into the normalized schema.
- SQLite entities are stored in versioned tables. The migration is covered by code tests; a backup and disaster-recovery procedure has not been implemented or rehearsed.
- The node CA private key is loaded by the Master to issue/rotate node certificates. Keep it separate from the Master TLS key and from all future task/release signing keys. Offline key custody and disaster recovery remain design decisions.
- This is not production release approval. See [Phase 0/1 status](docs/phase-0-1-implementation.md), the [phased workflow](docs/phased-development-workflow.md), and the design documents for open gates.

## Components

- `cmd/panel`: TLS-capable Master panel/API server; loopback-only development HTTP mode
- `cmd/agent`: Core-free Agent enrollment, mTLS heartbeat, and certificate rotation client
- `internal/store`: versioned SQLite schema and legacy-state migration
- `internal/master`: bootstrap, MFA sessions, scoped reads, invites, disable, and mTLS identity endpoints
- `internal/protocol`: Phase 0 signed-message schema validation and canonicalization; not connected to runtime task execution
- `web`: Vue administration panel
