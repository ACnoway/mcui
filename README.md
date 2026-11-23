# MCUI

MCUI is a lightweight panel for managing proxy services on Linux nodes. The Master manages nodes and Core configuration. Agents connect outbound to the Master, and clients connect directly to the proxy Core on each node.

## V1 deployment target

1. Install one Master with a one-click script or Docker Compose. MCUI publishes Master and Agent packages through GitHub Releases. A fresh Master is reachable only locally. Configure your own HTTPS reverse proxy or configure TLS on the Master to enable public access.
2. Sign in as the single administrator with the generated initial credentials. The installer prints them once in its output, or in the Master container logs for Compose. First sign-in sets a new password and enrolls MFA.
3. Add a node and copy a single installation command from the panel. On a supported Linux host, the command installs and enrolls the Core-free Agent and its restricted Helper, including the required trust configuration.
4. Manage the node from the same administrator account. Pick a Core version, defaulting to the latest verified stable release available for that node. MCUI selects and verifies the official binary package and handles task signing. The panel controls installation, start, stop, upgrade, downgrade, and uninstall.

The first delivery validates this workflow on Xray with a real client connection. The full V1 scope also includes sing-box and mita. The plan covers indexed SQLite access for low-resource hosts and signed updates with recovery. [Product scope](docs/project-overview-and-development-workflow.md) · [Implementation order](docs/phased-development-workflow.md#4-当前开发顺序)

## Current stage

The Master can be built as a systemd installer or a Compose image with local access by default. Both paths initialize a single administrator with mandatory password change and MFA enrollment. Direct TLS and a configured HTTPS reverse proxy support public access. With an approved Agent package and configured enrollment trust, the generated command provisions the node's task public key and optional private Master CA. [Master deployment](docs/master-deployment.md) · [Agent enrollment](docs/phase-1-operations.md)

Phase 3 adds the official Core release catalog, a backup cache, signed Xray lifecycle tasks, and paired Agent/Helper updates with rollback. A single administrator can select a verified Xray version and queue a task through a dedicated signer. A single Master supports the remote workflows with Cloudflare NTS and an optional independent rollback checkpoint. Phase 4 starts with an opt-in SOCKS5 template for Xray `v26.10.31` on Linux amd64. The node administrator approves listening ports and provisions credentials. The panel assigns users to those ports and approves the node-rendered configuration digest. [Xray signing](docs/phase-3-approval.md) · [Controlled SOCKS5 inbound](docs/phase-4-xray-inbound.md) · [Production release](docs/phase-3-release.md#生产发布验收)

## Development checks

For documentation changes, review the diff and check links. For feature changes, run the checks relevant to the change. Use `scripts/check-static.sh` for the full Linux checks.

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

Over HTTPS, a security administrator creates a node and generates a one-time install command after MFA. The command verifies the approved installer SHA-256 before running it. The package sets up a Core-free Agent and a status-only Helper. Older installer packages can use locally provisioned trust. [Agent deployment and migration](docs/phase-1-operations.md)

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
- `internal/checkpoint`, `internal/checkpointstore`, `internal/checkpointjournal`: optional independent rollback checkpoint and its SQLite authority and journal
- `internal/corecatalog`: read-only official GitHub release metadata for Xray, sing-box, and mita; entries are discovery data and do not authorize installation
- `web`: Vue administration panel
