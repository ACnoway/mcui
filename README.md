# MCUI

MCUI is a lightweight panel for managing proxy services on Linux nodes. The Master manages nodes and Core configuration. Agents connect outbound to the Master, and clients connect directly to the proxy Core on each node.

## V1 deployment target

1. Start the Master with Docker Compose. The default image comes from GitHub Container Registry and starts on loopback. Give the HTTPS Compose overlay a public hostname to connect remote Agents.
2. Sign in as the single administrator with the generated initial credentials. The installer prints them once in its output, or in the Master container logs for Compose. First sign-in sets a new password and enrolls MFA.
3. Add a node and copy a single installation command from the panel. On a supported Debian host, the command verifies the matching GitHub Release installer, passes the deployment's public keys, and enrolls the Core-free Agent and its restricted Helper.
4. Manage the node from the same administrator account. Pick a Core version, defaulting to the latest verified stable release available for that node. MCUI selects and verifies the official binary package and handles task signing. The panel controls installation, start, stop, upgrade, downgrade, and uninstall.

The first delivery validates this workflow on Xray with a real client connection. The full V1 scope also includes sing-box and mita. The plan covers indexed SQLite access for low-resource hosts and signed updates with recovery. [Product scope](docs/project-overview-and-development-workflow.md) · [Implementation order](docs/phased-development-workflow.md#4-当前开发顺序)

## Current stage

Compose automatically generates independent status and Core management signing keys and keeps them in its persistent volume. The release workflow publishes the generic Debian Agent installer with the matching Master image. The systemd installer supports explicit configuration and separately managed signers. [Master deployment](docs/master-deployment.md) · [Agent enrollment](docs/phase-1-operations.md#节点首次接入) · [GitHub publishing](docs/phase-3-release.md)

Phase 3 adds the official Core release catalog, a backup cache, signed Xray lifecycle tasks, and paired Agent/Helper updates with rollback. The Compose Master uses Cloudflare NTS when issuing tasks. Advanced deployments can separate the signers and use an independent rollback checkpoint. Phase 4 starts with an opt-in SOCKS5 template for Xray `v26.10.31` on Linux amd64. The node administrator approves listening ports and provisions credentials. The panel assigns users to those ports and approves the node-rendered configuration digest. [Xray signing](docs/phase-3-approval.md) · [Controlled SOCKS5 inbound](docs/phase-4-xray-inbound.md) · [Production release](docs/phase-3-release.md#生产发布验收)

The panel opens on the node overview. Use the node list for Agent enrollment and Core lifecycle operations. Proxy Configuration can create Xray loopback inbounds, publish Trojan/TLS, and configure IPv4 TCP outbounds and routes on newly enrolled Debian amd64 nodes. It also supports editing grants from an existing node catalog. Settings contains the audit log, Core releases, task history, and administrator management. [Frontend design](docs/frontend-design.md) · [Xray inbound creation](docs/phase-4-xray-inbound.md#从主控添加入站)

Administrators can create an Xray client on the Master and bind it to both panel-defined and node-catalog inbounds on multiple nodes. The panel can issue one subscription for the client and a separate HTTPS share link for each applied inbound. For a panel-defined inbound, the administrator can rotate the credential and issue a 24-hour setup link that the recipient can use once the revision is applied. [Client subscriptions](docs/phase-4-xray-inbound.md#客户端订阅)

Updated panel-defined nodes support multiple clients per inbound. An administrator can assign one client to several nodes and generate a separate credential and setup link for each selected inbound. Removing a binding keeps the other clients on that inbound active after the revised configuration is applied. [Multi-client inbounds](docs/phase-4-xray-inbound.md#从主控添加入站)

Proxy Configuration shows sampled inbound, client, and outbound bytes for the node's applied revision. The client list combines available samples across nodes. [Xray traffic](docs/phase-4-xray-inbound.md#用户级统计与额度) · [3x-ui feature roadmap](docs/phased-development-workflow.md#阶段-4xray-完整业务闭环与最小演示)

## Releases

Push a tag such as `v0.1.0-alpha.1` to build the Linux amd64 and arm64 Master and Agent packages and publish a GitHub pre-release. Stable deployment releases are published after the offline-signed manifest is available. [Release tags and publishing](docs/phase-3-release.md#标签和预发布)

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
