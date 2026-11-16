# MCUI Phase 1

A development-first Master + empty Agent baseline. The Agent package contains no proxy Core.

## Development setup

Go 1.24.4 is selected for the initial project baseline. The web package manager is pnpm 12.15.0; dependency versions are pinned in `web/package.json` and `web/pnpm-lock.yaml`.

```sh
cd web
pnpm install --frozen-lockfile
pnpm build
cd ..
go test ./...
go run ./cmd/panel -listen 127.0.0.1:8080 -db ./data/mcui.db -web ./web/dist
```

Set `MCUI_BOOTSTRAP_TOKEN` to a one-time local bootstrap secret before starting the panel. Initialize the first administrator from `/` with a password (12+ characters) and a Base32 TOTP secret. The secret must be provisioned using a trusted local channel; do not use a public HTTP network for bootstrap or login.

Create a node invitation in the panel and run the Agent with `-master http://127.0.0.1:8080 -name <name> -group <group> -invite <token>`. The Agent generates an Ed25519 identity locally, consumes the invitation once, saves the returned bearer token with restrictive file permissions, then sends heartbeats.

## Security and scope limitations

- The current HTTP transport is development-only and defaults to loopback. Do not bind to a public interface or use outside a trusted local environment. HTTP does not protect invitation, password, TOTP, cookie, or node bearer tokens in transit.
- mTLS enrollment, certificate rotation/revocation, MFA rate limiting, full role/resource-scope authorization, persistent task delivery, database backup/recovery drills, and security acceptance tests remain out of scope for this initial scaffold and must be completed before production use.
- Sessions are server-side and revocable, cookies are HttpOnly/SameSite and Secure when HTTPS is used. Browser persistence is not used for credentials.
- SQLite currently stores a single serialized state document in one transaction. A normalized schema/migration set is still required before using this as a production database.
- The bootstrap token must be high entropy and is disabled when unset. Rotate/remove it after the first administrator is created.

## Components

- `cmd/panel`: Master web/API server
- `cmd/agent`: non-root Agent enrollment and heartbeat client
- `internal/store`: SQLite persistence boundary
- `internal/master`: login, MFA, sessions, one-time node invites, read-only inventory/audit, disable endpoint
- `web`: Vue dashboard

No Core install, configuration, or other node side-effect operation is exposed.
