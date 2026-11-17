# Stage 2 Helper security boundary

The Linux Helper now has a runtime socket path, restricted to a fixed,
read-only status query. It is not a general command runner and it does not
authorize Core installation, configuration, service changes, arbitrary paths,
units, URLs, executables, shell text, or argv.

## Authorization path

1. `RunSocket` creates only a root-owned Unix socket under a root-owned,
   non-writable parent. Requests are length-limited and have one strict JSON
   shape. The Helper obtains the peer UID from `SO_PEERCRED`; it never trusts a
   UID in the request.
2. The Helper validates the exact signed V2 envelope, node ID, task-purpose
   public key, operation, fixed step fields, validity window, and the Core to
   fixed systemd unit mapping.
3. Before reading status, it sends the exact envelope and current delivery
   lease ID to the configured HTTPS Master origin. TLS 1.3 verifies the
   preconfigured CA and host name. Master checks the exact persisted bytes,
   current unexpired lease, signature and node sequence history, and returns
   its current wall-clock time plus the preceding terminal sequence.
4. Under a root-private ledger lock, the Helper verifies the ledger and time
   high-water mark, stores allowed terminal gaps, and persists a pending record
   before invoking the fixed status reader. A completed result is replayed
   without a second read. An uncertain local ledger state blocks execution.
5. `cmd/mcui-helper` runs `/usr/bin/systemctl show` with fixed properties and
   only one of `xray.service`, `sing-box.service`, or `mita.service`. The
   output is bounded and reduced to a strict fixed-field JSON result.

## Limits and recovery

The online checkpoint is independent of the Agent/Helper host's local ledger,
but it uses the Master task database and the Master system clock. No independent
external trusted time source is configured. Coordinated rollback of Master
state and time, or loss/rollback of both Master and node state, is outside the
current guarantee. The Helper high-water mark remains in the same rollback
domain as its ledger.

The V1 signed cancel/skip control messages are not connected to this runtime.
An expired V2 task can be accepted only as a terminal receipt; it is never
executed. An unexplained Agent sequence gap, damaged ledger, or uncertain Helper
record remains fenced and requires offline inspection. Do not delete or rewrite
the ledger to restore service. The Master task DB and main identity/audit DB are
separate SQLite transactions; authorization is recorded before issuing, while
the later issue event is best-effort. Backup/restore consistency and the
cross-database crash window still require dedicated review.

This package and its tests do not constitute a production security review,
Debian clean-VM installation, systemd sandbox test, or full stage exit. See
[`docs/phase-2-progress.md`](../../docs/phase-2-progress.md) for remaining gates.
