# Development-only helper: security gate

The exported socket execution path is disabled and returns reconciliation even
for an authorized peer. Do not enable it for a runtime or treat this package as
production-ready.

The local ledger and its time high-water mark are in the same rollback domain.
Restoring an older structurally valid ledger can erase both; the high-water mark
only detects backward time relative to the surviving ledger, not ledger rollback.
Runtime requires a genuinely independent trusted freshness checkpoint with a
reviewed crash-consistent protocol covering every state transition, initial
provisioning, loss and recovery. No such mechanism is implemented here.
TrustedTimeHealthy is only an input contract; no trusted clock health provider is
implemented, and a caller returning true is not proof of clock trust.

Agent sequence slots can expire without reaching the helper. The helper requires
consecutive sequences and has no signed gap/skip authorization, so the next
slot remains blocked; it must not silently skip. A failed status read or a crash
with a pending record also blocks subsequent work. There is no authorized
reconciliation or retry procedure; do not delete or rewrite the ledger to clear
it. Safe recovery and signed gap semantics require protocol design and review
before the socket execution gate can be removed.
