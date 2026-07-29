# PoC: real Postgres — audit hash-chain concurrency/tamper-evidence + evidence/case CRUD

## Versions
- `postgres:16-alpine` (matches `docker-compose.dev.yml`)

## What this actually does

Uses the **real**, unmodified `PostgresAuditLogRepository`, `AuditLogService`,
`PostgresEvidenceRepository`, `PostgresCaseRepository` against a real
Postgres container — no reimplementation, no mocks. Existing unit tests
only ever exercise these against `InMemoryAuditLogRepository`
(`tests/conftest.py`), so the hash-chain's core compliance guarantee
(CLAUDE.md A.2) — cryptographic tamper-evidence under real concurrent
writers — had never been checked against a real database before this pass.

## Results: 18/18 passed. No bugs found — this component pair is genuinely solid.

1. **Sequential chain correctness**: 5 real events logged, `verify_chain()`
   confirms the hash chain (`row_hash = SHA256(prev_hash || canonical_json)`)
   is intact, `sequence_number` reached 5 exactly.

2. **Real concurrency, same org (the critical test)**: 30 concurrent
   `AuditLogService.log()` calls (real asyncio tasks, real separate pooled
   Postgres connections) against the *same* org. `append_atomic()`'s
   `pg_advisory_xact_lock` design worked exactly as its own comment
   describes: sequence advanced by exactly 30 (35 total, no gaps, no
   duplicates — confirmed by a direct `GROUP BY sequence_number HAVING
   COUNT(*) > 1` query against real Postgres, not just trusting the
   application's own bookkeeping), and the chain still verified intact
   afterward.

3. **Lock scoping is genuinely per-org, not global**: first attempt at this
   check used a flawed comparison (unequal total work between the "one org"
   and "two org" cases) and produced a misleading result — caught and fixed
   before drawing any conclusion (see "Methodology note" below). The
   corrected, fair comparison — same 40 total writes either way — showed 40
   writes to one org (fully serialized) taking meaningfully longer than the
   same 40 writes split across two orgs (which run their two 20-write
   batches in parallel): **5.35x** speedup in the committed run
   (`output.txt`), and a cleaner **16x** in an earlier isolated check with
   more connection-pool headroom (see note). Confirms `_org_lock_key`
   correctly scopes the advisory lock per-org rather than accidentally
   serializing unrelated tenants against each other.

4. **Tamper detection (the actual compliance guarantee) — real proof**: a
   raw SQL `UPDATE audit_log SET details = ...` directly against Postgres,
   completely bypassing the application, was correctly detected by
   `AuditLogService.verify_chain()`: `Hash mismatch at seq=3
   event_id=...`. This is the mechanism the whole hash-chain design exists
   for, and it was never exercised against a real tamper before this PoC.

5. **`PostgresEvidenceRepository` real CRUD**: save → get_by_id → state
   transition via `update()` → cross-org `get_by_id` returns `None` →
   `delete_by_id` → confirmed gone. All real round trips against Postgres.

6. **`PostgresCaseRepository` pagination**: 7 real cases, `page_size=5`
   correctly returns 5 then 2 with no overlap between pages.

## Methodology note: my own first version of the lock-scoping test was wrong

The very first run of Test C compared "20 writes split across 2 orgs" against
"20 writes to 1 org alone" — unequal total work (40 vs 20), so a naive "should
take about the same time" expectation was itself invalid; a >1x slowdown was
guaranteed even with zero cross-org serialization. Caught before drawing a
conclusion, fixed to compare equal total work (40 either way). The *second*
version (still in the full script, `pool_size=20/max_overflow=20`) then
produced a near-1.0 ratio — not because the code serializes across orgs, but
because 40 concurrent tasks exactly saturated a 40-connection pool in both
cases, making pool-checkout contention (identical in both scenarios) the
dominant cost and masking the real difference. Raising the pool to
`pool_size=60/max_overflow=60` (still in `run_poc.py`) removed that
bottleneck and produced the clean 5.35x result in `output.txt`. Documented
here because this is exactly the kind of "my test was plausible-looking but
wrong" mistake this whole initiative exists to catch — including in the
PoCs themselves, not just the code under test.
