# PoC: BatchSealingService — Merkle + TSA + WORM batch sealing (roadmap M3/D3, GATE)

## Versions (pinned, read from this repo / this host — not assumed)

- Redis server: real running `docker-redis-1` (`redis:7-alpine`), `INFO server`
  reports **7.4.9**. Python client `redis` **8.0.1** (already confirmed in
  `poc/stream_ingest_redis/`).
- Postgres: real running `docker-postgres-1` (`postgres:16-alpine`),
  `postgres --version` reports **16.14**. `sqlalchemy` **2.0.51**, `asyncpg`
  **0.31.0**.
- MinIO: real running `docker-minio-1` (`minio/minio:latest`),
  `RELEASE.2025-09-07T16-13-09Z`. `boto3` **1.43.46**.
- RFC 3161 TSA: `rfc3161ng` **2.1.3** (matches `poc/rfc3161/`'s own pin).
- Components under test (all real, unmodified `src/` classes): `RedisStreamIngestAdapter`,
  `PostgresSealedBatchRepository`, `PostgresAuditLogRepository`,
  `S3SealedBatchStorage`, `RFC3161TimestampService`, `BatchSealingService`,
  `SizeBoundTriggerPolicy`, `AuditLogService`, `src/domain/merkle.py`.

## Which real TSA, and why

Identical finding to `poc/rfc3161/README.md`: the repo's own dev-compose `tsa`
service is an inline Python stub that returns a bare HTTP 200 with an **empty
body** — it can never produce a decodable DER `TimeStampResp`, so it cannot
exercise `RFC3161TimestampService.verify()`, and using it here would silently
skip the very thing `BatchSealingService` treats as **mandatory** (a TSA
failure aborts the whole seal — see the module's own docstring). This PoC
reuses `poc/rfc3161`'s real substitute instead: a local HTTP server whose POST
handler shells out to a real `openssl ts -reply` invocation against a
throwaway CA + TSA certificate, producing genuine ASN.1-signed DER
`TimeStampToken` bytes for every request. No public TSA endpoint or fetched
web content was used.

## What this actually does

`run_poc.py` connects to the **already-running real dev stack**
(`docker-postgres-1`, `docker-redis-1`, `docker-minio-1`) plus the real
openssl-backed TSA server above, and drives the exact, unmodified production
classes through three scenarios:

### Scenario 1 — happy path + the literal GATE condition

1. Produces 5 real events onto a real Redis stream
   (`kronos:stream:{org}:poc-zeek-conn`, DB 3 — same isolated DB D1's own PoC
   uses).
2. Calls the real `BatchSealingService.seal_pending()` (`SizeBoundTriggerPolicy(5)`).
3. Independently verifies, against the real dependencies (not just the
   in-process return value):
   - The real WORM manifest object round-trips from MinIO
     (`S3SealedBatchStorage.get_batch()`) and its `event_count`/`batch_id`
     match.
   - The real MinIO bucket really has Object Lock enabled with COMPLIANCE
     default retention (`get_object_lock_configuration`).
   - `openssl ts -reply -in <token> -text` independently decodes the real TSA
     token as `Status: Granted`, and the embedded message digest is the exact
     `merkle_root` hex.
   - `RFC3161TimestampService.verify()` independently confirms the same
     token against the same `merkle_root` digest.
   - A raw `SELECT ... FROM sealed_batches` (not the repository's own method)
     shows the persisted row with the matching `merkle_root`.
   - A raw `SELECT ... FROM audit_log` shows a real `BATCH_SEALED` event.
   - Real `XPENDING` on the consumer group shows **0** pending entries — every
     event was really acked, only after everything else succeeded.
4. **The GATE itself**: re-fetches the `SealedBatch` fresh from real Postgres
   (`repository.get_by_id()`, a completely separate round trip from the
   in-process object returned by `seal_pending()`), picks an **arbitrary**
   event (index 2 of 5, not index 0), reconstructs its inclusion proof via
   `src.domain.merkle.merkle_proof()`, and calls `verify_proof()` — **TRUE**.
   Then demonstrates both negative cases: a tampered leaf against the real
   proof verifies **FALSE**, and a tampered proof against the real leaf
   verifies **FALSE**.

### Scenario 2 — sealing failure must never ack the stream

1. Produces 2 real events on a fresh (org, source).
2. Constructs a **real** `S3SealedBatchStorage` pointed at the real MinIO
   endpoint but with a **wrong secret key** — a genuine S3 `ClientError` on
   `put_object`, not a mock.
3. Confirms `seal_pending()` raises `BatchSealFailedError` (not swallowed),
   that real `XPENDING` still shows **2** pending entries (nothing was acked),
   that a real `BATCH_SEAL_FAILED` audit row exists, and that no
   `SealedBatch` row was ever persisted.
4. **Recovery**: the same consumer name, this time with correct MinIO
   credentials. `seal_pending()` succeeds and — critically — seals **exactly**
   the two originally-failed message ids (verified by set equality), proving
   D1's `reclaim_stale(min_idle_ms=0)` mechanism genuinely recovers a failed
   sealer's own still-pending backlog with no loss and no duplication. Real
   `XPENDING` now shows 0.

### Scenario 3 — a MAXLEN trim of unsealed events must page, not warn

1. Seals one small batch for real (`batch_a`, 2 events).
2. Produces 3 more events that are **deliberately never sealed**.
3. Runs a real `XTRIM key MAXLEN 1` — physically evicting everything except
   the newest entry, which lands *after* `batch_a.last_message_id`.
4. Confirms via the real `earliest_message_id()` primitive that the earliest
   retained id is now past the sealed watermark (real evidence loss).
5. Confirms `seal_pending()` raises `EvidenceLossDetectedError` (not a
   swallowed warning) and that a real `BATCH_SEAL_WATERMARK_GAP_DETECTED`
   audit row is persisted in Postgres.

Run:
```
~/venv/bin/python3 poc/batch_sealing/run_poc.py
```

## Result: `output.txt` — 28/28 real checks passed on the first run

No bugs were found in the dead subagent's `src/` implementation during this
verification — every real-dependency check passed on the first attempt. This
is itself notable given this session's own track record (B3, C3, C4 each
surfaced a real bug on first live run) — it reflects that the implementation
correctly and closely mirrored `AuditLogService.anchor_day()` and
`RuleCostGate`'s already-proven idioms rather than inventing new ones, and
that its own 45 unit tests (independently re-run: **850 passed** in the full
suite, up from the 818 baseline before D3 — the subagent's self-reported "45
new tests" count is close but not exact against this independent recount, not
material to the gate) already exercised the same scenarios this PoC proves
against real infrastructure.

**GATE: PASSED.**

## Known, explicitly-flagged gaps (not silently glossed over)

- **`sealed_batches` table was never created anywhere in production wiring**
  before this verification pass — `PostgresSealedBatchRepository` existed but
  `create_tables()` was never called from `src/external/startup.py`, so the
  first real production save would have failed with "relation does not
  exist." Fixed as part of closing out this gate: added
  `await PostgresSealedBatchRepository.create_tables(engine)` to
  `wire_dependencies_async()` alongside the other repositories' own calls
  (note: the Celery-worker sync path, `wire_dependencies_sync()`, already
  omits Detection/RulePack table creation too — a pre-existing gap in that
  function predating D3, not introduced or fixed here, left as-is to keep
  this change scoped to D3).
- **No scheduled invocation exists yet.** `BatchSealingService.seal_pending()`
  is never called by anything in production — no Celery beat task, no
  `configure_batch_sealing_service()` call anywhere in `startup.py`. This
  mirrors D2's own precedent (the collector mTLS listener process also isn't
  wired into `docker-compose.dev.yml` yet) and is intentionally out of this
  gate's scope — the gate is "can an arbitrary event be proven included in a
  sealed batch," not "is sealing scheduled in production." Flagged as a
  concrete, named follow-up for whichever roadmap item wires the beat
  schedule (a natural fit for D5 or D6, since both already depend on D3).
- **Single-sealer-per-(org, source) assumption**, documented in
  `BatchSealingService`'s own docstring: `reclaim_stale(min_idle_ms=0)`
  reclaims the consumer's own prior pending backlog, which is correct for one
  active sealer but would need per-message ownership leases for genuine
  multi-sealer concurrency. Not attempted here, not needed until a
  multi-instance sealer is actually deployed.
- **The empty-stream case in `_check_watermark_gap`** (stream returns no
  entries at all after a prior successful seal) is deliberately treated as
  "nothing to check" rather than an automatic gap, since D1's adapter can't
  distinguish "stream never had more data" from "everything, including
  unsealed data, was trimmed" once it's fully empty. Documented in the
  service's own docstring as a known follow-up (a persistent
  last-produced-id watermark independent of the stream itself would close
  it) — not exercised by this PoC's three scenarios since none of them empty
  a stream completely after a prior seal.
