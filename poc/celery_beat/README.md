# PoC: real Celery beat task bodies against real seeded-stale Postgres rows

## Component pair
`src/external/celery_app.py`'s four beat-scheduled tasks — `abort_orphan_uploads`,
`abort_orphan_parses`, `auto_dispatch_received`, `anchor_audit_log` — run as
the actual, unmodified task functions (not reimplemented), against a real
Postgres 16 + real Redis 7, using `src/external/startup.py`'s real
`wire_dependencies_sync()` (the exact function Celery's `worker_init`
signal calls in production).

## Versions (pinned, read from this repo)
- `postgres:16-alpine`, `redis:7-alpine` (`docker/docker-compose.dev.yml`)
- Same real local `openssl ts`-backed RFC 3161 responder technique as
  `poc/rfc3161/` and `poc/chain_of_custody/` (the repo's own dev-compose
  `tsa` stub returns an empty 200, not a real TimeStampResp — confirmed
  non-functional in `poc/rfc3161/README.md`).

## Why this PoC exists
These four tasks are only ever exercised by Celery's crontab schedule
(hourly/hourly/hourly/daily — `beat_schedule` in `celery_app.py`) or unit
tests that would need to fake the clock. No prior PoC or test had run them
against **real** Postgres rows old enough to actually cross their timeout
cutoffs (2h / 3h / 5min) or a real "yesterday" UTC date boundary — the
exact kind of gap CLAUDE.md Section F exists to catch (a plausible-looking
`cutoff = now() - timedelta(hours=2)` comparison is not verified until it's
run against a row that is really that old).

## What this actually does
`run_poc.sh` starts real Postgres + Redis, exports the full `Settings()`
environment (only `DATABASE_URL`/`REDIS_URL`/`CELERY_*` point at the real
containers; MinIO/Keycloak/Vault/OpenSearch are required fields these four
tasks never touch, so dummy unreachable values are honest, not a shortcut).
`run_poc.py` then:
1. Calls the real `wire_dependencies_sync()` (creates real tables, wires
   the real DI container — including the real `RFC3161TimestampService`
   from `TSA_URL`, exactly as a real worker does at startup).
2. Seeds real `Evidence` rows via the real `PostgresEvidenceRepository.save()`
   — one genuinely stale + one fresh control per state (`UPLOADING`,
   `PARSING`, `RECEIVED`), with real backdated `created_at`/`updated_at`
   (no raw SQL needed — these are plain fields on the domain model, set at
   construction, then persisted as-is).
3. Seeds real audit events via the real `AuditLogService.log(occurred_at=...)`
   — two orgs with events dated **yesterday UTC**, one control org with a
   **today** event only.
4. Starts the real local `openssl ts` TSA responder.
5. Calls the four real task functions **directly** (eager, in-process —
   each already runs its own `asyncio.run()` internally via
   `run_evidence_coro()`, exactly like a real worker executing them).
6. Verifies real Postgres/Redis state afterward.

## Real finding (process, not a product bug): `wire_dependencies_sync()` cannot run inside an active event loop
First attempt wrapped the whole PoC (seeding + task calls) in one
`asyncio.run(seed_and_run())`. `wire_dependencies_sync()` does its own
internal `asyncio.run()` to create tables — nesting `asyncio.run()` calls
raises `RuntimeError: asyncio.run() cannot be called from a running event
loop`. **Fixed** by restructuring into three separate top-level
`asyncio.run()` calls (`seed()`, then the plain synchronous task-function
calls, then `verify()`) orchestrated from a plain sync `main()` — the same
"one `asyncio.run()` per unit of work, never nested" constraint
`run_evidence_coro()` itself already follows for the tasks, confirmed here
to apply to `wire_dependencies_sync()` too.

## Result: 16/16 real checks passed (`output.txt`)
- **`abort_orphan_uploads`**: the real stale (`created_at` 3h old) row is
  correctly transitioned to `ERROR` with `error_reason="upload_timeout"`
  and a real `evidence.error` audit event; the fresh (10min old) control
  row is correctly left untouched — confirms the `>2h` cutoff comparison
  works against genuinely old data, not just unit-tested with a frozen clock.
- **`abort_orphan_parses`**: same shape, `>3h` cutoff on `updated_at`,
  `error_reason="parse_timeout"`, control row untouched.
- **`auto_dispatch_received`**: the real stale (`updated_at` 10min old,
  `>5min` cutoff) `RECEIVED` row triggers a real `dispatch_parse.apply_async()`
  call — confirmed by directly checking `LLEN q.index` on the real Redis
  broker afterward (1, not 0) — genuine end-to-end proof the re-enqueue
  reached the real broker, not just that the task's Python-level counter
  incremented.
- **`anchor_audit_log`**: correctly discovered exactly the two orgs with
  real **yesterday UTC** activity (`list_by_date_range` on the real
  Postgres table), correctly excluded the today-only control org, called
  the real `AuditLogService.anchor_day()` once per discovered org (real
  Merkle root + real TSA call to the local `openssl ts` responder — real
  ASN.1 request/response bytes logged), and the real anchor row persisted
  in Postgres with a real, non-empty TSA token (2269 bytes) matching the
  task's own return value. `verify_chain()` confirms the hash chain is
  still intact after anchoring.

No product bugs found in these four tasks — the previously-found and
already-fixed timezone bug (`date.today()` vs UTC, `poc/full_pipeline/README.md`
finding, fixed in commit referenced there) is confirmed to genuinely stay
fixed under a real run: `anchor_audit_log` anchored `2026-07-21` (yesterday
UTC) correctly, not the wrong day.

## Files
- `run_poc.sh` — full reproducible bootstrap (Postgres + Redis + env) + `run_poc.py`
- `run_poc.py` — the actual verification, using the real task functions and
  real repositories/services throughout
- `output.txt` — captured transcript of the last real run (16/16 passed)

## Cleanup
```bash
docker rm -f kronos-poc-beat-postgres kronos-poc-beat-redis
```
