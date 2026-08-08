# PoC: real tenant storage usage/quota enforcement

Design authority: `docs/TENANT_USAGE_QUOTA.md`. This PoC exercises the
**real, unmodified** `src/` classes this feature added — not reimplemented
logic, not mocks of the exact calls under test — against real Postgres,
real MinIO, and the real (shared, already-running) dev-stack OpenSearch,
then the real Celery task functions from `src/external/celery_app.py`.

## Component pair(s) under test

- `StorageQuotaGate` (+ `TenantUsageService`, `OrgQuotaRepository`) ↔ real
  Postgres 16 — the 1.5x hard ceiling / 1.0x soft ceiling arithmetic
  against a real `SUM(size_bytes)` query.
- `EvidenceIntakeService.request_upload()` (enforcement hook 1) ↔ real
  MinIO — a real presigned PUT that gets genuinely rejected once it would
  cross the hard ceiling.
- `ParsingOrchestrationService.start_parsing()` (enforcement hook 2) ↔ real
  Postgres — an evidence row genuinely held (not parsed) while over the
  soft ceiling, confirmed to never reach `COMPLETE`.
- `auto_resume_quota_held` / `dispatch_parse` / `parse_artefact_fast` (real
  Celery task **functions**, called directly — see "What was NOT verified"
  below) ↔ real Postgres + real Redis broker + real MinIO + real OpenSearch
  — the full autonomous resume-and-parse chain, with **no manual FSM
  mutation by this script** (only Postgres row updates for the quota
  *config* itself, which is exactly what a real admin PATCH would do).

## Versions (pinned, read from this repo)

- `postgres:16-alpine`, `redis:7-alpine`, `minio/minio:latest` — same tags
  as `docker/docker-compose.dev.yml` / `poc/celery_beat/run_poc.sh`.
- OpenSearch: the already-running shared dev-stack instance,
  `opensearchproject/opensearch:2.11.1` (`docker/docker-compose.dev.yml`),
  reused rather than a fresh throwaway container — see "Scope decisions"
  below for why.
- `celery==5.6.3` (installed in `/home/reca/venv`, matches `pyproject.toml`'s
  `celery>=5.4` pin), `sqlalchemy[asyncio]>=2.0`, `asyncpg>=0.29`.

## How to run

```bash
poc/tenant_storage_quota/run_poc.sh
```

Starts three throwaway containers (`kronos-poc-quota-postgres`,
`kronos-poc-quota-redis`, `kronos-poc-quota-minio`), exports the full
`Settings()` environment, runs `run_poc.py`, then tears the three
containers down (set `KRONOS_POC_KEEP_CONTAINERS=1` to keep them for
inspection — used during development of this PoC; the captured
`output.txt` run tore them down after).

## Scope decisions (read before treating this as "the" quota PoC forever)

1. **OpenSearch is the shared dev-stack instance, not a throwaway
   container.** `execute_parse()` (via the real, unmodified
   `celery_runtime.py::_build_task_resources()`) unconditionally builds a
   real `TimelineIngestionService` and calls `ingest_records()` on
   success — reaching a real `COMPLETE` state via the real
   `parse_artefact_fast` task therefore requires a *reachable* OpenSearch,
   unlike `poc/celery_beat`'s four tasks (none of which touch OpenSearch,
   so dummy unreachable values were honest there). Reusing the shared
   cluster only adds one new `kronos-<pocorg>-*` index/DLS role; it never
   reads, modifies, or restarts anything belonging to another org or
   another PoC.
2. **`NoOpScanner`, not real ClamAV.** AV scanning is orthogonal to quota
   logic and already independently verified in `poc/clamav/`; using it
   here is the same "real class already used throughout this codebase's
   own tests, not a mock of the thing under test" pattern `EvidenceIntakeService`
   itself documents (`scanner: AntivirusScanner` is DI-injected precisely
   so this swap needs no source change).
3. **Real Celery task *functions* called directly, not through a live
   worker consuming the broker.** Mirrors `poc/celery_beat/run_poc.py`'s
   own established, documented precedent exactly: eager in-process
   invocation is the correct way to verify task **body** logic against
   real seeded data; verifying that Celery's broker-to-worker dequeue
   mechanism itself works is a different, already-covered concern
   (`poc/celery_redis/`). This PoC does independently confirm the real
   re-enqueue lands on the real broker (`redis-py` `LLEN q.index` check,
   see Step 7b in `output.txt`) before calling the next task function
   directly — so the one hop *not* re-verified here is specifically "a
   live worker process dequeues and dispatches that exact message," not
   "does the message really reach Redis."

## What this actually does (see `output.txt` for the full real captured run)

1. Real `EvidenceIntakeService.request_upload()` → real presigned-URL PUT
   to real MinIO → `start_intake()` (falls back to running
   `process_intake()` inline, its own documented behavior with no
   `task_queue` configured) → a real 1000-byte evidence row reaches
   `RECEIVED` in real Postgres.
2. Real `evidence_repo.get_total_size_bytes(org_id)` (a real
   `SUM(size_bytes) ... WHERE state != 'PURGED'` query) returns exactly
   1000.
3. A real quota (`storage_quota_bytes=1000`) is upserted via
   `PostgresOrgQuotaRepository`. A second real upload of 600 more bytes
   (1000+600=1600 > 1.5×1000=1500) is genuinely rejected —
   `StorageQuotaExceededError` raised for real, carrying the real
   `current_usage_bytes`/`quota_bytes` numbers, and a real
   `QUOTA_UPLOAD_DENIED` audit event persisted.
4. A real upload of 400 more bytes (1000+400=1400 ≤ 1500) is accepted and
   reaches `RECEIVED` — real usage is now 1400, at/above the 1.0×1000 soft
   ceiling.
5. `wire_dependencies_sync()` (the real function Celery's `worker_init`
   signal calls) wires the DI container exactly as a real worker would.
   The real `dispatch_parse` task is called directly on the second
   evidence row: `ParsingOrchestrationService.start_parsing()` genuinely
   holds it — real Postgres row stays `RECEIVED` with `quota_held=True`,
   confirmed **not** `COMPLETE`, and a real `QUOTA_INGESTION_HELD` audit
   event is persisted (re-read from a fresh Postgres connection).
6. The quota is raised for real (`storage_quota_bytes=1_000_000`) via a
   second real `PostgresOrgQuotaRepository.upsert()` call — the same
   mutation the admin `PATCH /api/admin/org/quota` route performs.
7. The real `auto_resume_quota_held` beat task is called directly — **no
   FSM mutation happens in this script**; it only re-checks
   `is_ingestion_held()` (now `False`) and re-enqueues via a real
   `CeleryTaskQueue`, confirmed to land as a real message on the real
   Redis broker (`LLEN q.index` == 1).
8. The real `dispatch_parse` task (the same function a live worker
   consuming that exact message would run) clears `quota_held`, logs a
   real `QUOTA_INGESTION_RESUMED` event, and transitions the evidence to
   `PARSING` — genuinely calling the real `CloudTrailParser`.
9. The real `parse_artefact_fast` task runs `execute_parse()` against the
   real evidence bytes in MinIO, indexes into the real OpenSearch cluster,
   and the evidence reaches real `COMPLETE`.
10. A totally separate, fresh script/connection (not the PoC's own
    verification helpers) independently re-reads the org's full 17-event
    audit trail and final quota/usage numbers straight from Postgres —
    reproduced at the bottom of `output.txt`'s capture session (see the
    "Independent re-read" lines).

**Result: 22/22 checks passed.** See `output.txt` for the full real
captured stdout of the run (JSON-structured log lines from the real
`AuditLogService`/OpenSearch client included, not trimmed).
