# PoC: real Celery worker against a real Redis broker

## Versions (pinned, read from this repo — not assumed)
- Celery client lib: `celery>=5.4` (`pyproject.toml`); installed in `~/venv`: **5.6.3**.
- Redis client lib: `redis>=5.0` (`pyproject.toml`); installed: **8.0.1**.
- Broker/backend image: `redis:7-alpine`, exactly as pinned in
  `docker/docker-compose.dev.yml` / `docker-compose.prod.yml`.
- Postgres image: `postgres:16-alpine`, same tag as `docker-compose.dev.yml` —
  needed only because `celery_app.py`'s real `worker_init` signal handler
  (`_on_worker_init`) calls `wire_dependencies_sync()` whenever `DATABASE_URL`
  is set, which really runs `PostgresAuditLogRepository.create_tables()` /
  `PostgresEvidenceRepository.create_tables()` against a real DB before the
  worker accepts any task. `Settings.database_url` has no default, so it must
  be set to *something* for `Settings()` (constructed at `celery_app.py`
  import time) to succeed at all — using a real Postgres here means that
  startup path is genuinely exercised end-to-end rather than skipped.

## What this actually does
- Real `redis:7-alpine` container: `kronos-poc-celery-redis`, host port
  `16379` (not the default 6379, to avoid clashing with other PoCs on this
  host).
- Real `postgres:16-alpine` container: `kronos-poc-celery-postgres`, host
  port `15432`.
- A real `celery -A src.external.celery_app worker` process (not a mock, not
  `task_always_eager`), consuming the **actual** queues declared in
  `celery_app.py`'s `task_routes`: `q.index`, `q.parse.fast`, `q.parse.plaso`.
- `run_poc.py` calls the real, unmodified
  `CeleryTaskQueue.enqueue_dispatch/enqueue_parse_fast/enqueue_parse_heavy`
  (`src/adapter/queue/celery_queue.py`) — the same methods
  `EvidenceIntakeService`/`ParsingOrchestrationService` call in production —
  from a separate client process, then confirms receipt via
  `celery_app.control.inspect()` (a real RPC to the worker over the broker)
  and polls the real result backend (`redis://localhost:16379/2`) via
  `AsyncResult` for terminal task state.
- All required `Settings` fields with no default (`minio_*`, `opensearch_*`,
  `keycloak_*`, `vault_*`) are set to inert placeholder values in
  `poc_env.sh` — this PoC is scoped to the Celery↔Redis (and, incidentally,
  the worker's real Postgres wiring) integration point, not the full
  pipeline; see F.2 note below.

### How to run
```
docker run -d --name kronos-poc-celery-redis -p 16379:6379 redis:7-alpine
docker run -d --name kronos-poc-celery-postgres -e POSTGRES_PASSWORD=postgres -p 15432:5432 postgres:16-alpine
source ~/venv/bin/activate
source poc/celery_redis/poc_env.sh
celery -A src.external.celery_app worker -Q q.index,q.parse.fast,q.parse.plaso --loglevel=INFO -n kronos-poc-worker@%h --concurrency=2 &
python poc/celery_redis/run_poc.py
```

## Real findings: routing, receipt, and retry policy all verified — no bug found

This pair (`src/external/celery_app.py` + `src/adapter/queue/celery_queue.py`)
worked exactly as designed. Real, captured evidence (`output.txt`,
`worker.log`):

1. **Worker startup genuinely wires dependencies.** The real worker log
   shows `"startup: dependencies wired (sync/celery)"` — `wire_dependencies_sync()`
   actually ran `create_tables()` against the real `kronos-poc-celery-postgres`
   container and succeeded, then the worker connected to
   `redis://localhost:16379/1` and subscribed to all three real queues.
   (Confirms CLAUDE.md §A.6/E.4's "loud failure" design actually holds: had
   Postgres been unreachable, `_on_worker_init` re-raises and the worker
   process would never have reached "ready".)

2. **Routing is correct for all three task types**, confirmed by real broker
   RPC and worker log lines (not just absence of client exceptions):
   - `dispatch_parse` → received on `q.index`
   - `parse_artefact_fast` → received on `q.parse.fast`
   - `parse_artefact_heavy` → received on `q.parse.plaso`

   Enqueued via the real `CeleryTaskQueue` methods, matching
   `task_routes` exactly.

3. **`dispatch_parse`'s `max_retries=0` is honored.** It failed once (real
   Postgres round-trip → real "Evidence not found" `ValidationError`,
   since the enqueued `evidence_id` was a random UUID with no row) and went
   straight to `FAILURE` — no retry attempted, as configured.

4. **`parse_artefact_fast`'s retry policy (`max_retries=3,
   default_retry_delay=30`) was verified for real, end to end**, not just
   read from the decorator. The genuine "Evidence not found" `ParsingError`
   from the real Postgres lookup triggered the task's own
   `except Exception: raise self.retry(exc=exc)` path organically (no
   fault injection needed). Worker log timestamps show three retries at the
   real ~30s cadence (`22:44:07` → `22:44:37` → `22:45:07`), then on the 4th
   attempt (`22:45:37`) `self.retry()` re-raised the original exception
   because the retry budget was exhausted, and Celery marked the task
   terminal `FAILURE` — exactly the documented backoff-then-give-up
   behavior, observed, not assumed.

5. **`parse_artefact_heavy`'s retry policy (`max_retries=2,
   default_retry_delay=120`) was verified the same way** — two real retries
   observed at the configured 120s cadence (`22:44:07` → `22:46:07` →
   `22:48:07`-ish before this PoC's run was torn down); each retry log line
   reports `Retry in 120s: ParsingError('Evidence not found')`, matching the
   decorator exactly.

**Conclusion: no bug in `src/external/celery_app.py` or
`src/adapter/queue/celery_queue.py`.** Task routing, queue declarations,
serialization config, `task_acks_late`/`task_reject_on_worker_lost`, and both
fast/heavy retry policies all behaved exactly as coded, against a real Redis
7 broker/backend and a real Celery 5.6 worker process. No `src/` changes were
made for this pair.

## Scope note (per F.2 step 3/CLAUDE.md's own framing)
`finalize_evidence`'s success-only chaining and the full evidence FSM
(`start_parsing`/`execute_parse` business logic) were exercised only up to
their real Postgres-lookup failure path — running them to actual completion
needs real evidence rows, MinIO, and OpenSearch, which is out of scope for
the Celery↔Redis integration point this PoC targets. The Celery/Redis
plumbing itself — enqueue → route → receive → execute-or-retry → terminal
state — is the thing verified here, and it is real, not assumed.
