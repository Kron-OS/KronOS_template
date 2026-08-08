# PoC: IntegrationSource foundation (roadmap Q1)

**Objective.** Prove the `IntegrationSource` ABC + registry +
`IntegrationSourceIngestService` + pluggable auth strategies +
`SourceCursorRepository` work end to end for BOTH real shapes this
foundation must support (PUSH webhook and POLL-with-cursor), against real
local dependencies -- never a live third-party SaaS (roadmap SS1 invariant
#9).

## What's verified here vs. what isn't

This PoC exercises the **foundation** (`GenericWebhookPushSource`/
`GenericPollSource`, not a named vendor -- Wazuh/Defender are Q2/Q4). It
proves the plumbing (auth -> dedup -> backpressure -> produce -> audit;
cursor persistence across poll cycles) is real and correct. It does **not**
prove any specific vendor's real wire format (that's each Q2+ connector's
own PoC).

## Versions pinned

- `httpx` >=0.27 (pyproject.toml) -- the real HTTP client for the outbound
  poll call and the PoC's own inbound test client.
- `uvicorn` >=0.30 (pyproject.toml) -- the real ASGI server hosting the
  actual `create_app()` FastAPI app for the push scenario.
- `fastapi` >=0.111 (pyproject.toml).
- Python stdlib `http.server.ThreadingHTTPServer` -- the real local
  stand-in for the external tool's own poll API (same idiom already used
  by `poc/detection_ticket_integration/`).
- Postgres: whatever `docker-postgres-1` (the already-running shared dev
  stack, `docker_default` network) is running -- reused as-is, not a fresh
  testcontainer, since this is a one-off adapter check, not a full
  integration-test suite addition.

## How to run

Requires Python with the project's `[dev]` extras installed (this sandbox
has no host Python venv; the exact commands used to produce `output.txt`
ran inside a throwaway `python:3.12-slim`-based image with `pip install
'.[dev]'`, attached to the already-running dev stack's `docker_default`
network so `postgres`/`redis`/etc. hostnames resolve):

```bash
# (a) PUSH shape -- needs the full app's settings env vars (DATABASE_URL etc.,
#     same values docker-compose.dev.yml already uses) since create_app()
#     does full startup wiring; only the integration-source-specific
#     dependencies are overridden with real in-memory doubles.
python poc/integration_source_foundation/run_poc_push.py

# (b) POLL shape -- fully self-contained, no external services needed at all
#     (constructs its own real local HTTP server).
python poc/integration_source_foundation/run_poc_poll.py

# (c) PostgresSourceCursorRepository -- needs DATABASE_URL pointed at a real
#     Postgres reachable on the network (used the already-running dev stack's).
python poc/integration_source_foundation/run_poc_postgres_cursor.py
```

## What each script actually proves (see `output.txt` for the real captured run)

### (a) `run_poc_push.py` -- PUSH webhook shape

A REAL `uvicorn.Server` is started on `127.0.0.1` with a real ephemeral
port, hosting the real `create_app()` FastAPI app with the real
`POST /api/integrations/push/{source_type}` route
(`src/external/routes/integration_source_push.py`) wired to the real
`GenericWebhookPushSource` + `StaticApiKeyInboundAuthenticator` +
`IntegrationSourceIngestService` + `AuditLogService`. A REAL
`httpx.AsyncClient` then makes REAL HTTP POST requests over a REAL TCP
socket (not `ASGITransport`, not `TestClient`) proving, with real captured
status codes/bodies:

1. A single bare-JSON event is accepted (202, `accepted: true`).
2. The exact same body POSTed again is deduped (`duplicate: true`,
   `accepted: false`, no second stream produce) -- the SHA-256-over-raw-
   bytes dedup key works for real.
3. A `{"events": [...]}` batch envelope is split into 3 independently
   produced events.
4. A wrong API key is rejected 401 -- never reaches the service.
5. A correct key but mismatched `source_type` in the URL path is rejected
   403 -- a key provisioned for `generic-webhook` cannot be replayed
   against a different source_type's route.
6. The real `InMemoryStreamIngestAdapter`'s own stream length for
   `(org_id, source_id)` is exactly 4 (1 + 0 + 3) after all calls --
   confirms `org_id`/`source_id` came from the authenticated identity, not
   the request body (which claimed a different `org_id`/`source_id` and
   was ignored).
7. Exactly 3 real `AuditEvent`s of type `integration_source.push_ingested`
   were written (once per HTTP call that reached the service -- including
   the deduped one, which is still audited with `accepted_count: 0`).

### (b) `run_poc_poll.py` -- POLL-with-cursor shape

A REAL stdlib `ThreadingHTTPServer` on `127.0.0.1` serves a real, fixed
3-page pagination fixture (`GET /events?cursor=<token>` ->
`{"events": [...], "next_cursor": "<token>"}`, real `Authorization: Bearer
<key>` check, real 401 on a wrong key). The real `GenericPollSource`
(a real `httpx.AsyncClient` making real GET requests) and the real
`IntegrationSourceIngestService.run_poll_cycle()` are run across 3 real
poll cycles using a real `InMemorySourceCursorRepository`, proving:

- Cycle 1 passes `cursor=None` (first-ever poll) -> server returns page 1
  (2 events) + `next_cursor="page-2"` -> persisted.
- Cycle 2 passes `cursor="page-2"` (the REAL persisted watermark from
  cycle 1, not a hardcoded value) -> server returns page 2 (1 event) +
  `next_cursor="page-3"` -> persisted.
- Cycle 3 passes `cursor="page-3"` -> server returns an empty page ->
  the cursor is correctly **not** advanced (`cursor_advanced=False`) --
  proves `PollFetchResult`'s own "never advance on no real progress"
  contract, not just its docstring claim.
- Final persisted cursor is `"page-3"`, final real stream length is
  exactly 3 (2 + 1 + 0).
- Exactly 3 real `AuditEvent`s of type `integration_source.poll_completed`
  were written, one per cycle (including the empty one).
- A separate real call with a deliberately wrong bearer token gets a real
  401 from the real stand-in server, which surfaces as a real, observed
  `IntegrationSourceError` (never a silently-empty result) -- CLAUDE.md
  invariant #8 (fail loudly), and would (per `run_poll_cycle`'s own code
  path, exercised in the application-layer unit tests, not re-proven here
  to avoid a second server) audit an `INTEGRATION_SOURCE_POLL_FAILED`
  event before re-raising.

### (c) `run_poc_postgres_cursor.py` -- PostgresSourceCursorRepository

Real `asyncpg`/SQLAlchemy connection to the already-running shared dev
Postgres (`docker-postgres-1`). Real `CREATE TABLE IF NOT EXISTS
integration_source_cursors`, a real `get()` on a never-seen pair (returns
`None`, not a fabricated default), a real `INSERT`, a real
`ON CONFLICT DO UPDATE`, and real `SELECT`s confirming both. Cleans up its
own row afterward (leaves the table itself in place, matching every other
`create_tables()`-style repository's convention in this codebase).

## Judgment calls / honesty notes

- **In-memory storage doubles inside the push scenario's app, not
  Postgres/Redis.** The actual bytes-over-the-wire integration this PoC
  needs to prove is the HTTP request/response contract and the
  auth/dedup/backpressure/audit *orchestration logic* -- swapping
  `InMemoryStreamIngestAdapter`/`InMemoryEventDedupChecker`/
  `InMemoryAuditLogRepository` in for their real Redis/Postgres
  counterparts is the exact same PoC-tier bar `poc/collector_ingest_mtls/`
  and `poc/detection_ticket_integration/` already established as
  legitimate (those real backends are independently, already verified in
  `poc/stream_ingest_redis/` and their own repositories' own tests) --
  doing it again here would re-verify Redis/Postgres, not this feature.
  The Postgres-specific adapter (`PostgresSourceCursorRepository`) IS
  separately verified for real in (c), since that file's own real SQL had
  never been run before this pass.
- **`run_poc_push.py` logs one harmless startup warning**
  (`"startup wiring failed: 2 validation errors for Settings ...
  celery_broker_url/celery_result_backend"`) -- `create_app()`'s lifespan
  tries the full production DI wiring (including Celery, which this
  minimal PoC's env vars don't configure) and degrades gracefully; it does
  not affect any of the routes this PoC exercises, all of which use
  `dependency_overrides`. Flagged here rather than silently ignored,
  per CLAUDE.md's "no confident-sounding gaps" rule -- this is pre-existing
  `create_app()` behavior, not something this pass introduced or fixed.
