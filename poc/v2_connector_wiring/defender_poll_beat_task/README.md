# PoC: Defender poll beat task (Gap Audit V2, fix b)

**Claim under test:** Gap Audit P1-2 -- `configure_defender_poll_source_
from_settings()` registers a real `DefenderPollSource` at process startup,
but nothing in `celery_app.py`'s `beat_schedule` ever called
`IntegrationSourceIngestService.run_poll_cycle()` for it. Setting real
Defender credentials made the source *available*, never *active*.

**Design problem this closes (flagged explicitly in `wire_dependencies_sync
()`'s own 2026-08-09 comment):** the FastAPI process's own
`configure_defender_poll_source_from_settings()` keeps one
process-lifetime `httpx.AsyncClient` alive so
`OAuth2ClientCredentialsOutboundAuthStrategy`'s token cache persists across
calls -- but that client is bound to the event loop that was running when
it was built. Celery tasks each get a fresh event loop via `asyncio.run()`
(`celery_runtime.py`'s own established pattern), so reusing that one
client from inside a beat task risks the same "Future attached to a
different loop" failure class `celery_runtime.py`'s docstring already
documents for Postgres/OpenSearch.

## Design choice made (and why), for the report

**Picked: a fresh, task-scoped `httpx.AsyncClient` (and fresh OAuth2 token
fetch) every poll cycle** (`src/external/celery_defender.py`), not a
dedicated long-lived event-loop thread.

- Microsoft's own v2.0 client-credentials docs (fetched 2026-08-10,
  `https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow`)
  show a real worked example token response: `{"token_type": "Bearer",
  "expires_in": 3599, "access_token": "..."}` -- **`expires_in: 3599`
  seconds, ~60 minutes.**
- The beat task runs every 10 minutes (`celery_app.py`'s
  `poll-defender-alerts` schedule entry). Even a perfectly-working
  cross-cycle token cache would only ever save 5 of every 6 possible token
  fetches at that interval -- losing it costs one extra cheap `POST
  .../oauth2/v2.0/token` per cycle, never more than 6/hour.
- That is a strictly smaller cost than the risk being avoided (a real,
  repeating cross-event-loop `httpx`/`asyncio` failure that could take
  every future poll cycle down until a worker restart).
- A dedicated long-lived event-loop-owning thread was considered and
  rejected for now: more correct in theory, but a genuinely novel addition
  to this codebase's Celery patterns (nothing here runs a background loop
  thread today) for a benefit that doesn't yet justify the added
  operational surface. Worth revisiting only if a future poll-mode
  source's own auth handshake becomes the real bottleneck, which Entra
  ID's token endpoint (a single cheap POST) is not.

Every other loop-bound resource `celery_defender.py`'s
`_run_defender_poll_cycle_async()` touches (Postgres `AsyncEngine`, Redis
client) follows `celery_runtime.py`'s already-established "build fresh
inside this task's own loop, dispose before it exits" shape exactly --
nothing new invented there either.

## What this PoC proves, all for real

Calls the REAL, unmodified `src.external.celery_defender
.run_defender_poll_cycle()` -- the exact function
`celery_app.py`'s `poll_defender_alerts` task body calls -- **twice in a
row**, mirroring two consecutive 10-minute beat firings:

1. **No live Microsoft SaaS call, ever** (a hard invariant of this whole
   initiative). `celery_defender.py`'s own code hardcodes the real
   `login.microsoftonline.com` / `graph.microsoft.com` hostnames -- exactly
   like production. Rather than editing those hostnames out for testing,
   this PoC intercepts at the `httpx` transport layer
   (`httpx.MockTransport`) with a real local handler that implements
   Microsoft's own documented OAuth2 client-credentials and
   `alerts_v2`/`$filter`/pagination contracts (same real, doc-verified
   shapes already used in `poc/integration_source_defender/`). The handler
   asserts on the real hostnames/paths it receives, so this also proves
   the real hardcoded URLs in `celery_defender.py` are what's actually
   requested, not stand-in ones substituted into the code under test.
2. Cycle 1 (no cursor yet): the real stand-in server returns all 4 seeded
   alerts; `run_defender_poll_cycle()` returns `accepted=4`.
3. **Real Postgres cursor persistence**, read back via a completely fresh
   `AsyncEngine`/raw SQL against `integration_source_cursors` (the same
   table fix (c) wires as the live default) -- cursor value after cycle 1
   is exactly the max `lastUpdateDateTime` seen (`2026-08-01T00:15:00...`).
4. **Real Redis stream production**, read back via a real `XLEN` against
   `kronos:stream:{org_id}:ms-defender-alerts` on DB 3
   (`settings.stream_redis_db`'s own default) -- length 4 after cycle 1.
5. Three new alerts are appended to the stand-in server's own live alert
   store between cycles (simulating real alerts arriving at the real
   tenant) -- not injected into the poll response directly.
6. Cycle 2 (10 minutes later, mirrors the real beat schedule): the real
   stand-in server genuinely parses and enforces
   `$filter=lastUpdateDateTime gt 2026-08-01T00:15:00...` against its own
   store and returns only the 3 new alerts; `run_defender_poll_cycle()`
   returns `accepted=3`.
7. Cursor after cycle 2 advances to the new max (`2026-08-01T00:30:00...`);
   Redis stream length is cumulative (7).
8. **Real audit trail**: exactly 2 `integration_source.poll_completed`
   rows exist in the real `audit_log` table for this PoC's own org_id
   after the two cycles (one per real, non-exceptional
   `run_poll_cycle()` call) -- confirms `IntegrationSourceIngestService`'s
   own audit discipline (`INTEGRATION_SOURCE_POLL_COMPLETED`/`_FAILED`)
   fires correctly from inside the Celery-shaped call path, not just the
   FastAPI-shaped one it was originally proven against.
9. **The honest "not configured" skip path**: with `DEFENDER_POLL_ORG_ID`
   unset, `run_defender_poll_cycle()` raises
   `DefenderPollNotConfiguredError` -- exactly what
   `poll_defender_alerts`'s own task body catches and turns into a `0`-return,
   no-op, no retry (mirrors every other beat task's own "repository not
   configured; skipping" idiom in `celery_app.py`).
10. Cleans up its own test rows/keys from the shared dev-stack Postgres/
    Redis afterward.

## Real dependencies used (not mocked)

- **Postgres**: the real, already-running shared dev-stack container
  `docker-postgres-1` (confirmed via `docker ps` before this PoC ran; not
  started/stopped by it), reached at `localhost:5432` (db `kronos`).
  `PostgresAuditLogRepository`/`PostgresSourceCursorRepository` (both real,
  unmodified `src/` classes) do the real writes/reads.
- **Redis**: the real, already-running shared dev-stack container
  `docker-redis-1`, reached at `localhost:6379`, DB 3 (matches
  `settings.stream_redis_db`'s own default). `RedisStreamIngestAdapter`/
  `RedisEventDedupChecker` (both real, unmodified `src/` classes) do the
  real `XADD`/`SET NX EX` calls.
- **`pydantic-settings`**: a real `Settings()` construction from real
  environment variables this script sets (not a `SimpleNamespace` stand-in)
  -- the identical construction `celery_defender.py` performs at real
  task-run time.

Versions pinned: sqlalchemy 2.0.51, asyncpg 0.31.0, redis-py 8.0.1, httpx
0.28.1, celery 5.6.3 (installed venv, matches `pyproject.toml`).

## How to run

```bash
source /home/reca/venv/bin/activate
PYTHONPATH=. python poc/v2_connector_wiring/defender_poll_beat_task/run_poc.py
```

## Real captured output

See `output.txt` in this directory -- last real run, 2026-08-10. All
assertions passed; final line `ALL ASSERTIONS PASSED -- ...`.

## What this motivated in `src/`

- `src/config.py`: two new `Settings` fields, `defender_poll_org_id`
  (which KronOS org this Entra ID app registration's alerts feed belongs
  to -- there is no honest per-alert attribution signal in the payload
  itself, mirrors `IntegrationSourceIdentity`'s own "never from the
  external tool's own payload" invariant) and `defender_poll_source_id`
  (default `"ms-defender-alerts"`).
- `src/external/celery_defender.py` (new module): `run_defender_poll_cycle()`
  and `DefenderPollNotConfiguredError`, following the design choice above.
- `src/external/celery_app.py`: new `poll_defender_alerts` task (every 10
  minutes, `q.index` queue) delegating entirely to
  `celery_defender.run_defender_poll_cycle()`, following the exact
  try/except/retry shape every other beat task in that file already uses.
- `src/external/startup.py`: updated `wire_dependencies_sync()`'s own
  2026-08-09 comment to point at this fix instead of describing it as an
  open follow-up.
