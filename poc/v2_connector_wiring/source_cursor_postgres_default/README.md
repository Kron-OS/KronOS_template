# PoC: SourceCursorRepository Postgres round-trip (Gap Audit V2, fix c)

**Claim under test:** Gap Audit P1-8 -- `SourceCursorRepository`'s live DI
default was `InMemorySourceCursorRepository`, so any poll-mode source's
cursor (Defender's included) was lost on every backend/worker restart.
`PostgresSourceCursorRepository` already existed and was unit-tested, but
was never wired as the real default anywhere `configure_dependencies()` is
actually called from a real startup path.

**Versions pinned:** sqlalchemy 2.0.51, asyncpg 0.31.0 (installed venv,
matches `pyproject.toml`), against `postgres:16-alpine`
(`docker/docker-compose.dev.yml`'s own pinned image tag) -- the real,
already-running shared dev-stack container `docker-postgres-1` (confirmed
via `docker ps` before this PoC ran; NOT started or stopped by this PoC,
per CLAUDE.md's "never touch containers you didn't create" rule -- this
PoC only opens/disposes its own `AsyncEngine`s against that existing
container's exposed `localhost:5432`).

## What this proves

`run_poc.py` does NOT just call `.get()`/`.upsert()` on one repository
instance (that would only prove the SQL is well-formed, not that data
persists across a real restart). It:

1. Builds engine #1 + `PostgresSourceCursorRepository` #1, confirms no
   cursor exists yet for a fresh random `(org_id, source_id)`.
2. Upserts a real cursor value.
3. **Fully disposes engine #1** (closes the connection pool -- the
   equivalent of the owning process exiting).
4. Builds a **completely separate** engine #2 + repository #2 -- no
   shared Python object, no cached connection, nothing in common with
   step 1-3 except the same Postgres DSN.
5. Reads the cursor back via repository #2 and asserts the exact value
   matches -- this is the real "survives a fresh repository
   instantiation" claim CLAUDE.md SS F requires, not an assumption.
6. Upserts a second time via repository #2 to prove the
   `ON CONFLICT DO UPDATE` path overwrites the same row rather than
   erroring or duplicating.
7. Deletes its own test row so no PoC artifact is left behind in the
   shared dev-stack database.

## How to run

```bash
source /home/reca/venv/bin/activate
PYTHONPATH=. python poc/v2_connector_wiring/source_cursor_postgres_default/run_poc.py
```

Requires the dev-stack Postgres container (`docker-postgres-1`) already
running and reachable at `localhost:5432` (db `kronos`, user `kronos`,
password `kronos_dev_password` per `docker/docker-compose.dev.yml`).

## Real captured output

See `output.txt` in this directory -- last real run, 2026-08-10. All 9
steps passed; final line `ALL ASSERTIONS PASSED.`

## What this motivated in `src/`

- `src/external/dependencies.py`: `configure_dependencies()` gained a new
  `source_cursor_repository: SourceCursorRepository | None = None`
  parameter, following the exact same "`None` means keep the current
  binding" idiom every other optional Postgres-backed repository param
  on that function already uses (e.g. `org_quota_repository`,
  `detection_repository`) -- not a new pattern.
- `src/external/startup.py` `wire_dependencies_async()` (the FastAPI
  process, which owns one long-lived event loop for its whole lifetime):
  now constructs a real `PostgresSourceCursorRepository(engine)`, calls
  `.create_tables(engine)` alongside every other repository's own
  `create_tables()` call, and passes it into `configure_dependencies()`
  -- so any FastAPI-served route that resolves
  `get_source_cursor_repository()` (currently only
  `get_integration_source_ingest_service`, the PUSH ingest route) now
  gets the real, persistent, Postgres-backed repository instead of the
  process-local `InMemorySourceCursorRepository` it silently fell back
  to before.
- `src/external/startup.py` `wire_dependencies_sync()` (the Celery
  `worker_init` path): only gained a `PostgresSourceCursorRepository
  .create_tables(engine)` call inside its own throwaway-engine
  `_create_tables()` helper -- it deliberately does NOT configure a
  process-wide Postgres-backed singleton here, for the exact same
  documented reason `_org_quota_repository` doesn't either: Postgres
  repositories built from a pooled engine are loop-bound, and Celery
  tasks each get their own fresh event loop via `asyncio.run()`. The
  Defender poll beat task (fix b, `src/external/celery_defender.py`)
  therefore builds its own throwaway `PostgresSourceCursorRepository`
  fresh per invocation, exactly mirroring how `celery_runtime.py`
  already does this for `PostgresOrgQuotaRepository`/
  `PostgresEvidenceRepository`/etc.
- The raw module-level default in `dependencies.py`
  (`_source_cursor_repository: SourceCursorRepository =
  InMemorySourceCursorRepository()`) was intentionally left unchanged --
  every other Postgres-backed repository in this container (evidence,
  detection, org quota, ...) follows the identical "in-memory literal
  default, only ever overridden for real by an explicit
  `wire_dependencies_*()` call at real startup" shape; changing just
  this one literal would have been inventing a new, inconsistent pattern
  instead of closing the actual gap (the missing real-startup wiring).
