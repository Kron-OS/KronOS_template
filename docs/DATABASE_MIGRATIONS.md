# Database Migrations (Alembic)

**Status:** Real, adopted (Gap Audit P1-12 / Milestone V4). Replaces the
previous `create_tables()`-only, "tables only, never columns" schema story.
See `poc/alembic_migration_baseline/README.md` for the real verification
this adoption was based on, and `docs/GAP_AUDIT_2026-08.md`'s P1-12 row for
the audit trail.

## The short version

- **Alembic is now the source of truth for schema.** A dedicated
  `db-migrate` container (in every compose file: dev/test/prod) runs
  `alembic upgrade head` to completion, once, before `kronos-backend` or
  any `celery-worker*`/`celery-beat` container starts.
- **`create_tables()` no longer runs at app/worker boot.** The 14
  `src/adapter/repository/postgres_*.py` classmethods themselves still
  exist (unchanged) and are still used directly by
  `tests/integration/conftest.py` for lightweight per-test schema setup —
  they are just no longer called from `src/external/startup.py`.
- **A new column/table = a new Alembic revision, not a `Table(...)` edit
  that "just works" on next boot.** If you add or change a column in any
  `postgres_*.py` repository module, you must also generate and commit a
  migration (see below) — nothing will pick up the change automatically
  anymore.

## Why this design (and not "keep `create_tables()` as a safety net too")

Two designs are both legitimate in general, and both were considered:

1. **Alembic replaces `create_tables()` at boot** (what this repo does).
2. **Keep `create_tables()` running at boot as an idempotent safety net,
   with Alembic layered on top for real schema evolution.**

Option 2 was rejected for this codebase specifically: `create_all(checkfirst
=True)` only ever *adds missing tables* — per this repo's own
long-standing comment, it "only adds missing TABLES, not columns." Running
it *alongside* Alembic at every boot does not add real safety; it adds a
real, silent hazard: if a `db-migrate` step is ever skipped or fails
partway (e.g. a bad deploy script, a missing `IMAGE_TAG` bump), a
brand-new table introduced in the same release would still get created by
`create_tables()`'s own `checkfirst=True` fallback, masking the fact that
the *real* migration never ran. That is exactly the "two sources of truth
for schema, silently drifting" failure mode adopting a real migration tool
exists to prevent — and this repo already has a working precedent for the
alternative (a one-shot init container gating dependent services via
`depends_on: condition: service_completed_successfully`), used today for
`keycloak-init`, `opensearch-init`/`opensearch-security-init`, and
`dashboards-tenant-init`. `db-migrate` follows that exact, already-proven
shape instead of inventing a new one.

## How the boot sequence works now

```
docker compose up
  └─► postgres (healthy)
        └─► db-migrate   (alembic upgrade head; restart: "no"; exits 0)
              └─► kronos-backend, celery-worker, celery-worker-plaso, celery-beat
                    (depends_on: db-migrate: condition: service_completed_successfully)
```

If `db-migrate` fails (bad migration, unreachable Postgres, etc.), Compose
will not start any of the app/worker containers — a loud, visible failure
at `docker compose up` time, not a silent "the new column doesn't exist
yet" bug discovered later in application logs.

## Day-to-day developer workflow

### Adding a new column/table

1. Edit the relevant `src/adapter/repository/postgres_*.py` module's
   `sa.Table(...)` definition (add the column/table) exactly as you always
   did.
2. Generate a migration:
   ```
   make migration msg="add risk_score_v2 to detections"
   ```
   This runs `alembic revision --autogenerate` inside a throwaway
   `db-migrate` container against your running dev Postgres, using the
   combined `MetaData` `migrations/target_metadata.py` builds from all 15
   repository modules (see that file's own docstring for why a combined
   registry is needed — this repo has 15 separate `_metadata = sa.MetaData()`
   registries, not one shared declarative `Base`).
3. **Read the generated file in `migrations/versions/` before committing
   it.** Autogenerate is a diffing tool, not magic — it does not detect
   every change (see "What autogenerate does NOT catch" below), and it
   sometimes proposes a technically-correct-but-suboptimal migration
   (e.g. a column rename it sees as "drop + add", losing data if applied
   naively).
4. Apply it locally: `make migrate` (or just restart your dev stack — the
   `db-migrate` container re-runs on every `docker compose up`, and
   `alembic upgrade head` is a no-op if already at head).
5. Commit the generated file under `migrations/versions/` alongside your
   `postgres_*.py` change, in the same PR.

### What autogenerate does NOT catch

Per Alembic's own documented limitations (verified against the real
installed `alembic==1.19.1`, not assumed from memory): autogenerate does
not reliably detect table/column **renames** (it proposes drop+add,
which loses data on a populated table), does not detect changes to
**server-side check constraints** in all dialects, and does not manage
plain data migrations (backfills) at all — those require a hand-written
`op.execute(...)` step in the generated revision. If your change is a
rename or needs a backfill, edit the autogenerated file by hand rather
than trusting the diff as-is.

### Applying migrations in each environment

| Environment | How `alembic upgrade head` runs |
|---|---|
| `docker-compose.dev.yml` | Automatic — the `db-migrate` service, gated by `postgres: condition: service_healthy`, runs before `kronos-backend`/`celery-worker*`/`celery-beat`. Also runnable standalone: `make migrate`. |
| `docker-compose.test.yml` | Same pattern — `db-migrate` runs before `kronos-backend`/`celery-worker` in CI. |
| `docker-compose.prod.yml` | Same pattern, using the exact same built/pushed `ghcr.io/.../backend:${IMAGE_TAG}` image as `kronos-backend`/`celery-worker` (command override only — no separate image to keep in sync). **A production deploy that changes schema must ensure `db-migrate` actually completes before rolling `kronos-backend`/`celery-worker` to the new `IMAGE_TAG`** — with plain `docker compose up`, `depends_on: condition: service_completed_successfully` already enforces this ordering; if this deployment ever moves to an orchestrator without that primitive (e.g. a hand-rolled rolling-update script, or Kubernetes without an initContainer/Job equivalent), that ordering guarantee must be re-created there — see `charts/kronos/` if/when a Helm migration hook is added. |

### Rolling back a migration

`alembic downgrade -1` (one revision) or `alembic downgrade base` (all the
way to empty) — real, tested in this pass (see
`poc/alembic_migration_baseline/idempotency_and_downgrade_output.txt`).
Every generated revision has a real `downgrade()` function; whether it is
*safe* to run against a populated table (e.g. dropping a column loses
data) is a case-by-case judgment call the same way it would be for a
hand-written `ALTER TABLE`.

### Adopting Alembic on an existing deployed database

This pass's own verification (`poc/alembic_migration_baseline/`) only
proved the baseline migration against an **empty** database — it was not
run against a real, already-`create_tables()`-populated database with real
rows in it (an explicit, stated gap, not a silent omission). For a real
already-deployed KronOS database, the correct procedure is:

1. Confirm the deployed database's actual schema already matches this
   baseline migration's `upgrade()` exactly (it should, since every column
   this baseline captures is the same set `create_tables()` already
   created there over time) — a `pg_dump --schema-only` diff against
   `poc/alembic_migration_baseline/alembic_produced_schema.sql` is the
   fastest real check.
2. **Do NOT run `alembic upgrade head`** against it — that would try to
   `CREATE TABLE` things that already exist and fail loudly (a safe
   failure, not silent corruption, but still the wrong step).
3. Instead run `alembic stamp head`, which records "this database is
   already at the baseline revision" in `alembic_version` **without**
   running any DDL. From that point on, `db-migrate`'s `alembic upgrade
   head` behaves correctly for every *subsequent* migration.

## Files

- `alembic.ini` (repo root) — configuration; `sqlalchemy.url` is
  intentionally a placeholder (see `migrations/env.py`'s own docstring —
  the real `DATABASE_URL` always comes from the environment, matching
  every other KronOS process, never from a committed ini file).
- `migrations/env.py` — the real async environment, following Alembic's
  own documented "Using Asyncio with Alembic" cookbook recipe.
- `migrations/target_metadata.py` — builds the combined `MetaData`
  autogenerate diffs against, by importing all 15 `postgres_*.py` modules
  and copying (`Table.tometadata()`, non-mutating) their tables into one
  registry. Add a new module here the same release you add a new
  `postgres_*.py` repository.
- `migrations/versions/` — the actual migration files. The first one,
  `..._baseline_schema.py`, captures the full current schema (21 tables
  across all 14 repositories) as of this pass — see
  `poc/alembic_migration_baseline/README.md` for how it was generated and
  verified.
- `migrations/` is **deliberately out of this repo's `ruff`/`mypy`/`black`
  invocation scope** — `Makefile`/CI run `ruff check src/ tests/` (not the
  repo root), matching how this codebase already scopes tooling by
  directory rather than `pyproject.toml` `[tool.*].exclude` patterns.
  Format/lint `migrations/` by hand (`black migrations/`,
  `ruff check --fix migrations/`) if you want it clean — not enforced by
  CI, but recommended, since a generated revision's own formatting can be
  genuinely ugly (long single-line `op.create_table(...)` calls).

## What this pass did NOT verify (explicit, not a silent gap)

- Upgrade-from-a-real-populated-database path (see "Adopting Alembic on an
  existing deployed database" above) — only an empty-database round-trip
  was actually run and verified.
- Concurrent `alembic upgrade head` invocations racing each other (the
  `create_tables()`-era `_schema_lock.py` advisory lock existed for
  exactly this scenario across N simultaneously-booting processes). Not
  expected to occur given the one-shot `db-migrate` init-container design,
  but not load-tested.
