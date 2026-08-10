# PoC: Alembic baseline migration vs. `create_tables()` — real Postgres round-trip

Gap Audit P1-12 / Milestone V4. See `docs/DATABASE_MIGRATIONS.md` for the
resulting developer-facing workflow and `docs/GAP_AUDIT_2026-08.md`'s P1-12
row for the "V4 STATUS" note.

## Versions pinned (per CLAUDE.md §F.2 step 1)

- **Postgres: `postgres:16-alpine`** — matches `docker-compose.dev.yml` /
  `docker-compose.prod.yml` / `docker-compose.test.yml` exactly (all three
  already pin this tag).
- **SQLAlchemy: `sqlalchemy[asyncio]>=2.0`** (`pyproject.toml`, unchanged).
- **Alembic: `alembic>=1.13`** (newly added to `pyproject.toml`). The
  floor version matches this repo's existing loose-pin style (e.g.
  `pydantic>=2.7`). The real version actually installed and exercised in
  every run below is **1.19.1** (current PyPI latest as of this pass,
  confirmed via `pip install alembic` inside the exact runtime image —
  see "Real environment used" below).
- **Python runtime: `cgr.dev/chainguard/python:latest-dev`** (3.14.7 at
  pull time) — the same base image `docker/Dockerfile`'s own builder stage
  uses (`FROM cgr.dev/chainguard/python:latest-dev AS builder`), so this
  PoC ran against the actual pinned-in-this-repo Python/dependency
  resolution path, not a hand-picked local interpreter (the host itself
  only has system Python 3.14 with no project dependencies installed, and
  no python3.11/3.12 available — using the repo's own Docker image instead
  of a local venv is the more faithful "real pinned version" environment
  per CLAUDE.md §F.2, and it's what actually ships).

## Docs actually used (per CLAUDE.md §F.2 step 2)

- Alembic's own cookbook, "Using Asyncio with Alembic":
  https://alembic.sqlalchemy.org/en/latest/cookbook.html#using-asyncio-with-alembic
  — fetched and read directly. `migrations/env.py` follows this documented
  `run_sync()`-based pattern; also cross-checked against the literal output
  of `alembic init -t async <dir>` run against the real installed
  `alembic==1.19.0` package (`/tmp/alembic_template_check/migrations_ref/`
  during this pass) to confirm the fetched doc page matched the actual
  current async template, not a stale copy. No untrusted-content override
  attempts were found on the fetched page (plain technical docs only).
- PyPI (`https://pypi.org/project/alembic/`) via WebSearch, to confirm the
  current real released version (1.19.0 at search time; 1.19.1 was what
  `pip install alembic>=1.13` actually resolved to minutes later — both
  are within the same `>=1.13` floor pin, consistent with this repo's own
  "don't hand-pin to a single patch version" convention for most deps).

## The real architectural fact this PoC had to work around

This repo has **14 separate** `src/adapter/repository/postgres_*.py`
modules, each with its own private `_metadata = sa.MetaData()` + `sa.Table(...)`
Core definitions (no shared declarative `Base`). Confirmed via
`grep -rn "^_metadata = sa.MetaData()" src/adapter/repository/*.py` before
writing any code. Alembic's autogenerate needs ONE `MetaData` to diff
against, so `migrations/target_metadata.py` builds a throwaway **combined**
`MetaData` at import time by copying each already-defined `Table` into it
via `Table.tometadata()` — this does not mutate any repository's own
`_metadata`/`create_tables()` contract (verified: `tests/integration/
conftest.py`'s `postgres_engine` fixture, which calls `create_tables()`
directly, still works unmodified — see "What was NOT changed" below).

No foreign keys exist between any of the 21 tables across these 14 modules
(confirmed via `grep -n "ForeignKey" src/adapter/repository/postgres_*.py`
— zero matches), so there was no cross-table ordering concern for either
`create_all()` or Alembic's generated `op.create_table()` sequence.

## What this PoC actually ran (real containers, real output — not assumed)

`run_poc.sh` is the exact, reproducible script; `output.txt`-equivalent
artifacts are the four files below, each a **real captured run**, not a
description of expected output:

1. **`docker network create kronos-poc-alembic-net`** + a throwaway
   `kronos-poc-alembic-pg` (`postgres:16-alpine`) container — never the
   shared dev stack's `docker-postgres-1`. Two databases created inside it:
   `alembic_target` (empty) and `createall_target` (empty).
2. **`alembic revision --autogenerate -m "baseline schema"`** against the
   empty `alembic_target` — real captured log detected all 21 tables
   correctly (`assets`, `audit_anchor`, `audit_log`, `cases`,
   `dead_letter_events`, `detection_correlations`, `detections`,
   `evidence`, `integration_source_cursors`, `ioc_feed_current_indicators`,
   `ioc_feed_versions`, `ioc_feeds`, `org_quotas`,
   `published_custom_rules`, `rule_pack_versions`, `rule_packs`,
   `sealed_batches`, `structured_artifacts`, `yara_rule_pack_published`,
   `yara_rule_pack_versions`, `yara_rule_packs`) plus every real index —
   the generated file is
   `migrations/versions/20260810_1401_56c861716f8f_baseline_schema.py`
   (committed as the real baseline migration, not regenerated by
   `run_poc.sh` on a re-run — see its own top-of-file note).
3. **`alembic upgrade head`** against `alembic_target` — real captured log:
   `Running upgrade  -> 56c861716f8f, baseline schema`, exit 0.
4. **`create_tables()`** (`run_create_tables.py`) — the exact same 14
   classmethod calls, in the exact same order, `wire_dependencies_async()`
   used before this pass — against `createall_target`. Real captured
   output: `create_tables(): all 14 repositories done`.
5. **`pg_dump --schema-only`** on both databases
   (`alembic_produced_schema.sql`, `create_tables_produced_schema.sql`) —
   kept for human/diff inspection.
6. **A programmatic SQLAlchemy-reflection diff** (`compare_schemas.py`) —
   the actual pass/fail bar, not just "both ran without error": reflects
   both live databases (columns incl. type/nullable/server_default,
   primary key, unique constraints, indexes) and compares table-by-table.
   Real captured output (`schema_comparison_output.txt`):

   ```
   Alembic-produced tables: 21
   create_tables()-produced tables: 21

   Total tables compared: 21
   Mismatches: 0
   RESULT: SCHEMAS ARE IDENTICAL (modulo alembic_version bookkeeping table)
   ```

   The only difference between the two databases at all is Alembic's own
   `alembic_version` bookkeeping table (expected — it doesn't exist in the
   `create_tables()`-only database and is explicitly excluded from the
   comparison for that reason, not hidden).

7. **Idempotency + downgrade sanity check**
   (`idempotency_and_downgrade_output.txt`): `alembic upgrade head` run a
   second time against an already-upgraded database is a real no-op (no
   `Running upgrade` line — nothing to do); `alembic downgrade base`
   really drops all 21 tables (`Running downgrade 56c861716f8f -> ,
   baseline schema`); a third `alembic upgrade head` from that now-empty
   state re-creates everything again identically. This is not part of the
   required proof bar but was cheap to check and rules out an
   accidentally-non-reversible or non-reproducible migration.

## Result

**PASS.** `alembic upgrade head` from empty produces a schema that is
column-for-column, constraint-for-constraint, and index-for-index
identical to today's `create_tables()`-produced schema, across all 21
tables spanning the 14 repository modules.

## What this PoC did NOT verify (explicit gap, not a silent omission)

- **Upgrade-from-an-existing-populated-database path.** This PoC only
  proves the baseline migration is correct against an EMPTY database (the
  actual required proof bar for "is the baseline migration correct").
  It does not simulate "a real deployed KronOS database that already has
  months of `create_tables()`-created schema and real rows in it" being
  stamped to this baseline (`alembic stamp head`) and then later upgraded
  by a second, real, non-baseline migration. That is the correct next real
  test for whoever writes the *second* migration (the first schema change
  after this baseline lands) — see `docs/DATABASE_MIGRATIONS.md`'s
  "Adopting Alembic on an existing deployed database" section, which
  documents the `alembic stamp head` procedure for that case but does not
  claim to have executed it against a real populated database here.
- Multi-process concurrent `alembic upgrade head` (analogous to the
  `acquire_schema_creation_lock()` race `_schema_lock.py` documents for
  concurrent `create_tables()` callers) was not tested. This is a smaller
  real risk than for `create_tables()`: the boot-sequence design adopted
  in this pass (see `docs/DATABASE_MIGRATIONS.md`) runs migrations from
  exactly ONE `migrate` init-container/step before any app/worker process
  starts, so concurrent invocation is not an expected runtime scenario the
  way concurrent `create_tables()` calls from N simultaneously-booting
  processes was.
