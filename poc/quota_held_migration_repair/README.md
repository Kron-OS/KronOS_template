# PoC: repairing the `evidence.quota_held` schema drift (Milestone Y1)

**Component pair:** Alembic migration ↔ real Postgres 16 (both the
long-lived, drifted shared dev container `docker-postgres-1`, and a fresh
throwaway container simulating a real production first install).

## Background

`migrations/versions/20260816_1113_913567ca653a_add_integration_source_keys_table.py`
(Milestone W8) already found and documented, but deliberately did not fix,
a real drift: the shared dev Postgres container (`docker-postgres-1`) is
stamped at Alembic head yet is missing the `evidence.quota_held` column
that the baseline migration (`56c861716f8f`) defines. The same drift was
rediscovered twice more (Milestone X1's `poc/evidence_download/`, X2a's
`poc/postgres_replication/`), each time routed around with a fresh
throwaway Postgres container rather than fixed.

**Root cause, confirmed directly against the real container (see
`output.txt`):** this container predates this repo's adoption of Alembic.
When the baseline migration was created, this already-existing database
was `alembic stamp`ed to head (standard practice for baselining an
existing DB — `upgrade` would try to `CREATE TABLE` on tables that already
exist) rather than `upgrade`d from empty. But the live `evidence` table on
this container predates the `quota_held` column being added to
`postgres_evidence.py`'s `sa.Table` (task #6, tenant storage quota), and
the pre-Alembic `create_tables()`'s `checkfirst=True` only ever created
missing *tables*, never added missing *columns* — so the column was never
actually added, and stamping recorded this DB as "head" without the drift
being reconciled.

This is a one-time repair, not a systemic risk: a genuinely fresh install's
`db-migrate` init container runs `alembic upgrade head` from an empty
database, so the baseline's own `CREATE TABLE` already includes
`quota_held` correctly. Only this long-lived, pre-Alembic dev database (and
any other environment with the same pre-Alembic history) needs the repair.

## Fix

New migration `20260817_2053_5a0779975c5a_repair_evidence_quota_held_drift.py`,
head after `913567ca653a`. Uses `ALTER TABLE evidence ADD COLUMN IF NOT
EXISTS quota_held boolean NOT NULL DEFAULT false` (not `op.add_column`,
which would error on a fresh DB where the baseline already created the
column) — safe no-op everywhere except the drifted case. `downgrade()` is
deliberately a no-op with a docstring explaining why (dropping a real
baseline column on downgrade would be destructive on any normally
provisioned database).

## How this was verified (real, not assumed)

1. Confirmed the drift directly against the real `docker-postgres-1`
   before writing any code: column absent, `alembic_version` at head.
2. Wrote the migration, ran `alembic upgrade head` (via
   `DATABASE_URL=postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos`,
   the container's published port) against that same real container —
   confirmed the column now exists with correct type/nullable/default, and
   `alembic_version` advanced to the new head.
3. Started a **fresh, throwaway** `postgres:16-alpine` container
   (`kronos-poc-y1-fresh-pg`, port 15433) with an empty database and ran
   the full migration chain from scratch (`baseline -> ... -> this
   migration`) to confirm the new migration's `IF NOT EXISTS` guard is a
   safe no-op on a database where the baseline already created the column
   correctly — no error, correct final column state. Torn down after.
4. Full backend test suite before/after: 1954 passed, 2 skipped both times
   (true no-op delta — no `src/` change, this is a `migrations/`-only fix).

See `output.txt` for the real captured commands/output from steps 1-3.

## How to run

Real commands are in `output.txt`, reproduced from an interactive session
against the real dev stack — this PoC has no separate script since the
"build" was the migration file itself and the verification was running
`alembic upgrade head` twice (once against the real drifted container,
once against a fresh throwaway one).
