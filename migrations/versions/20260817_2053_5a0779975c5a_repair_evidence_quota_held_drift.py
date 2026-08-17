"""repair pre-existing evidence.quota_held column drift

Revision ID: 5a0779975c5a
Revises: 913567ca653a
Create Date: 2026-08-17 20:53:00.000000

Milestone Y1 (Gap Audit follow-up). Root-causes and fixes a drift first
noted (but deliberately not fixed) in 913567ca653a's own docstring, and
rediscovered twice more since (Milestone X1's `poc/evidence_download/`,
X2a's `poc/postgres_replication/`): the shared dev Postgres container
(`docker-postgres-1`) is stamped at Alembic head yet is missing the real
`evidence.quota_held` column that the baseline migration
(56c861716f8f) defines.

Confirmed root cause: `docker-postgres-1` predates this repo's adoption of
Alembic (docs/DATABASE_MIGRATIONS.md). When the baseline migration was
created, this already-existing database was `alembic stamp`ed to head
rather than `upgrade`d from empty -- standard practice when baselining an
existing DB, since `upgrade` would try to `CREATE TABLE` on tables that
already exist. But this database's live `evidence` table predates the
`quota_held` column being added to `postgres_evidence.py`'s own
`sa.Table` (Milestone task #6, tenant storage quota), and
`create_tables()`'s `checkfirst=True` (the pre-Alembic bootstrap
mechanism) only ever created missing *tables*, never added missing
*columns* to an existing one -- so the live column was never added, and
stamping recorded this DB as "head" without the drift ever being
reconciled. Confirmed directly against the real container before writing
this migration:

    $ docker exec docker-postgres-1 psql -U kronos -d kronos -tAc \\
        "SELECT column_name FROM information_schema.columns \\
         WHERE table_name='evidence' AND column_name='quota_held';"
    (no rows)
    $ docker exec docker-postgres-1 psql -U kronos -d kronos -tAc \\
        "SELECT version_num FROM alembic_version;"
    913567ca653a

This is a real, one-time repair, not a systemic risk: a genuinely fresh
install's `db-migrate` init container runs `alembic upgrade head` from an
empty database, so the baseline migration's own `CREATE TABLE` already
includes `quota_held` correctly on any new deployment. Only this specific
long-lived, pre-Alembic dev database (and any other environment with the
same pre-Alembic history) needs this repair. `ADD COLUMN IF NOT EXISTS` is
used (not `op.add_column`, which would error on a fresh DB where the
baseline already created the column) so this migration is a safe no-op
everywhere except the drifted case it exists to fix.
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "5a0779975c5a"
down_revision: str | Sequence[str] | None = "913567ca653a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(
        "ALTER TABLE evidence ADD COLUMN IF NOT EXISTS quota_held boolean NOT NULL DEFAULT false"
    )


def downgrade() -> None:
    """Downgrade schema.

    Deliberately a no-op: `quota_held` is a real baseline column
    (56c861716f8f) on every database except the one drifted case this
    migration repairs. Dropping it here would destroy a real, in-use
    column on any normally-provisioned database that happens to downgrade
    past this revision.
    """
