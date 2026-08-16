"""add integration_source_keys table

Revision ID: 913567ca653a
Revises: 56c861716f8f
Create Date: 2026-08-16 11:13:39.934155

Milestone W8 (Gap Audit P1-7): real per-(org, source) inbound-push API-key
provisioning storage -- see
src/adapter/repository/postgres_integration_source_key.py's own module
docstring. Only the SHA-256 hash of each key is ever persisted (never the
plaintext) -- ``key_hash`` is unique+indexed so
``IntegrationSourceKeyRepository.get_by_key`` is a real, exact-match lookup.

Hand-edited after ``alembic revision --autogenerate``: the raw diff against
this dev database's live schema also proposed ``ADD COLUMN evidence.
quota_held`` -- real, pre-existing drift on this shared dev Postgres
unrelated to this change (that table predates the ``quota_held`` column
being added to ``postgres_evidence.py``'s own ``sa.Table`` and was never
migrated since `create_tables()`'s ``checkfirst=True`` only adds missing
*tables*, never columns -- see docs/DATABASE_MIGRATIONS.md's own "Why this
design" section). Deliberately NOT folded into this revision -- an
unrelated drift discovered by accident while adding a new table is not the
same change and does not belong in the same, focused migration; flagged
here rather than silently carried along.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "913567ca653a"
down_revision: str | Sequence[str] | None = "56c861716f8f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "integration_source_keys",
        sa.Column("org_id", sa.UUID(), nullable=False),
        sa.Column("source_id", sa.String(length=256), nullable=False),
        sa.Column("source_type", sa.String(length=128), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("org_id", "source_id"),
    )
    op.create_index(
        op.f("ix_integration_source_keys_key_hash"),
        "integration_source_keys",
        ["key_hash"],
        unique=True,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f("ix_integration_source_keys_key_hash"), table_name="integration_source_keys")
    op.drop_table("integration_source_keys")
