"""add connector_configs table

Revision ID: 33dfde5b0b1f
Revises: c3d8f6a91b02
Create Date: 2026-09-18 01:30:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "33dfde5b0b1f"
down_revision: str | Sequence[str] | None = "c3d8f6a91b02"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "connector_configs",
        sa.Column("org_id", sa.UUID(), nullable=False),
        sa.Column("source_type", sa.String(length=64), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("non_secret_fields", sa.JSON(), nullable=False),
        sa.Column("secret_field_names", sa.JSON(), nullable=False),
        sa.Column("consecutive_failure_count", sa.Integer(), nullable=False),
        sa.Column("auto_disabled_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("created_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("updated_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("org_id", "source_type"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("connector_configs")
