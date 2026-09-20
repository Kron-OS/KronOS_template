"""add sealed_batches.source_type column

Revision ID: 4f0a3d08ee60
Revises: 33dfde5b0b1f
Create Date: 2026-09-19 09:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "4f0a3d08ee60"
down_revision: str | Sequence[str] | None = "33dfde5b0b1f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("sealed_batches", sa.Column("source_type", sa.String(length=128), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("sealed_batches", "source_type")
