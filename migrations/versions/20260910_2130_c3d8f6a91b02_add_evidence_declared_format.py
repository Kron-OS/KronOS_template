"""add evidence.declared_format column

Revision ID: c3d8f6a91b02
Revises: 5a0779975c5a
Create Date: 2026-09-10 21:30:00.000000

Real diagnosis fix (case 43097ab0-aae3-4968-915b-8f0229ac3865): raw memory
dumps have no reliable magic bytes at all, so `MagicByteValidator` only
accepted them by a fixed extension allowlist -- a genuine memory image
uploaded under an unlisted extension (e.g. `ch2.dat`) was flatly rejected
with no recourse. `EvidenceMetadata.declared_format` (`src/domain/
evidence.py`) is an explicit, analyst-declared override (only real value
today: `"memory_dump"`) that lets `MagicByteValidator` and
`ParsingOrchestrationService._detect_parser` bypass normal detection.

Additive, nullable column -- existing rows get `NULL` (meaning "no
override, detect normally"), identical behavior to today.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c3d8f6a91b02"
down_revision: str | Sequence[str] | None = "5a0779975c5a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column("evidence", sa.Column("declared_format", sa.String(length=32), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("evidence", "declared_format")
