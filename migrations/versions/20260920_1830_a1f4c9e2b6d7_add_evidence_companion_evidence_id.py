"""add evidence.companion_evidence_id column

Revision ID: a1f4c9e2b6d7
Revises: 4f0a3d08ee60
Create Date: 2026-09-20 18:30:00.000000

Real diagnosis fix (poc/volatility_vmware_companion/): a VMware .vmem
memory image needs its .vmsn/.vmss companion co-located on disk under a
matching basename for volatility3's own VmwareStacker to correctly
interpret memory regions -- confirmed live that most linked-list-walk
Linux plugins return zero rows without it, and real, non-zero rows with
it. Since each evidence upload is currently processed as a fully
independent object with no relationship to any other, there was no way
to associate an already-uploaded companion file with an existing
evidence item.

`companion_evidence_id` is a nullable self-referential FK to another row
in this same table (same tenant, enforced at the application layer via
ParsingOrchestrationService.attach_companion_and_reparse, not a DB
constraint, since org_id isolation is already a WHERE-clause concern
everywhere else in this codebase, not a cross-table FK concern). Generic,
not VMware-specific -- any future parser needing a second file could use
the same relationship. Additive, nullable -- existing rows get NULL
(no companion), identical behavior to today.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1f4c9e2b6d7"
down_revision: str | Sequence[str] | None = "4f0a3d08ee60"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "evidence",
        sa.Column(
            "companion_evidence_id",
            sa.UUID(as_uuid=True),
            sa.ForeignKey("evidence.evidence_id"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("evidence", "companion_evidence_id")
