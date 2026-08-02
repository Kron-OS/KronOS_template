"""Asset: a real, org-scoped asset-inventory record (roadmap F1).

The first concrete enrichment context source (see
``src/application/enrichment.py``'s own module docstring for why
enrichment itself is derived, additive, and computed once at ingest).
Unlike this codebase's other org-scoped domain rows (``RulePackVersion``,
``YaraRulePackVersion``, ``SealedBatch``), an ``Asset`` is deliberately
**not** append-only/immutable -- it is a live, mutable "current
understanding" of an organization's own asset inventory (a hostname's
owner or criticality legitimately changes over time), not itself forensic
evidence. ``AssetRepository.upsert`` (``src/adapter/repository/asset.py``)
reflects that: it really updates a row in place, keyed on
``(org_id, hostname)``.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, Field


class Asset(BaseModel):
    """One organization's own record of a real asset (host) it owns.

    ``org_id`` is always the authenticated tenant's own value (mirrors
    every other org-scoped domain row in this codebase) -- never anything
    read from event/record content.
    """

    model_config = {"frozen": True}

    asset_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    org_id: uuid.UUID
    hostname: str = Field(min_length=1, description="Matched against TimelineRecord.host_name")
    criticality: str = Field(description="Tenant-defined free-text criticality, e.g. 'high'")
    owner: str | None = None
    environment: str | None = Field(default=None, description="e.g. 'production', 'staging'")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
