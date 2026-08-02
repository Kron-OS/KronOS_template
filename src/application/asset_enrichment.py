"""AssetContextEnricher: the first real, concrete Enricher (roadmap F1).

Looks up a ``TimelineRecord.host_name`` against a real, org-scoped
``AssetRepository`` and attaches the match's own criticality/owner/
environment as derived, ``enrichment.asset.*``-namespaced fields. See
``src/application/enrichment.py``'s own module docstring for the full
design rationale (why ``extra[]``, why computed once at ingest).
"""

from __future__ import annotations

import uuid
from typing import Any

from src.adapter.repository.asset import AssetRepository
from src.application.enrichment import Enricher
from src.domain.timeline import TimelineRecord


class AssetContextEnricher(Enricher):
    """Enriches a record whose ``host_name`` matches a real asset this org owns."""

    def __init__(self, repository: AssetRepository) -> None:
        self._repo = repository

    @property
    def source_name(self) -> str:
        return "asset"

    async def enrich(self, record: TimelineRecord, org_id: uuid.UUID) -> dict[str, Any] | None:
        if not record.host_name:
            return None

        asset = await self._repo.get_by_hostname(org_id, record.host_name)
        if asset is None:
            return None

        result: dict[str, Any] = {
            "enrichment.asset.asset_id": str(asset.asset_id),
            "enrichment.asset.criticality": asset.criticality,
        }
        if asset.owner:
            result["enrichment.asset.owner"] = asset.owner
        if asset.environment:
            result["enrichment.asset.environment"] = asset.environment
        return result
