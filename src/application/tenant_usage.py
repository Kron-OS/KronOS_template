"""TenantUsageService: computes real current per-org storage usage.

See docs/TENANT_USAGE_QUOTA.md §2. Deliberately the simplest correct
implementation -- a real SUM(size_bytes) query scoped to non-purged
Evidence for an org, computed fresh on every call. No maintained running
counter/cache: that would be an optimization with its own real
invalidation-correctness risk (evidence deleted, purged, or erroring
concurrently with a quota check), not justified without evidence a plain
SUM query is actually too slow (CLAUDE.md: don't design for hypothetical
future requirements).
"""

from __future__ import annotations

import uuid

from src.adapter.repository.evidence import EvidenceRepository


class TenantUsageService:
    """Computes an org's real current storage usage from Evidence rows."""

    def __init__(self, evidence_repository: EvidenceRepository) -> None:
        self._repo = evidence_repository

    async def get_current_usage_bytes(self, org_id: uuid.UUID) -> int:
        """Return the sum of ``size_bytes`` for all non-purged evidence in *org_id*."""
        return await self._repo.get_total_size_bytes(org_id)
