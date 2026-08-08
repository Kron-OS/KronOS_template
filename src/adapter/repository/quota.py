"""Abstract and in-memory OrgQuota repository.

Mirrors the DetectionRepository/SealedBatchRepository pattern: an ABC + a
thread-unsafe in-memory default so DI wiring never hard-fails before
Postgres is configured, plus a real Postgres implementation
(postgres_quota.py) for production. See docs/TENANT_USAGE_QUOTA.md.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from src.domain.quota import OrgQuota


class OrgQuotaRepository(ABC):
    """Per-org storage quota persistence, one row per org that ever had a
    quota configured. Absence of a row means unlimited -- callers must not
    default to a magic number when ``get()`` returns None."""

    @abstractmethod
    async def get(self, org_id: uuid.UUID) -> OrgQuota | None:
        """Return the org's configured quota, or None if never set (unlimited)."""

    @abstractmethod
    async def upsert(self, quota: OrgQuota) -> OrgQuota:
        """Insert or replace the org's quota row."""


class InMemoryOrgQuotaRepository(OrgQuotaRepository):
    """Thread-unsafe in-memory double for unit tests and as the DI default."""

    def __init__(self) -> None:
        self._store: dict[uuid.UUID, OrgQuota] = {}

    async def get(self, org_id: uuid.UUID) -> OrgQuota | None:
        return self._store.get(org_id)

    async def upsert(self, quota: OrgQuota) -> OrgQuota:
        self._store[quota.org_id] = quota
        return quota
