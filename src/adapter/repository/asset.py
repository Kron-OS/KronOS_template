"""Abstract and in-memory Asset repository (roadmap F1).

Mirrors this codebase's dozen other repository pairs (e.g.
``src/adapter/repository/yara_rule_pack.py``): an ABC + a thread-unsafe
in-memory default so DI wiring never hard-fails before Postgres is
configured, plus a real Postgres implementation (``postgres_asset.py``)
for production.

Unlike those append-only repositories, ``upsert`` here really does update
a row in place -- see ``src/domain/asset.py``'s own docstring for why an
``Asset`` is legitimately mutable, not forensic evidence.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from src.domain.asset import Asset


class AssetRepository(ABC):
    """Org-scoped asset-inventory persistence, keyed by (org_id, hostname)."""

    @abstractmethod
    async def upsert(self, asset: Asset) -> Asset:
        """Insert or update the asset for this (org_id, hostname).

        Hostname matching is case-insensitive (``TimelineRecord.host_name``
        values are not reliably normalized to one case across source
        systems) but the returned/stored ``Asset.hostname`` preserves
        whatever case the caller supplied.
        """

    @abstractmethod
    async def get_by_hostname(self, org_id: uuid.UUID, hostname: str) -> Asset | None:
        """Return the asset for this (org_id, hostname), or None if this org
        has no asset record for that hostname -- an honest "no context
        available" state, never a fabricated default."""


class InMemoryAssetRepository(AssetRepository):
    """Thread-unsafe in-memory double for unit tests."""

    def __init__(self) -> None:
        self._assets: dict[tuple[uuid.UUID, str], Asset] = {}

    async def upsert(self, asset: Asset) -> Asset:
        self._assets[(asset.org_id, asset.hostname.lower())] = asset
        return asset

    async def get_by_hostname(self, org_id: uuid.UUID, hostname: str) -> Asset | None:
        return self._assets.get((org_id, hostname.lower()))
