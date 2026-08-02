"""Unit tests for InMemoryAssetRepository (roadmap M5/F1)."""

from __future__ import annotations

import uuid

import pytest

from src.adapter.repository.asset import InMemoryAssetRepository
from src.domain.asset import Asset


class TestInMemoryAssetRepository:
    @pytest.mark.asyncio
    async def test_upsert_then_get_by_hostname(self) -> None:
        repo = InMemoryAssetRepository()
        org_id = uuid.uuid4()
        asset = Asset(org_id=org_id, hostname="host1", criticality="high")

        await repo.upsert(asset)

        assert await repo.get_by_hostname(org_id, "host1") == asset

    @pytest.mark.asyncio
    async def test_get_by_hostname_case_insensitive(self) -> None:
        repo = InMemoryAssetRepository()
        org_id = uuid.uuid4()
        asset = Asset(org_id=org_id, hostname="WIN-DC01", criticality="high")
        await repo.upsert(asset)

        assert await repo.get_by_hostname(org_id, "win-dc01") is not None

    @pytest.mark.asyncio
    async def test_unknown_hostname_returns_none(self) -> None:
        repo = InMemoryAssetRepository()
        assert await repo.get_by_hostname(uuid.uuid4(), "nope") is None

    @pytest.mark.asyncio
    async def test_upsert_updates_existing_asset_in_place(self) -> None:
        """Unlike this codebase's append-only repositories, an Asset is
        legitimately mutable -- see src/domain/asset.py's own docstring."""
        repo = InMemoryAssetRepository()
        org_id = uuid.uuid4()
        original = Asset(org_id=org_id, hostname="host1", criticality="low")
        await repo.upsert(original)

        updated = Asset(org_id=org_id, hostname="host1", criticality="critical")
        await repo.upsert(updated)

        result = await repo.get_by_hostname(org_id, "host1")
        assert result is not None
        assert result.criticality == "critical"

    @pytest.mark.asyncio
    async def test_cross_org_isolation(self) -> None:
        repo = InMemoryAssetRepository()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        await repo.upsert(Asset(org_id=org_a, hostname="shared", criticality="critical"))

        assert await repo.get_by_hostname(org_b, "shared") is None
