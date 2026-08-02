"""Unit tests for AssetContextEnricher (roadmap M5/F1)."""

from __future__ import annotations

import uuid

import pytest

from src.adapter.repository.asset import InMemoryAssetRepository
from src.application.asset_enrichment import AssetContextEnricher
from src.domain.asset import Asset
from tests.fixtures.factories import make_timeline_record


class TestAssetContextEnricher:
    @pytest.mark.asyncio
    async def test_no_host_name_returns_none(self) -> None:
        repo = InMemoryAssetRepository()
        enricher = AssetContextEnricher(repo)
        record = make_timeline_record()  # host_name is None by default
        assert record.host_name is None

        result = await enricher.enrich(record, uuid.uuid4())

        assert result is None

    @pytest.mark.asyncio
    async def test_no_matching_asset_returns_none(self) -> None:
        repo = InMemoryAssetRepository()
        enricher = AssetContextEnricher(repo)
        org_id = uuid.uuid4()
        record = make_timeline_record().model_copy(update={"host_name": "unknown-host"})

        result = await enricher.enrich(record, org_id)

        assert result is None

    @pytest.mark.asyncio
    async def test_real_match_returns_namespaced_fields(self) -> None:
        repo = InMemoryAssetRepository()
        org_id = uuid.uuid4()
        await repo.upsert(
            Asset(
                org_id=org_id,
                hostname="WIN-DC01",
                criticality="critical",
                owner="it-security",
                environment="production",
            )
        )
        enricher = AssetContextEnricher(repo)
        record = make_timeline_record().model_copy(update={"host_name": "WIN-DC01"})

        result = await enricher.enrich(record, org_id)

        assert result is not None
        assert set(result.keys()) == {
            "enrichment.asset.asset_id",
            "enrichment.asset.criticality",
            "enrichment.asset.owner",
            "enrichment.asset.environment",
        }
        assert result["enrichment.asset.criticality"] == "critical"
        assert result["enrichment.asset.owner"] == "it-security"
        assert result["enrichment.asset.environment"] == "production"
        assert all(key.startswith("enrichment.asset.") for key in result)

    @pytest.mark.asyncio
    async def test_hostname_match_is_case_insensitive(self) -> None:
        repo = InMemoryAssetRepository()
        org_id = uuid.uuid4()
        await repo.upsert(Asset(org_id=org_id, hostname="WIN-DC01", criticality="high"))
        enricher = AssetContextEnricher(repo)
        record = make_timeline_record().model_copy(update={"host_name": "win-dc01"})

        result = await enricher.enrich(record, org_id)

        assert result is not None
        assert result["enrichment.asset.criticality"] == "high"

    @pytest.mark.asyncio
    async def test_optional_fields_absent_when_unset(self) -> None:
        repo = InMemoryAssetRepository()
        org_id = uuid.uuid4()
        await repo.upsert(Asset(org_id=org_id, hostname="host1", criticality="low"))
        enricher = AssetContextEnricher(repo)
        record = make_timeline_record().model_copy(update={"host_name": "host1"})

        result = await enricher.enrich(record, org_id)

        assert result is not None
        assert set(result.keys()) == {"enrichment.asset.asset_id", "enrichment.asset.criticality"}
        assert result["enrichment.asset.criticality"] == "low"

    @pytest.mark.asyncio
    async def test_cross_org_isolation_real(self) -> None:
        """An asset seeded for org A must never enrich a record for org B."""
        repo = InMemoryAssetRepository()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        await repo.upsert(Asset(org_id=org_a, hostname="shared-hostname", criticality="critical"))
        enricher = AssetContextEnricher(repo)
        record = make_timeline_record().model_copy(update={"host_name": "shared-hostname"})

        result_a = await enricher.enrich(record, org_a)
        result_b = await enricher.enrich(record, org_b)

        assert result_a is not None
        assert result_a["enrichment.asset.criticality"] == "critical"
        assert result_b is None
