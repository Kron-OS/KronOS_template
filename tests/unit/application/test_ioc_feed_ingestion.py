"""Unit tests for IOCFeedIngestionService (roadmap M5/F2)."""

from __future__ import annotations

import json
import uuid

import pytest

from src.adapter.repository.ioc_feed import InMemoryIOCFeedRepository
from src.application.ioc_feed_ingestion import IOCFeedIngestionService
from src.domain.ioc_feed import IOCType
from src.exceptions import ValidationError

_SHA256_HEX = "3059be08a17bebc0f4edb82e52a0297f32347b556c474a3f252d3b149a7b17ba"


def _real_bundle_bytes() -> bytes:
    return json.dumps(
        {
            "type": "bundle",
            "id": "bundle--test",
            "objects": [
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": "indicator--10000000-0000-4000-8000-000000000001",
                    "created": "2024-01-01T00:00:00.000Z",
                    "modified": "2024-01-01T00:00:00.000Z",
                    "pattern": "[ipv4-addr:value = '203.0.113.66']",
                    "pattern_type": "stix",
                    "pattern_version": "2.1",
                    "valid_from": "2024-01-01T00:00:00Z",
                    "confidence": 85,
                },
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": "indicator--10000000-0000-4000-8000-000000000002",
                    "created": "2024-01-01T00:00:00.000Z",
                    "modified": "2024-01-01T00:00:00.000Z",
                    "pattern": f"[file:hashes.'SHA-256' = '{_SHA256_HEX}']",
                    "pattern_type": "stix",
                    "pattern_version": "2.1",
                    "valid_from": "2024-01-01T00:00:00Z",
                },
            ],
        }
    ).encode()


class TestIOCFeedIngestionService:
    @pytest.mark.asyncio
    async def test_first_ingestion_creates_version_1(self) -> None:
        repo = InMemoryIOCFeedRepository()
        service = IOCFeedIngestionService(repo)
        org_id = uuid.uuid4()

        version = await service.ingest_stix_bundle(org_id, "my-feed", _real_bundle_bytes())

        assert version.version == 1
        assert version.org_id == org_id
        assert version.source_format == "stix2.1"
        assert len(version.indicators) == 2

    @pytest.mark.asyncio
    async def test_reingesting_same_feed_name_creates_version_2_not_overwrite(self) -> None:
        repo = InMemoryIOCFeedRepository()
        service = IOCFeedIngestionService(repo)
        org_id = uuid.uuid4()

        v1 = await service.ingest_stix_bundle(org_id, "my-feed", _real_bundle_bytes())
        v2 = await service.ingest_stix_bundle(org_id, "my-feed", _real_bundle_bytes())

        assert v1.version == 1
        assert v2.version == 2
        assert v1.feed_id == v2.feed_id

        versions = await repo.list_versions(v1.feed_id)
        assert [v.version for v in versions] == [1, 2]

    @pytest.mark.asyncio
    async def test_different_feed_names_get_independent_version_sequences(self) -> None:
        repo = InMemoryIOCFeedRepository()
        service = IOCFeedIngestionService(repo)
        org_id = uuid.uuid4()

        v_a = await service.ingest_stix_bundle(org_id, "feed-a", _real_bundle_bytes())
        v_b = await service.ingest_stix_bundle(org_id, "feed-b", _real_bundle_bytes())

        assert v_a.feed_id != v_b.feed_id
        assert v_a.version == 1
        assert v_b.version == 1

    @pytest.mark.asyncio
    async def test_malformed_bundle_raises_validation_error_and_creates_no_version(self) -> None:
        repo = InMemoryIOCFeedRepository()
        service = IOCFeedIngestionService(repo)
        org_id = uuid.uuid4()

        with pytest.raises(ValidationError):
            await service.ingest_stix_bundle(org_id, "my-feed", b'{"type": "not-a-bundle"}')

        feed = await repo.get_or_create_feed(org_id, "my-feed")
        assert await repo.get_latest_version(feed.feed_id, org_id) is None

    @pytest.mark.asyncio
    async def test_ingested_indicators_are_immediately_matchable(self) -> None:
        repo = InMemoryIOCFeedRepository()
        service = IOCFeedIngestionService(repo)
        org_id = uuid.uuid4()

        await service.ingest_stix_bundle(org_id, "my-feed", _real_bundle_bytes())

        match = await repo.match_indicator(org_id, IOCType.IP, "203.0.113.66")
        assert match is not None
        assert match.feed_name == "my-feed"
        assert match.indicator.confidence == 85

    @pytest.mark.asyncio
    async def test_cross_org_isolation_real(self) -> None:
        repo = InMemoryIOCFeedRepository()
        service = IOCFeedIngestionService(repo)
        org_a, org_b = uuid.uuid4(), uuid.uuid4()

        await service.ingest_stix_bundle(org_a, "shared-name", _real_bundle_bytes())

        assert await repo.match_indicator(org_b, IOCType.IP, "203.0.113.66") is None
