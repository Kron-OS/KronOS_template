"""Unit tests for IOCMatchEnricher (roadmap M5/F2)."""

from __future__ import annotations

import uuid

import pytest

from src.adapter.repository.ioc_feed import InMemoryIOCFeedRepository
from src.application.ioc_enrichment import IOCMatchEnricher
from src.domain.ioc_feed import IOCFeedVersion, IOCIndicator, IOCType
from src.domain.timeline import TimelineRecord
from tests.fixtures.factories import make_timeline_record

_SHA256_HEX = "3059be08a17bebc0f4edb82e52a0297f32347b556c474a3f252d3b149a7b17ba"


async def _seed_feed(
    repo: InMemoryIOCFeedRepository, org_id: uuid.UUID, name: str, indicators: list[IOCIndicator]
) -> None:
    feed = await repo.get_or_create_feed(org_id, name)
    await repo.save_version(
        IOCFeedVersion(
            feed_id=feed.feed_id,
            version=1,
            org_id=org_id,
            source_format="stix2.1",
            indicators=tuple(indicators),
        )
    )


def _record_with_extra(**extra: object) -> TimelineRecord:
    return make_timeline_record().model_copy(update={"extra": extra})


def _record_with_sha256(sha256: str) -> TimelineRecord:
    base = make_timeline_record()
    return base.model_copy(update={"kronos": base.kronos.model_copy(update={"sha256": sha256})})


class TestIOCMatchEnricher:
    @pytest.mark.asyncio
    async def test_no_candidate_fields_returns_none(self) -> None:
        repo = InMemoryIOCFeedRepository()
        enricher = IOCMatchEnricher(repo)
        base = make_timeline_record()
        record = base.model_copy(update={"kronos": base.kronos.model_copy(update={"sha256": ""})})

        result = await enricher.enrich(record, uuid.uuid4())

        assert result is None

    @pytest.mark.asyncio
    async def test_no_matching_indicator_returns_none(self) -> None:
        repo = InMemoryIOCFeedRepository()
        enricher = IOCMatchEnricher(repo)
        record = _record_with_extra(**{"source.ip": "10.0.0.1"})

        result = await enricher.enrich(record, uuid.uuid4())

        assert result is None

    @pytest.mark.asyncio
    async def test_real_source_ip_match_returns_namespaced_fields(self) -> None:
        repo = InMemoryIOCFeedRepository()
        org_id = uuid.uuid4()
        await _seed_feed(
            repo,
            org_id,
            "poc-feed",
            [
                IOCIndicator(
                    ioc_type=IOCType.IP, value="203.0.113.66", confidence=85, description="C2 IP"
                )
            ],
        )
        enricher = IOCMatchEnricher(repo)
        record = _record_with_extra(**{"source.ip": "203.0.113.66"})

        result = await enricher.enrich(record, org_id)

        assert result is not None
        assert result["enrichment.ioc.matched"] is True
        assert result["enrichment.ioc.ioc_type"] == "ip"
        assert result["enrichment.ioc.value"] == "203.0.113.66"
        assert result["enrichment.ioc.feed_name"] == "poc-feed"
        assert result["enrichment.ioc.confidence"] == 85
        assert result["enrichment.ioc.description"] == "C2 IP"
        assert all(key.startswith("enrichment.ioc.") for key in result)

    @pytest.mark.asyncio
    async def test_destination_ip_also_checked(self) -> None:
        repo = InMemoryIOCFeedRepository()
        org_id = uuid.uuid4()
        await _seed_feed(
            repo, org_id, "f", [IOCIndicator(ioc_type=IOCType.IP, value="198.51.100.7")]
        )
        enricher = IOCMatchEnricher(repo)
        record = _record_with_extra(**{"destination.ip": "198.51.100.7"})

        result = await enricher.enrich(record, org_id)

        assert result is not None
        assert result["enrichment.ioc.value"] == "198.51.100.7"

    @pytest.mark.asyncio
    async def test_domain_match_is_case_insensitive(self) -> None:
        repo = InMemoryIOCFeedRepository()
        org_id = uuid.uuid4()
        await _seed_feed(
            repo, org_id, "f", [IOCIndicator(ioc_type=IOCType.DOMAIN, value="evil.test")]
        )
        enricher = IOCMatchEnricher(repo)
        record = _record_with_extra(**{"url.domain": "EVIL.TEST"})

        result = await enricher.enrich(record, org_id)

        assert result is not None
        assert result["enrichment.ioc.ioc_type"] == "domain"

    @pytest.mark.asyncio
    async def test_evidence_file_sha256_match(self) -> None:
        repo = InMemoryIOCFeedRepository()
        org_id = uuid.uuid4()
        await _seed_feed(
            repo,
            org_id,
            "f",
            [IOCIndicator(ioc_type=IOCType.FILE_HASH_SHA256, value=_SHA256_HEX)],
        )
        enricher = IOCMatchEnricher(repo)
        record = _record_with_sha256(_SHA256_HEX)

        result = await enricher.enrich(record, org_id)

        assert result is not None
        assert result["enrichment.ioc.ioc_type"] == "sha256"
        assert result["enrichment.ioc.value"] == _SHA256_HEX

    @pytest.mark.asyncio
    async def test_sha256_match_takes_priority_over_ip_when_both_would_match(self) -> None:
        """Most-specific-first priority: a file hash match must win over an
        IP match on the same record (see this module's own docstring)."""
        repo = InMemoryIOCFeedRepository()
        org_id = uuid.uuid4()
        await _seed_feed(
            repo,
            org_id,
            "f",
            [
                IOCIndicator(ioc_type=IOCType.FILE_HASH_SHA256, value=_SHA256_HEX),
                IOCIndicator(ioc_type=IOCType.IP, value="203.0.113.66"),
            ],
        )
        enricher = IOCMatchEnricher(repo)
        record = _record_with_sha256(_SHA256_HEX).model_copy(
            update={"extra": {"source.ip": "203.0.113.66"}}
        )

        result = await enricher.enrich(record, org_id)

        assert result is not None
        assert result["enrichment.ioc.ioc_type"] == "sha256"

    @pytest.mark.asyncio
    async def test_optional_fields_absent_when_unset(self) -> None:
        repo = InMemoryIOCFeedRepository()
        org_id = uuid.uuid4()
        await _seed_feed(
            repo, org_id, "f", [IOCIndicator(ioc_type=IOCType.IP, value="203.0.113.66")]
        )
        enricher = IOCMatchEnricher(repo)
        record = _record_with_extra(**{"source.ip": "203.0.113.66"})

        result = await enricher.enrich(record, org_id)

        assert result is not None
        assert "enrichment.ioc.confidence" not in result
        assert "enrichment.ioc.description" not in result
        assert "enrichment.ioc.source_ref" not in result

    @pytest.mark.asyncio
    async def test_cross_org_isolation_real(self) -> None:
        repo = InMemoryIOCFeedRepository()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        await _seed_feed(
            repo, org_a, "f", [IOCIndicator(ioc_type=IOCType.IP, value="203.0.113.66")]
        )
        enricher = IOCMatchEnricher(repo)
        record = _record_with_extra(**{"source.ip": "203.0.113.66"})

        result_a = await enricher.enrich(record, org_a)
        result_b = await enricher.enrich(record, org_b)

        assert result_a is not None
        assert result_b is None

    @pytest.mark.asyncio
    async def test_source_name_is_ioc(self) -> None:
        assert IOCMatchEnricher(InMemoryIOCFeedRepository()).source_name == "ioc"
