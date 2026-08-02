"""Unit tests for Enricher/EnrichmentPipeline (roadmap M5/F1)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from src.application.enrichment import Enricher, EnrichmentPipeline
from src.domain.timeline import TimelineRecord
from tests.fixtures.factories import make_timeline_record


class _StubEnricher(Enricher):
    def __init__(self, source_name: str, result: dict[str, Any] | None) -> None:
        self._source_name = source_name
        self._result = result
        self.calls: list[tuple[TimelineRecord, uuid.UUID]] = []

    @property
    def source_name(self) -> str:
        return self._source_name

    async def enrich(self, record: TimelineRecord, org_id: uuid.UUID) -> dict[str, Any] | None:
        self.calls.append((record, org_id))
        return self._result


class _FailingEnricher(Enricher):
    @property
    def source_name(self) -> str:
        return "broken"

    async def enrich(self, record: TimelineRecord, org_id: uuid.UUID) -> dict[str, Any] | None:
        raise RuntimeError("boom")


class TestEnrichmentPipeline:
    @pytest.mark.asyncio
    async def test_no_enrichers_returns_record_unchanged(self) -> None:
        pipeline = EnrichmentPipeline([])
        record = make_timeline_record()

        result = await pipeline.enrich(record, uuid.uuid4())

        assert result is record

    @pytest.mark.asyncio
    async def test_no_match_returns_record_unchanged(self) -> None:
        enricher = _StubEnricher("asset", None)
        pipeline = EnrichmentPipeline([enricher])
        record = make_timeline_record()

        result = await pipeline.enrich(record, uuid.uuid4())

        assert result.extra == record.extra
        assert result == record

    @pytest.mark.asyncio
    async def test_real_match_merges_namespaced_keys_into_extra(self) -> None:
        enricher = _StubEnricher("asset", {"enrichment.asset.criticality": "high"})
        pipeline = EnrichmentPipeline([enricher])
        record = make_timeline_record()

        result = await pipeline.enrich(record, uuid.uuid4())

        assert result.extra["enrichment.asset.criticality"] == "high"

    @pytest.mark.asyncio
    async def test_original_record_is_never_mutated(self) -> None:
        enricher = _StubEnricher("asset", {"enrichment.asset.criticality": "high"})
        pipeline = EnrichmentPipeline([enricher])
        record = make_timeline_record()
        original_extra = dict(record.extra)

        await pipeline.enrich(record, uuid.uuid4())

        assert record.extra == original_extra  # frozen input untouched

    @pytest.mark.asyncio
    async def test_every_other_field_is_byte_for_byte_unchanged(self) -> None:
        enricher = _StubEnricher("asset", {"enrichment.asset.criticality": "high"})
        pipeline = EnrichmentPipeline([enricher])
        record = make_timeline_record()

        result = await pipeline.enrich(record, uuid.uuid4())

        assert result.timestamp == record.timestamp
        assert result.message == record.message
        assert result.event_kind == record.event_kind
        assert result.kronos == record.kronos
        assert result.document_id == record.document_id

    @pytest.mark.asyncio
    async def test_namespace_violation_is_dropped_not_applied(self) -> None:
        enricher = _StubEnricher("asset", {"host_name": "attacker-controlled"})
        pipeline = EnrichmentPipeline([enricher])
        record = make_timeline_record()

        result = await pipeline.enrich(record, uuid.uuid4())

        assert "host_name" not in result.extra

    @pytest.mark.asyncio
    async def test_key_collision_with_existing_extra_is_skipped_not_overwritten(self) -> None:
        record = make_timeline_record().model_copy(
            update={"extra": {"enrichment.asset.criticality": "already-set"}}
        )
        enricher = _StubEnricher("asset", {"enrichment.asset.criticality": "high"})
        pipeline = EnrichmentPipeline([enricher])

        result = await pipeline.enrich(record, uuid.uuid4())

        assert result.extra["enrichment.asset.criticality"] == "already-set"

    @pytest.mark.asyncio
    async def test_one_enricher_failing_does_not_prevent_others(self) -> None:
        good = _StubEnricher("asset", {"enrichment.asset.criticality": "high"})
        pipeline = EnrichmentPipeline([_FailingEnricher(), good])
        record = make_timeline_record()

        result = await pipeline.enrich(record, uuid.uuid4())

        assert result.extra["enrichment.asset.criticality"] == "high"

    @pytest.mark.asyncio
    async def test_org_id_passed_through_to_every_enricher(self) -> None:
        enricher = _StubEnricher("asset", None)
        pipeline = EnrichmentPipeline([enricher])
        record = make_timeline_record()
        org_id = uuid.uuid4()

        await pipeline.enrich(record, org_id)

        assert enricher.calls[0][1] == org_id

    @pytest.mark.asyncio
    async def test_multiple_enrichers_compose_additively(self) -> None:
        asset_enricher = _StubEnricher("asset", {"enrichment.asset.criticality": "high"})
        identity_enricher = _StubEnricher("identity", {"enrichment.identity.department": "finance"})
        pipeline = EnrichmentPipeline([asset_enricher, identity_enricher])
        record = make_timeline_record()

        result = await pipeline.enrich(record, uuid.uuid4())

        assert result.extra["enrichment.asset.criticality"] == "high"
        assert result.extra["enrichment.identity.department"] == "finance"
