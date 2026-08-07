"""Unit tests for MeanTimeToDetectCalculator (roadmap M8/I2)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from src.adapter.opensearch.client import InMemoryOpenSearchClient
from src.adapter.repository.detection import InMemoryDetectionRepository
from src.application.metric_mttd import MeanTimeToDetectCalculator
from src.domain.detection import Detection
from tests.fixtures.factories import make_tenant_context

_INDEX = "kronos-testorg-case-11111111-1111-4111-8111-111111111111-202601"


def _detection(
    org_id: uuid.UUID, finding_id: str, matched_doc_ids: tuple[str, ...], synced_at: datetime
) -> Detection:
    return Detection(
        org_id=org_id,
        org_alias="testorg",
        finding_id=finding_id,
        detector_name="kronos-testorg-windows-detector",
        source_index=_INDEX,
        matched_document_ids=matched_doc_ids,
        finding_timestamp=synced_at,
        synced_at=synced_at,
    )


class TestMeanTimeToDetectCalculator:
    @pytest.mark.asyncio
    async def test_no_detections_reports_unavailable(self) -> None:
        calc = MeanTimeToDetectCalculator(InMemoryDetectionRepository(), InMemoryOpenSearchClient())
        result = await calc.compute(make_tenant_context())

        assert result.value is None
        assert result.sample_size == 0
        assert "No synced Detection" in result.unavailable_reason

    @pytest.mark.asyncio
    async def test_computes_real_delta_from_matched_document_timestamp(self) -> None:
        tenant = make_tenant_context()
        detection_repo = InMemoryDetectionRepository()
        timeline_index = InMemoryOpenSearchClient()

        event_time = datetime(2026, 1, 1, tzinfo=UTC)
        synced_at = event_time + timedelta(seconds=120)
        await timeline_index.bulk_index([(_INDEX, "doc-1", {"@timestamp": event_time.isoformat()})])
        await detection_repo.save(_detection(tenant.org_id, "finding-1", ("doc-1",), synced_at))

        result = await MeanTimeToDetectCalculator(detection_repo, timeline_index).compute(tenant)

        assert result.value == pytest.approx(120.0)
        assert result.sample_size == 1
        assert result.unit == "seconds"

    @pytest.mark.asyncio
    async def test_takes_earliest_of_multiple_matched_documents(self) -> None:
        tenant = make_tenant_context()
        detection_repo = InMemoryDetectionRepository()
        timeline_index = InMemoryOpenSearchClient()

        synced_at = datetime(2026, 1, 1, 0, 10, 0, tzinfo=UTC)
        await timeline_index.bulk_index(
            [
                (_INDEX, "doc-early", {"@timestamp": "2026-01-01T00:00:00+00:00"}),
                (_INDEX, "doc-late", {"@timestamp": "2026-01-01T00:05:00+00:00"}),
            ]
        )
        await detection_repo.save(
            _detection(tenant.org_id, "finding-1", ("doc-early", "doc-late"), synced_at)
        )

        result = await MeanTimeToDetectCalculator(detection_repo, timeline_index).compute(tenant)

        # min(event_times) is doc-early (00:00:00) -> 600s delta, not doc-late's 300s.
        assert result.value == pytest.approx(600.0)

    @pytest.mark.asyncio
    async def test_missing_matched_document_is_skipped_not_fabricated(self) -> None:
        tenant = make_tenant_context()
        detection_repo = InMemoryDetectionRepository()
        timeline_index = InMemoryOpenSearchClient()  # no documents indexed at all
        await detection_repo.save(
            _detection(tenant.org_id, "finding-1", ("missing-doc",), datetime.now(UTC))
        )

        result = await MeanTimeToDetectCalculator(detection_repo, timeline_index).compute(tenant)

        assert result.value is None
        assert result.detail["skipped_missing_doc"] == 1

    @pytest.mark.asyncio
    async def test_detections_without_matched_documents_are_excluded(self) -> None:
        tenant = make_tenant_context()
        detection_repo = InMemoryDetectionRepository()
        await detection_repo.save(_detection(tenant.org_id, "finding-1", (), datetime.now(UTC)))

        result = await MeanTimeToDetectCalculator(
            detection_repo, InMemoryOpenSearchClient()
        ).compute(tenant)

        assert result.value is None
        assert result.detail["total_detections"] == 1

    @pytest.mark.asyncio
    async def test_scoped_to_tenant_org_never_leaks_other_org_data(self) -> None:
        tenant_a = make_tenant_context()
        tenant_b = make_tenant_context()
        detection_repo = InMemoryDetectionRepository()
        timeline_index = InMemoryOpenSearchClient()
        await timeline_index.bulk_index(
            [(_INDEX, "doc-1", {"@timestamp": "2026-01-01T00:00:00+00:00"})]
        )
        await detection_repo.save(
            _detection(tenant_b.org_id, "finding-1", ("doc-1",), datetime.now(UTC))
        )

        result = await MeanTimeToDetectCalculator(detection_repo, timeline_index).compute(tenant_a)

        assert result.value is None
        assert result.detail["total_detections"] == 0
