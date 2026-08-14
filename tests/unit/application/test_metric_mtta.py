"""Unit tests for MeanTimeToAcknowledgeCalculator (roadmap M8/I2, Gap Audit P2-11)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from src.adapter.repository.detection import InMemoryDetectionRepository
from src.application.metric_mtta import MeanTimeToAcknowledgeCalculator
from src.domain.audit import AuditEvent, AuditEventType
from src.domain.detection import Detection
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_tenant_context

_INDEX = "kronos-testorg-case-11111111-1111-4111-8111-111111111111-202601"


def _detection(
    org_id: uuid.UUID,
    finding_id: str,
    synced_at: datetime,
    detection_id: uuid.UUID | None = None,
) -> Detection:
    return Detection(
        detection_id=detection_id or uuid.uuid4(),
        org_id=org_id,
        org_alias="testorg",
        finding_id=finding_id,
        detector_name="kronos-testorg-windows-detector",
        source_index=_INDEX,
        finding_timestamp=synced_at,
        synced_at=synced_at,
    )


def _transition_event(
    org_id: uuid.UUID,
    detection_id: uuid.UUID,
    occurred_at: datetime,
    to_state: str = "INVESTIGATING",
    sequence_number: int = 1,
) -> AuditEvent:
    return AuditEvent(
        event_type=AuditEventType.DETECTION_TRIAGE_TRANSITIONED,
        org_id=org_id,
        details={
            "detection_id": str(detection_id),
            "from_state": "NEW",
            "to_state": to_state,
        },
        occurred_at=occurred_at,
        sequence_number=sequence_number,
    )


class TestMeanTimeToAcknowledgeCalculator:
    @pytest.mark.asyncio
    async def test_no_detections_reports_unavailable(self) -> None:
        calc = MeanTimeToAcknowledgeCalculator(
            InMemoryDetectionRepository(), InMemoryAuditLogRepository()
        )
        result = await calc.compute(make_tenant_context())

        assert result.value is None
        assert result.sample_size == 0
        assert "No Detection rows" in result.unavailable_reason

    @pytest.mark.asyncio
    async def test_detection_with_no_triage_event_is_honest_none_not_zero(self) -> None:
        tenant = make_tenant_context()
        detection_repo = InMemoryDetectionRepository()
        await detection_repo.save(_detection(tenant.org_id, "finding-1", datetime.now(UTC)))

        result = await MeanTimeToAcknowledgeCalculator(
            detection_repo, InMemoryAuditLogRepository()
        ).compute(tenant)

        assert result.value is None
        assert result.sample_size == 0
        assert result.detail["total_detections"] == 1
        assert result.detail["detections_with_triage_event"] == 0
        assert "no valid" not in (result.unavailable_reason or "")

    @pytest.mark.asyncio
    async def test_computes_real_delta_from_first_triage_transition(self) -> None:
        tenant = make_tenant_context()
        detection_repo = InMemoryDetectionRepository()
        audit_repo = InMemoryAuditLogRepository()

        synced_at = datetime(2026, 1, 1, tzinfo=UTC)
        detection = _detection(tenant.org_id, "finding-1", synced_at)
        await detection_repo.save(detection)
        await audit_repo.append(
            _transition_event(
                tenant.org_id,
                detection.detection_id,
                synced_at + timedelta(seconds=300),
            )
        )

        result = await MeanTimeToAcknowledgeCalculator(detection_repo, audit_repo).compute(tenant)

        assert result.value == pytest.approx(300.0)
        assert result.sample_size == 1
        assert result.unit == "seconds"

    @pytest.mark.asyncio
    async def test_takes_earliest_of_multiple_transitions_for_same_detection(self) -> None:
        tenant = make_tenant_context()
        detection_repo = InMemoryDetectionRepository()
        audit_repo = InMemoryAuditLogRepository()

        synced_at = datetime(2026, 1, 1, tzinfo=UTC)
        detection = _detection(tenant.org_id, "finding-1", synced_at)
        await detection_repo.save(detection)
        # NEW -> INVESTIGATING at +300s (the real "first engagement"),
        # then INVESTIGATING -> TRUE_POSITIVE at +9000s (the verdict, not
        # the acknowledgement -- must NOT be what this metric measures).
        await audit_repo.append(
            _transition_event(
                tenant.org_id,
                detection.detection_id,
                synced_at + timedelta(seconds=300),
                to_state="INVESTIGATING",
                sequence_number=1,
            )
        )
        await audit_repo.append(
            _transition_event(
                tenant.org_id,
                detection.detection_id,
                synced_at + timedelta(seconds=9000),
                to_state="TRUE_POSITIVE",
                sequence_number=2,
            )
        )

        result = await MeanTimeToAcknowledgeCalculator(detection_repo, audit_repo).compute(tenant)

        assert result.value == pytest.approx(300.0)

    @pytest.mark.asyncio
    async def test_aggregates_mean_across_multiple_detections_with_min_max_median(self) -> None:
        tenant = make_tenant_context()
        detection_repo = InMemoryDetectionRepository()
        audit_repo = InMemoryAuditLogRepository()

        base = datetime(2026, 1, 1, tzinfo=UTC)
        deltas = [100.0, 200.0, 900.0]
        for i, delta in enumerate(deltas):
            detection = _detection(tenant.org_id, f"finding-{i}", base)
            await detection_repo.save(detection)
            await audit_repo.append(
                _transition_event(
                    tenant.org_id,
                    detection.detection_id,
                    base + timedelta(seconds=delta),
                    sequence_number=i + 1,
                )
            )

        result = await MeanTimeToAcknowledgeCalculator(detection_repo, audit_repo).compute(tenant)

        assert result.value == pytest.approx(sum(deltas) / len(deltas))
        assert result.sample_size == 3
        assert result.detail["min_seconds"] == pytest.approx(100.0)
        assert result.detail["max_seconds"] == pytest.approx(900.0)
        assert result.detail["median_seconds"] == pytest.approx(200.0)

    @pytest.mark.asyncio
    async def test_mixed_triaged_and_untriaged_detections_only_averages_real_samples(
        self,
    ) -> None:
        tenant = make_tenant_context()
        detection_repo = InMemoryDetectionRepository()
        audit_repo = InMemoryAuditLogRepository()

        base = datetime(2026, 1, 1, tzinfo=UTC)
        triaged = _detection(tenant.org_id, "finding-triaged", base)
        untriaged = _detection(tenant.org_id, "finding-untriaged", base)
        await detection_repo.save(triaged)
        await detection_repo.save(untriaged)
        await audit_repo.append(
            _transition_event(tenant.org_id, triaged.detection_id, base + timedelta(seconds=60))
        )

        result = await MeanTimeToAcknowledgeCalculator(detection_repo, audit_repo).compute(tenant)

        # Only the one real triaged sample feeds the mean -- the untriaged
        # Detection is excluded, never averaged in as an implicit zero.
        assert result.value == pytest.approx(60.0)
        assert result.sample_size == 1
        assert result.detail["total_detections"] == 2
        assert result.detail["detections_with_triage_event"] == 1

    @pytest.mark.asyncio
    async def test_ignores_unrelated_audit_event_types(self) -> None:
        tenant = make_tenant_context()
        detection_repo = InMemoryDetectionRepository()
        audit_repo = InMemoryAuditLogRepository()

        base = datetime(2026, 1, 1, tzinfo=UTC)
        detection = _detection(tenant.org_id, "finding-1", base)
        await detection_repo.save(detection)
        await audit_repo.append(
            AuditEvent(
                event_type=AuditEventType.DETECTION_SYNCED,
                org_id=tenant.org_id,
                details={"detection_id": str(detection.detection_id)},
                occurred_at=base + timedelta(seconds=1),
                sequence_number=1,
            )
        )
        await audit_repo.append(
            _transition_event(
                tenant.org_id,
                detection.detection_id,
                base + timedelta(seconds=90),
                sequence_number=2,
            )
        )

        result = await MeanTimeToAcknowledgeCalculator(detection_repo, audit_repo).compute(tenant)

        assert result.value == pytest.approx(90.0)

    @pytest.mark.asyncio
    async def test_scoped_to_tenant_org_never_leaks_other_org_data(self) -> None:
        tenant_a = make_tenant_context()
        tenant_b = make_tenant_context()
        detection_repo = InMemoryDetectionRepository()
        audit_repo = InMemoryAuditLogRepository()

        base = datetime(2026, 1, 1, tzinfo=UTC)
        detection_b = _detection(tenant_b.org_id, "finding-1", base)
        await detection_repo.save(detection_b)
        await audit_repo.append(
            _transition_event(
                tenant_b.org_id, detection_b.detection_id, base + timedelta(seconds=60)
            )
        )

        result = await MeanTimeToAcknowledgeCalculator(detection_repo, audit_repo).compute(tenant_a)

        assert result.value is None
        assert result.detail["total_detections"] == 0

    @pytest.mark.asyncio
    async def test_malformed_detection_id_on_triage_event_raises_not_silently_skipped(
        self,
    ) -> None:
        tenant = make_tenant_context()
        detection_repo = InMemoryDetectionRepository()
        audit_repo = InMemoryAuditLogRepository()
        await audit_repo.append(
            AuditEvent(
                event_type=AuditEventType.DETECTION_TRIAGE_TRANSITIONED,
                org_id=tenant.org_id,
                details={"from_state": "NEW", "to_state": "INVESTIGATING"},  # no detection_id
                sequence_number=1,
            )
        )

        with pytest.raises(KeyError):
            await MeanTimeToAcknowledgeCalculator(detection_repo, audit_repo).compute(tenant)
