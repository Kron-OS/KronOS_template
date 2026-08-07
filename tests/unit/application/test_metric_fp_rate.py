"""Unit tests for FalsePositiveRateCalculator (roadmap M8/I2)."""

from __future__ import annotations

import uuid

import pytest

from src.application.metric_fp_rate import FalsePositiveRateCalculator
from src.domain.audit import AuditEvent, AuditEventType
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_tenant_context


def _transition_event(org_id: uuid.UUID, to_state: str, sequence_number: int = 1) -> AuditEvent:
    return AuditEvent(
        event_type=AuditEventType.DETECTION_TRIAGE_TRANSITIONED,
        org_id=org_id,
        details={
            "detection_id": str(uuid.uuid4()),
            "from_state": "INVESTIGATING",
            "to_state": to_state,
        },
        sequence_number=sequence_number,
    )


class TestFalsePositiveRateCalculator:
    @pytest.mark.asyncio
    async def test_no_transitions_reports_unavailable(self) -> None:
        calc = FalsePositiveRateCalculator(InMemoryAuditLogRepository())
        result = await calc.compute(make_tenant_context())

        assert result.value is None
        assert result.sample_size == 0
        assert "No terminal" in result.unavailable_reason

    @pytest.mark.asyncio
    async def test_computes_real_ratio_from_terminal_transitions(self) -> None:
        tenant = make_tenant_context()
        audit_repo = InMemoryAuditLogRepository()
        await audit_repo.append(_transition_event(tenant.org_id, "FALSE_POSITIVE", 1))
        await audit_repo.append(_transition_event(tenant.org_id, "FALSE_POSITIVE", 2))
        await audit_repo.append(_transition_event(tenant.org_id, "TRUE_POSITIVE", 3))

        result = await FalsePositiveRateCalculator(audit_repo).compute(tenant)

        assert result.value == pytest.approx(2 / 3)
        assert result.sample_size == 3
        assert result.detail == {
            "true_positive_count": 1,
            "false_positive_count": 2,
            "non_terminal_transitions": 0,
        }

    @pytest.mark.asyncio
    async def test_non_terminal_investigating_excluded_from_denominator(self) -> None:
        tenant = make_tenant_context()
        audit_repo = InMemoryAuditLogRepository()
        await audit_repo.append(_transition_event(tenant.org_id, "INVESTIGATING", 1))
        await audit_repo.append(_transition_event(tenant.org_id, "INVESTIGATING", 2))
        await audit_repo.append(_transition_event(tenant.org_id, "TRUE_POSITIVE", 3))

        result = await FalsePositiveRateCalculator(audit_repo).compute(tenant)

        # Only 1 terminal transition (TRUE_POSITIVE) -- denominator is 1, not 3.
        assert result.value == 0.0
        assert result.sample_size == 1
        assert result.detail["non_terminal_transitions"] == 2

    @pytest.mark.asyncio
    async def test_ignores_unrelated_event_types(self) -> None:
        tenant = make_tenant_context()
        audit_repo = InMemoryAuditLogRepository()
        await audit_repo.append(
            AuditEvent(
                event_type=AuditEventType.DETECTION_SYNCED,
                org_id=tenant.org_id,
                sequence_number=1,
            )
        )
        await audit_repo.append(_transition_event(tenant.org_id, "FALSE_POSITIVE", 2))

        result = await FalsePositiveRateCalculator(audit_repo).compute(tenant)

        assert result.value == 1.0
        assert result.sample_size == 1

    @pytest.mark.asyncio
    async def test_scoped_to_tenant_org_never_leaks_other_org_data(self) -> None:
        tenant_a = make_tenant_context()
        tenant_b = make_tenant_context()
        audit_repo = InMemoryAuditLogRepository()
        await audit_repo.append(_transition_event(tenant_b.org_id, "FALSE_POSITIVE", 1))

        result = await FalsePositiveRateCalculator(audit_repo).compute(tenant_a)

        assert result.value is None
