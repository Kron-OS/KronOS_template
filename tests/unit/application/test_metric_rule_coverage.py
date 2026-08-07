"""Unit tests for RuleCoverageCalculator (roadmap M8/I2)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from src.adapter.opensearch.rule_catalog import RuleCatalogClient
from src.adapter.repository.detection import InMemoryDetectionRepository
from src.application.metric_rule_coverage import RuleCoverageCalculator
from src.domain.detection import Detection, DetectionRuleMatch
from tests.fixtures.factories import make_tenant_context

_LOG_TYPES = ("windows", "network")


class _FakeRuleCatalog(RuleCatalogClient):
    def __init__(self, counts: dict[str, int]) -> None:
        self._counts = counts
        self.calls: list[str] = []

    async def count_prepackaged_rules(self, log_type: str) -> int:
        self.calls.append(log_type)
        return self._counts.get(log_type, 0)


def _calculator(
    detection_repo: InMemoryDetectionRepository, catalog: _FakeRuleCatalog
) -> RuleCoverageCalculator:
    return RuleCoverageCalculator(detection_repo, catalog, log_types=_LOG_TYPES)


def _detection(org_id: uuid.UUID, detector_name: str, rule_ids: tuple[str, ...]) -> Detection:
    return Detection(
        org_id=org_id,
        org_alias="testorg",
        finding_id=str(uuid.uuid4()),
        detector_name=detector_name,
        source_index="kronos-testorg-case-x-202601",
        rule_matches=tuple(DetectionRuleMatch(rule_id=r) for r in rule_ids),
        finding_timestamp=datetime.now(tz=UTC),
    )


class TestRuleCoverageCalculator:
    @pytest.mark.asyncio
    async def test_no_detections_reports_zero_not_unavailable(self) -> None:
        """A real, meaningful 0.0 (denominator > 0) is different from
        "unavailable" -- see module docstring: zero fired against a real,
        known set of available rules is itself an honest fact."""
        calc = RuleCoverageCalculator(
            InMemoryDetectionRepository(),
            _FakeRuleCatalog({"windows": 100, "network": 10}),
            log_types=_LOG_TYPES,
        )

        result = await calc.compute(make_tenant_context())

        assert result.value == 0.0
        assert result.detail["total_available"] == 110

    @pytest.mark.asyncio
    async def test_zero_available_rules_reports_unavailable(self) -> None:
        calc = RuleCoverageCalculator(
            InMemoryDetectionRepository(), _FakeRuleCatalog({}), log_types=_LOG_TYPES
        )

        result = await calc.compute(make_tenant_context())

        assert result.value is None
        assert "empty denominator" in result.unavailable_reason

    @pytest.mark.asyncio
    async def test_computes_real_ratio_across_log_types(self) -> None:
        tenant = make_tenant_context()
        detection_repo = InMemoryDetectionRepository()
        await detection_repo.save(
            _detection(tenant.org_id, "kronos-testorg-windows-detector", ("rule-1", "rule-2"))
        )
        await detection_repo.save(
            _detection(tenant.org_id, "kronos-testorg-windows-detector", ("rule-1",))  # dup rule-1
        )
        await detection_repo.save(
            _detection(tenant.org_id, "kronos-testorg-network-detector", ("rule-9",))
        )
        catalog = _FakeRuleCatalog({"windows": 100, "network": 10})

        result = await _calculator(detection_repo, catalog).compute(tenant)

        # 2 distinct windows rules (rule-1, rule-2) + 1 distinct network rule
        # (rule-9) = 3 fired / 110 available.
        assert result.value == pytest.approx(3 / 110)
        assert result.detail["per_log_type"]["windows"] == {"fired": 2, "available": 100}
        assert result.detail["per_log_type"]["network"] == {"fired": 1, "available": 10}

    @pytest.mark.asyncio
    async def test_detector_name_not_matching_any_known_log_type_is_unattributed(self) -> None:
        tenant = make_tenant_context()
        detection_repo = InMemoryDetectionRepository()
        await detection_repo.save(
            _detection(tenant.org_id, "some-legacy-detector-name", ("rule-1",))
        )
        catalog = _FakeRuleCatalog({"windows": 100, "network": 10})

        result = await _calculator(detection_repo, catalog).compute(tenant)

        assert result.value == 0.0
        assert result.detail["unattributed_detections"] == 1

    @pytest.mark.asyncio
    async def test_scoped_to_tenant_org_never_leaks_other_org_data(self) -> None:
        tenant_a = make_tenant_context()
        tenant_b = make_tenant_context()
        detection_repo = InMemoryDetectionRepository()
        await detection_repo.save(
            _detection(tenant_b.org_id, "kronos-testorg-windows-detector", ("rule-1",))
        )
        catalog = _FakeRuleCatalog({"windows": 100, "network": 10})

        result = await _calculator(detection_repo, catalog).compute(tenant_a)

        assert result.value == 0.0
        assert result.detail["total_detections"] == 0
