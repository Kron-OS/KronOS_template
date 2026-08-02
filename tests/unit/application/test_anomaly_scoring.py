"""Unit tests for BehavioralAnomalyScorer (roadmap M6/G2).

Mocks only the two injected collaborators (AnomalyDetectorProvisioner,
AnomalyDetectionResultsClient) -- mirrors tests/unit/application/
test_rarity_scoring.py's own "pure parsing, fake collaborators" shape.
Real captured response shape comes from
poc/anomaly_detection_baseline/output.txt.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from src.adapter.opensearch.anomaly_detection_client import AnomalyDetectionResultsClient
from src.adapter.opensearch.anomaly_detector_provisioner import AnomalyDetectorProvisioner
from src.application.anomaly_scoring import BehavioralAnomalyScorer
from tests.fixtures.factories import make_tenant_context

# Real, captured result shapes (poc/anomaly_detection_baseline/output.txt).
_HOST_ANOMALOUS_RESULT = {
    "detector_id": "det-1",
    "task_id": "task-1",
    "anomaly_grade": 1.0,
    "confidence": 0.8801892438983826,
    "feature_data": [{"feature_id": "feat-1", "feature_name": "event_volume", "data": 8040.0}],
    "expected_values": [
        {"likelihood": 1.0, "value_list": [{"feature_id": "feat-1", "data": 99.95229047436086}]}
    ],
    "entity": [{"name": "host.name", "value": "host-anomalous"}],
    "data_start_time": 1785709740000,
    "data_end_time": 1785709800000,
}

# Real, confirmed shape for an early result whose shingle isn't full yet --
# no expected_values, no entity attribution failure, just an honest gap.
_EARLY_NO_EXPECTED_VALUES_RESULT = {
    "detector_id": "det-1",
    "task_id": "task-1",
    "anomaly_grade": 0.0,
    "confidence": 0.0,
    "feature_data": [{"feature_id": "feat-1", "feature_name": "event_volume", "data": 100.0}],
    "entity": [{"name": "host.name", "value": "host-normal"}],
    "data_start_time": 1785693420000,
    "data_end_time": 1785693480000,
}


class _FakeProvisioner(AnomalyDetectorProvisioner):
    def __init__(self, detector_id: str | None) -> None:
        self._detector_id = detector_id
        self.ensure_calls: list[str] = []

    async def ensure_org_detector(self, org_alias: str) -> str | None:
        self.ensure_calls.append(org_alias)
        return self._detector_id


class _FakeResultsClient(AnomalyDetectionResultsClient):
    def __init__(self, response: dict[str, Any]) -> None:
        self._response = response
        self.search_calls: list[dict[str, Any]] = []

    async def search_results(
        self, *, detector_id: str, min_grade: float = 0.0, size: int = 1000
    ) -> dict[str, Any]:
        self.search_calls.append({"detector_id": detector_id, "min_grade": min_grade, "size": size})
        return self._response


class TestFetchOrgSignals:
    @pytest.mark.asyncio
    async def test_returns_empty_tuple_when_org_not_ready_yet(self) -> None:
        # Mirrors RarityBaselineScorer's own "zero matching indices"
        # precedent for a brand-new org -- honest empty result, no crash.
        provisioner = _FakeProvisioner(detector_id=None)
        results_client = _FakeResultsClient(response={})
        scorer = BehavioralAnomalyScorer(provisioner, results_client)
        tenant = make_tenant_context()

        signals = await scorer.fetch_org_signals(tenant)

        assert signals == ()
        assert results_client.search_calls == []  # never even queried results

    @pytest.mark.asyncio
    async def test_maps_real_results_into_signals_correctly_attributed(self) -> None:
        provisioner = _FakeProvisioner(detector_id="det-1")
        raw_response = {
            "hits": {
                "hits": [
                    {"_source": _HOST_ANOMALOUS_RESULT},
                    {"_source": _EARLY_NO_EXPECTED_VALUES_RESULT},
                ]
            }
        }
        results_client = _FakeResultsClient(response=raw_response)
        scorer = BehavioralAnomalyScorer(provisioner, results_client)
        org_id = uuid.uuid4()
        tenant = make_tenant_context(org_id=org_id)

        signals = await scorer.fetch_org_signals(tenant, min_grade=0.5, size=200)

        assert len(signals) == 2
        # Tenant fields ALWAYS come from the caller's own TenantContext,
        # never anything in the AD result document (roadmap invariant #3).
        assert all(s.org_id == org_id for s in signals)
        assert all(s.org_alias == tenant.org_alias for s in signals)
        assert all(s.detector_id == "det-1" for s in signals)
        assert all(s.detector_name == "kronos-testorg-behavioral-ad-detector" for s in signals)

        anomalous = signals[0]
        assert anomalous.anomaly_grade == 1.0
        assert anomalous.task_id == "task-1"
        assert len(anomalous.entities) == 1
        assert anomalous.entities[0].name == "host.name"
        assert anomalous.entities[0].value == "host-anomalous"
        assert anomalous.features[0].feature_name == "event_volume"
        assert anomalous.features[0].observed_value == 8040.0
        assert anomalous.features[0].expected_value == pytest.approx(99.95229047436086)

        early = signals[1]
        assert early.features[0].expected_value is None  # honest absence, not fabricated

        # Provisioner/results-client were called with what the scorer owns.
        assert provisioner.ensure_calls == [tenant.org_alias]
        assert results_client.search_calls == [
            {"detector_id": "det-1", "min_grade": 0.5, "size": 200}
        ]

    @pytest.mark.asyncio
    async def test_no_reproducibility_marker_leaks_a_false_value(self) -> None:
        provisioner = _FakeProvisioner(detector_id="det-1")
        raw_response = {"hits": {"hits": [{"_source": _HOST_ANOMALOUS_RESULT}]}}
        results_client = _FakeResultsClient(response=raw_response)
        scorer = BehavioralAnomalyScorer(provisioner, results_client)

        signals = await scorer.fetch_org_signals(make_tenant_context())

        assert all(s.not_reproducible is True for s in signals)
