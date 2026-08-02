"""BehavioralAnomalyScorer: query-time-only OpenSearch AD/RCF triage
signal orchestration (roadmap M6/G2).

**Standalone by design, mirroring G1's ``RarityBaselineScorer`` precedent
-- NOT wired into ``DetectionRiskScorer``/``Detection``, no repository, no
DI wiring, no HTTP route yet.** See
``poc/anomaly_detection_baseline/README.md``'s "Design decision:
BehavioralAnomalySignal is query-time-only, never persisted" for the full
reasoning: unlike G1 (which simply has no consumer yet), this item has a
STRUCTURAL reason to stay query-time-only -- persisting a snapshot of a
live, continuously-mutating RCF score would create a stored row that
looks like a `Detection` row (an id, a timestamp, "a fact on file") while
carrying none of `Detection`'s actual replayability guarantee. G3 (the
next roadmap item, a GATE) depends on this signal type staying
mechanically distinguishable from anything evidentiary; the safest way to
guarantee that is for there to be no persisted, queryable-later table to
mistake for one in the first place.

Orchestrates (does not itself perform raw I/O beyond delegating to its two
injected collaborators): ensure the org's own per-org AD detector exists
(``AnomalyDetectorProvisioner``), fetch its real, current anomaly results
(``AnomalyDetectionResultsClient``), then parse+map them into
:class:`BehavioralAnomalySignal` via pure, testable logic -- mirrors
``RarityBaselineScorer``'s exact "orchestrate two collaborators, parse the
raw response separately" shape.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from src.adapter.opensearch.anomaly_detection_client import AnomalyDetectionResultsClient
from src.adapter.opensearch.anomaly_detector_provisioner import AnomalyDetectorProvisioner
from src.domain.anomaly import (
    AnomalyEntityDimension,
    AnomalyFeatureObservation,
    BehavioralAnomalySignal,
)
from src.domain.user import TenantContext


class BehavioralAnomalyScorer:
    """Fetches real, current AD/RCF triage-prioritization signals for one
    org's own per-org detector.

    Never raises on "this org has no detector yet" (no ingested data) --
    returns an honest empty tuple, mirroring
    ``RarityBaselineScorer``'s own "zero matching indices" precedent for a
    brand-new org (``src/application/rarity_scoring.py``).
    """

    def __init__(
        self,
        provisioner: AnomalyDetectorProvisioner,
        results_client: AnomalyDetectionResultsClient,
    ) -> None:
        self._provisioner = provisioner
        self._results_client = results_client

    async def fetch_org_signals(
        self,
        tenant: TenantContext,
        *,
        min_grade: float = 0.0,
        size: int = 1000,
    ) -> tuple[BehavioralAnomalySignal, ...]:
        """Return real, current `BehavioralAnomalySignal`s for *tenant*'s
        own org, ordered most-anomalous-first.

        Args:
            tenant: authenticated caller context; ``org_id``/``org_alias``
                are the ONLY source for both the detector's own index
                scoping (via the provisioner) and every returned signal's
                own org fields -- never anything read out of an AD result
                document (roadmap invariant #3).
            min_grade: only return results with ``anomaly_grade >
                min_grade`` -- default 0.0 excludes AD's own frequent
                "computed, but non-anomalous" background results, which
                make up the large majority of any real result set (598 of
                600 configured intervals in this item's own PoC run) and
                are not, by themselves, a hunting lead.
            size: cap on how many (most-anomalous-first) results are
                fetched in one call -- mirrors
                ``RarityBaselineScorer``'s own ``max_distinct_values`` cap
                idiom for a v1, un-paginated read.
        """
        detector_id = await self._provisioner.ensure_org_detector(tenant.org_alias)
        if detector_id is None:
            return ()

        detector_name = self._provisioner.detector_name(tenant.org_alias)
        raw = await self._results_client.search_results(
            detector_id=detector_id, min_grade=min_grade, size=size
        )
        return _parse_results(
            raw,
            org_id=tenant.org_id,
            org_alias=tenant.org_alias,
            detector_id=detector_id,
            detector_name=detector_name,
        )


def _parse_results(
    raw: dict[str, Any],
    *,
    org_id: Any,
    org_alias: str,
    detector_id: str,
    detector_name: str,
) -> tuple[BehavioralAnomalySignal, ...]:
    """Pure parsing of an already-fetched raw AD results-search response.

    No I/O -- testable without OpenSearch (see
    ``tests/unit/application/test_anomaly_scoring.py``). Handles the real,
    confirmed shape where ``expected_values`` (the model's own predicted
    value per feature) may be entirely absent for an early result whose
    RCF shingle isn't yet full (``poc/anomaly_detection_baseline/
    output.txt``'s first captured host-normal result carries no
    ``expected_values`` key at all).
    """
    signals: list[BehavioralAnomalySignal] = []
    for hit in raw.get("hits", {}).get("hits", []):
        source = hit["_source"]
        expected_by_feature_id: dict[str, float] = {}
        expected_values = source.get("expected_values") or []
        if expected_values:
            # AD's own real shape: a list of {likelihood, value_list}
            # candidates -- the first (highest-likelihood) candidate is
            # the model's single best predicted-normal value per feature,
            # confirmed real (poc/anomaly_detection_baseline/output.txt).
            for value_entry in expected_values[0].get("value_list", []):
                expected_by_feature_id[value_entry["feature_id"]] = value_entry["data"]

        features = tuple(
            AnomalyFeatureObservation(
                feature_name=fd["feature_name"],
                observed_value=fd["data"],
                expected_value=expected_by_feature_id.get(fd["feature_id"]),
            )
            for fd in source.get("feature_data", [])
        )
        entities = tuple(
            AnomalyEntityDimension(name=e["name"], value=e["value"])
            for e in source.get("entity", [])
        )

        signals.append(
            BehavioralAnomalySignal(
                org_id=org_id,
                org_alias=org_alias,
                detector_id=detector_id,
                detector_name=detector_name,
                task_id=source.get("task_id"),
                entities=entities,
                anomaly_grade=source["anomaly_grade"],
                confidence=source.get("confidence"),
                features=features,
                data_start_time=datetime.fromtimestamp(source["data_start_time"] / 1000, tz=UTC),
                data_end_time=datetime.fromtimestamp(source["data_end_time"] / 1000, tz=UTC),
            )
        )
    return tuple(signals)
