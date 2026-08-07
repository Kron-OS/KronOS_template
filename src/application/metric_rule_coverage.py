"""RuleCoverageCalculator: distinct fired Sigma rules / real prepackaged
rule count, per org, per log type (roadmap M8/I2).

**Not new measurement work** -- roadmap C1 (``poc/security_analytics_field_mappings/``)
already measured this exact ratio by hand for a benign sample per log type
(e.g. windows 3/1580, network 1/38). This calculator's own job, per the
roadmap's I2 scope note, is to make that a queryable, persisted-service
metric a caller can compute for ANY org at ANY time from what has already
fired for real, rather than a one-off PoC printout -- the computation
itself (numerator from real ``Detection.rule_matches``, denominator from a
real, live prepackaged-rule-count query) is unchanged from C1's own
methodology.

Log type attribution: ``DetectorProvisioner._detector_name`` names every
detector ``kronos-{org_alias}-{log_type}-detector``
(``src/adapter/opensearch/detector_provisioner.py``) -- this calculator
recovers *which* log type a Detection's rules fired under by checking
``detector_name`` against each of ``get_default_log_types()``'s known
values (a plain suffix match, not a regex split, since ``org_alias`` may
itself contain hyphens and the log type set is small/known -- the same
"finite known vocabulary, no parsing ambiguity" reasoning
``highest_rule_severity`` already uses for severity tags).
"""

from __future__ import annotations

from src.adapter.opensearch.detector_provisioner import get_default_log_types
from src.adapter.opensearch.rule_catalog import RuleCatalogClient
from src.adapter.repository.detection import DetectionRepository
from src.application.metric_calculator import MetricCalculator
from src.domain.metrics import MetricResult
from src.domain.user import TenantContext


def _log_type_for_detector(detector_name: str, log_types: tuple[str, ...]) -> str | None:
    for log_type in log_types:
        if detector_name.endswith(f"-{log_type}-detector"):
            return log_type
    return None


class RuleCoverageCalculator(MetricCalculator):
    """Fraction of real prepackaged Sigma rules that have fired at least once, per org."""

    def __init__(
        self,
        detection_repository: DetectionRepository,
        rule_catalog: RuleCatalogClient,
        log_types: tuple[str, ...] | None = None,
    ) -> None:
        self._detections = detection_repository
        self._rule_catalog = rule_catalog
        self._log_types = log_types or get_default_log_types()

    @property
    def metric_name(self) -> str:
        return "rule_coverage_ratio"

    async def compute(self, tenant: TenantContext) -> MetricResult:
        fired_rule_ids_by_log_type: dict[str, set[str]] = {lt: set() for lt in self._log_types}
        unattributed_detections = 0
        total_detections = 0
        async for detection in self._detections.stream_by_org(tenant.org_id):
            total_detections += 1
            log_type = _log_type_for_detector(detection.detector_name, self._log_types)
            if log_type is None:
                unattributed_detections += 1
                continue
            fired_rule_ids_by_log_type[log_type].update(m.rule_id for m in detection.rule_matches)

        per_log_type: dict[str, dict[str, int]] = {}
        total_fired = 0
        total_available = 0
        for log_type in self._log_types:
            available = await self._rule_catalog.count_prepackaged_rules(log_type)
            fired = len(fired_rule_ids_by_log_type[log_type])
            per_log_type[log_type] = {"fired": fired, "available": available}
            total_fired += fired
            total_available += available

        if total_available == 0:
            return MetricResult(
                metric_name=self.metric_name,
                org_id=tenant.org_id,
                value=None,
                unit="ratio",
                sample_size=0,
                detail={"per_log_type": per_log_type, "total_detections": total_detections},
                unavailable_reason=(
                    "OpenSearch Security Analytics reports zero prepackaged rules for "
                    "every configured log type -- cannot compute a coverage ratio "
                    "against an empty denominator."
                ),
            )

        return MetricResult(
            metric_name=self.metric_name,
            org_id=tenant.org_id,
            value=total_fired / total_available,
            unit="ratio",
            sample_size=total_detections,
            detail={
                "per_log_type": per_log_type,
                "total_fired": total_fired,
                "total_available": total_available,
                "total_detections": total_detections,
                "unattributed_detections": unattributed_detections,
            },
        )
