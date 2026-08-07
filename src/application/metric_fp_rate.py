"""FalsePositiveRateCalculator: real FALSE_POSITIVE / terminal-triage ratio
from the org's own audit trail (roadmap M8/I2).

Deliberately reads the AUDIT TRAIL (``AuditEventType.DETECTION_TRIAGE_TRANSITIONED``
rows via ``AuditLogRepository.stream_by_org``), not ``Detection.triage_state``
directly off the ``detections`` table. Two reasons, both real: (1) the audit
trail is the append-only, tamper-evident record of every transition that
ever happened, including one a Detection's own current (mutable-until-
terminal) ``triage_state`` column would silently overwrite if it were
transitioned more than once (NEW -> INVESTIGATING -> TRUE_POSITIVE, e.g.,
only leaves TRUE_POSITIVE behind on the row itself, but the audit trail
still has the INVESTIGATING transition as its own event -- irrelevant for
THIS metric, but the audit trail is still the more defensible, replayable
source of truth per roadmap invariant #6); (2) it reuses the exact same
repository method (``stream_by_org``) already exercised throughout this
codebase, rather than adding a bespoke detections-table aggregate query.
"""

from __future__ import annotations

from src.adapter.repository.audit_log import AuditLogRepository
from src.application.metric_calculator import MetricCalculator
from src.domain.audit import AuditEventType
from src.domain.detection import DetectionTriageState
from src.domain.metrics import MetricResult
from src.domain.user import TenantContext

# Detection's own triage FSM (src/domain/detection.py's _VALID_TRANSITIONS)
# has exactly two terminal states, TRUE_POSITIVE and FALSE_POSITIVE --
# INVESTIGATING is explicitly non-terminal and excluded from the
# denominator below, since an in-flight triage is neither a true nor a
# false positive yet.


class FalsePositiveRateCalculator(MetricCalculator):
    """FALSE_POSITIVE transitions / total terminal transitions, per org."""

    def __init__(self, audit_log_repository: AuditLogRepository) -> None:
        self._audit_log = audit_log_repository

    @property
    def metric_name(self) -> str:
        return "false_positive_rate"

    async def compute(self, tenant: TenantContext) -> MetricResult:
        true_positive_count = 0
        false_positive_count = 0
        non_terminal_count = 0
        async for event in self._audit_log.stream_by_org(tenant.org_id):
            if event.event_type != AuditEventType.DETECTION_TRIAGE_TRANSITIONED:
                continue
            to_state = event.details.get("to_state")
            if to_state == DetectionTriageState.FALSE_POSITIVE.value:
                false_positive_count += 1
            elif to_state == DetectionTriageState.TRUE_POSITIVE.value:
                true_positive_count += 1
            else:
                non_terminal_count += 1

        terminal_count = true_positive_count + false_positive_count
        if terminal_count == 0:
            return MetricResult(
                metric_name=self.metric_name,
                org_id=tenant.org_id,
                value=None,
                unit="ratio",
                sample_size=0,
                detail={"non_terminal_transitions": non_terminal_count},
                unavailable_reason=(
                    "No terminal (TRUE_POSITIVE/FALSE_POSITIVE) triage transitions "
                    "recorded for this org yet -- every Detection triaged so far is "
                    "still NEW/INVESTIGATING, or none have been triaged at all."
                ),
            )

        return MetricResult(
            metric_name=self.metric_name,
            org_id=tenant.org_id,
            value=false_positive_count / terminal_count,
            unit="ratio",
            sample_size=terminal_count,
            detail={
                "true_positive_count": true_positive_count,
                "false_positive_count": false_positive_count,
                "non_terminal_transitions": non_terminal_count,
            },
        )
