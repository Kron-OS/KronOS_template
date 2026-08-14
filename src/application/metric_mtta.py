"""MeanTimeToAcknowledgeCalculator: real elapsed time from a Detection's
own sync moment to the first real human/automated triage engagement it
ever received (roadmap M8/I2, Gap Audit P2-11).

**Why this is MTTA, and explicitly NOT MTTR.** I2's own investigation
(``docs/NEXTGEN_SOC_ROADMAP.md`` I2, "Investigated, explicitly deferred")
confirmed true MTTR is **not honestly computable** in this codebase today:
a Detection's triage FSM (``src/domain/detection.py``) has no
remediation-complete terminal state, and ``containment.action_*`` audit
events key on ``user_id``/``session_id``, never ``detection_id`` -- there
is no real join key between a containment action and the Detection it
responded to. What I2 *did* confirm feasible is a weaker, honest proxy:
"time to first triage engagement" -- the real elapsed time between a
Detection existing and the first time any analyst or automation (a
playbook action counts too -- ``PlaybookExecutionService`` writes the same
``DETECTION_TRIAGE_TRANSITIONED`` event type as a human-driven
``DetectionTriageService.transition()`` call) touched it. This is a
genuinely different, weaker claim than "time to contain" and must never be
relabeled MTTR -- see I2's own text for why the label matters as much as
the number here.

**Data source.** Mirrors ``FalsePositiveRateCalculator``'s own choice to
read the audit trail (``AuditEventType.DETECTION_TRIAGE_TRANSITIONED`` rows
via ``AuditLogRepository.stream_by_org``), not any mutable column on the
``detections`` table -- for the identical reason: the audit trail is the
append-only, replayable record of every transition that ever happened,
including the very first one this metric needs (a Detection's own current
``triage_state`` column, by contrast, only ever shows the *latest* state,
not when the *first* transition away from ``NEW`` occurred).
``detection_triage.py``'s ``DetectionTriageService.transition()`` always
writes ``details={"detection_id": ..., "from_state": ..., "to_state":
...}`` on this event type (verified directly against that method's own
source, not assumed) -- ``detection_id`` is therefore always present for a
transition this platform itself produced; a ``DETECTION_TRIAGE_TRANSITIONED``
event missing it would mean something is genuinely broken upstream, not
that data is honestly absent, so parsing it uses the same
"let a malformed critical field raise, don't catch and hide it" idiom this
codebase already uses when pulling ``detection_id`` out of a params/details
dict elsewhere (e.g. ``playbook_actions.py``, ``evidence_collection_action
.py``, ``ticket_sync_action.py`` all do a bare ``uuid.UUID(params
["detection_id"])`` with no try/except) -- deliberately NOT a
``try/except``-and-skip like the OpenSearch document lookups in
``SecurityAnalyticsCycleTimeCalculator`` use, because those really can be
legitimately absent (a document can be deleted/reindexed out from under
the metric); a detection_id-less transition event from this platform's own
writer cannot.

**"First" engagement, not "latest".** A single Detection can transition
more than once (NEW -> INVESTIGATING -> TRUE_POSITIVE/FALSE_POSITIVE) --
this calculator takes the *earliest* ``occurred_at`` among all
``DETECTION_TRIAGE_TRANSITIONED`` events for a given ``detection_id``
(almost always its NEW -> INVESTIGATING transition), matching "time to
first engagement", not "time to verdict".

**Aggregation.** Mean, with min/max/median alongside it in ``detail`` --
mirrors ``SecurityAnalyticsCycleTimeCalculator``'s own choice (not
reinvented): a single average can hide a bimodal distribution (e.g. most
Detections triaged fast, a long tail nobody looked at yet), so the fuller
distribution is always reported alongside the mean.

**Honesty discipline (roadmap invariant #8, matching every other
``MetricCalculator`` in this module family).** A Detection with zero
``DETECTION_TRIAGE_TRANSITIONED`` events (still sitting in ``NEW``) simply
contributes nothing to the sample -- never a fabricated zero or an
average-of-nothing. An org with no Detections at all, or with Detections
but none yet triaged, gets an honest ``value=None`` +
``unavailable_reason``, exactly like ``SecurityAnalyticsCycleTimeCalculator``
and ``FalsePositiveRateCalculator`` both already do for their own
equivalent "nothing to compute yet" cases.
"""

from __future__ import annotations

import statistics
import uuid
from datetime import datetime

from src.adapter.repository.audit_log import AuditLogRepository
from src.adapter.repository.detection import DetectionRepository
from src.application.metric_calculator import MetricCalculator
from src.domain.audit import AuditEventType
from src.domain.metrics import MetricResult
from src.domain.user import TenantContext


class MeanTimeToAcknowledgeCalculator(MetricCalculator):
    """MTTA, in seconds: Detection.synced_at -> first real triage-transition event."""

    def __init__(
        self,
        detection_repository: DetectionRepository,
        audit_log_repository: AuditLogRepository,
    ) -> None:
        self._detections = detection_repository
        self._audit_log = audit_log_repository

    @property
    def metric_name(self) -> str:
        return "mtta_seconds"

    async def compute(self, tenant: TenantContext) -> MetricResult:
        # Build detection_id -> earliest real transition timestamp first
        # (mirrors SecurityAnalyticsCycleTimeCalculator's own "build the
        # lookup index before iterating the canonical source" shape). Both
        # this stream and the Detection stream below are independently
        # scoped to tenant.org_id (roadmap invariant #3) -- a
        # DETECTION_TRIAGE_TRANSITIONED event for another org can never
        # enter this map, and a Detection from another org is never
        # iterated below, so org isolation holds even without an explicit
        # cross-check between the two.
        first_triage_at: dict[uuid.UUID, datetime] = {}
        async for event in self._audit_log.stream_by_org(tenant.org_id):
            if event.event_type != AuditEventType.DETECTION_TRIAGE_TRANSITIONED:
                continue
            # Fail loudly: DetectionTriageService.transition() always
            # populates details["detection_id"] for this event type (see
            # module docstring) -- a missing/malformed value here is a real
            # upstream bug, not an honest data gap, so this is a bare
            # subscript + uuid.UUID(...), never a caught/skipped exception.
            detection_id = uuid.UUID(event.details["detection_id"])
            existing = first_triage_at.get(detection_id)
            if existing is None or event.occurred_at < existing:
                first_triage_at[detection_id] = event.occurred_at

        detection_count = 0
        deltas_seconds: list[float] = []
        skipped_negative = 0
        async for detection in self._detections.stream_by_org(tenant.org_id):
            detection_count += 1
            triage_at = first_triage_at.get(detection.detection_id)
            if triage_at is None:
                # Honest absence: this Detection has never been triaged --
                # never fabricated into a 0.0 "acknowledged instantly".
                continue
            delta = (triage_at - detection.synced_at).total_seconds()
            if delta < 0:
                # Not expected under this platform's own write path
                # (DetectionTriageService.transition() requires the
                # Detection to already exist via get_by_id before it can
                # audit a transition for it), but excluded rather than
                # reported as a fabricated negative latency should it ever
                # occur -- mirrors SecurityAnalyticsCycleTimeCalculator's
                # identical defensive choice for its own delta.
                skipped_negative += 1
                continue
            deltas_seconds.append(delta)

        if detection_count == 0:
            return MetricResult(
                metric_name=self.metric_name,
                org_id=tenant.org_id,
                value=None,
                unit="seconds",
                sample_size=0,
                detail={"total_detections": 0},
                unavailable_reason=(
                    "No Detection rows exist for this org yet -- MTTA needs at least "
                    "one real synced Detection."
                ),
            )

        if not deltas_seconds:
            return MetricResult(
                metric_name=self.metric_name,
                org_id=tenant.org_id,
                value=None,
                unit="seconds",
                sample_size=0,
                detail={
                    "total_detections": detection_count,
                    "detections_with_triage_event": len(first_triage_at),
                    "skipped_negative_delta": skipped_negative,
                },
                unavailable_reason=(
                    "None of this org's Detections have a real DETECTION_TRIAGE_"
                    "TRANSITIONED audit event yet -- every Detection triaged so far "
                    "produced only a negative delta, or (far more likely) none have "
                    "been triaged at all."
                ),
            )

        return MetricResult(
            metric_name=self.metric_name,
            org_id=tenant.org_id,
            value=statistics.mean(deltas_seconds),
            unit="seconds",
            sample_size=len(deltas_seconds),
            detail={
                "total_detections": detection_count,
                "detections_with_triage_event": len(first_triage_at),
                "min_seconds": min(deltas_seconds),
                "max_seconds": max(deltas_seconds),
                "median_seconds": statistics.median(deltas_seconds),
                "skipped_negative_delta": skipped_negative,
            },
        )
