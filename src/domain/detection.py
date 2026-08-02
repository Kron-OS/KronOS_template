"""Detection domain model: an audited, KronOS-owned mirror of a real
OpenSearch Security Analytics finding, with its own triage FSM.

Roadmap M2/C4 (docs/NEXTGEN_SOC_ROADMAP.md). Mirrors the exact idiom
``src/domain/evidence.py`` establishes: immutable Pydantic models, an FSM
enforced via ``transition_to()``, and zero framework imports (CLAUDE.md
SS A.3) -- callers (``DetectionTriageService``) are responsible for wrapping
every mutation in ``AuditLogService.audit_context()``; this module never
does I/O or logging itself.

A Detection is a *derived, recomputable opinion about an immutable fact*
(roadmap invariant #5): it never writes to Evidence, the evidence audit
chain, or an indexed timeline record. Everything about the underlying SA
finding is captured once at sync time and frozen -- ``rule_matches``,
``source_index``, ``matched_document_ids`` never change after creation, so
a Detection stays a faithful, replayable record of what SA reported at that
moment (roadmap invariant #6), independent of SA's own live, mutable plugin
state (which the A3 gate already established has no per-tenant isolation
of its own -- see ``poc/security_analytics_tenant_isolation/``).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from src.exceptions import DetectionStateError

# ---------------------------------------------------------------------------
# Triage state machine: NEW -> INVESTIGATING -> TRUE_POSITIVE | FALSE_POSITIVE
# ---------------------------------------------------------------------------

_VALID_TRANSITIONS: dict[str, set[str]] = {
    "NEW": {"INVESTIGATING"},
    "INVESTIGATING": {"TRUE_POSITIVE", "FALSE_POSITIVE"},
    # Terminal: once triaged, a Detection's verdict is itself an immutable,
    # court-facing fact (roadmap invariant #6) -- reopening a closed triage
    # is out of scope here (would need its own, separately-audited
    # "reopen" event type, not a silent FSM loophole).
    "TRUE_POSITIVE": set(),
    "FALSE_POSITIVE": set(),
}


class DetectionTriageState(StrEnum):
    """Lifecycle states for a Detection's human triage verdict."""

    NEW = "NEW"
    INVESTIGATING = "INVESTIGATING"
    TRUE_POSITIVE = "TRUE_POSITIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"

    def can_transition_to(self, target: DetectionTriageState) -> bool:
        return target.value in _VALID_TRANSITIONS.get(self.value, set())

    def transition_to(self, target: DetectionTriageState) -> DetectionTriageState:
        if not self.can_transition_to(target):
            raise DetectionStateError(
                f"Invalid detection triage transition: {self.value} → {target.value}",
                context={"from_state": self.value, "to_state": target.value},
            )
        return target


class DetectionRuleMatch(BaseModel):
    """One Sigma rule that fired for this finding -- the replayability unit.

    A single real SA finding can match multiple rules simultaneously: a real
    finding document's own ``queries`` array proved this (verified against
    the live cluster, see poc/detection_finding_sync/), so this is a list on
    ``Detection``, never a single rule id -- storing only "the" rule id
    would silently drop replayable information a real finding actually
    carries.
    """

    model_config = {"frozen": True}

    rule_id: str
    rule_name: str | None = None
    tags: tuple[str, ...] = Field(default_factory=tuple)


class Detection(BaseModel):
    """One immutable-once-created mirror of a real SA finding, plus triage state."""

    model_config = {"frozen": True}

    detection_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    # org_id/org_alias are ALWAYS the syncing caller's own TenantContext
    # values -- never anything read out of the finding document itself
    # (roadmap invariant #3: tenant isolation is computed, never supplied).
    # See DetectionSyncService.sync_org_findings() for where this is
    # enforced.
    org_id: uuid.UUID
    org_alias: str
    # Best-effort case correlation parsed from the finding's own source
    # index name (not a security boundary -- see
    # detection_sync.py::_extract_case_id). None for stream-scoped indices
    # (roadmap B2) that carry no case_id at all.
    case_id: uuid.UUID | None = None
    # The real SA finding document's own top-level `_id` -- confirmed via a
    # live query to be a flat `keyword` field (not nested, unlike this same
    # findings index's own `queries` field, or the unrelated
    # detectors-config `name` field C2's idempotency bug hit). This is the
    # dedup key: (org_id, finding_id) is unique per DetectionRepository.
    finding_id: str
    detector_name: str
    source_index: str
    rule_matches: tuple[DetectionRuleMatch, ...] = Field(default_factory=tuple)
    matched_document_ids: tuple[str, ...] = Field(default_factory=tuple)
    finding_timestamp: datetime
    triage_state: DetectionTriageState = DetectionTriageState.NEW
    synced_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def attack_tags(self) -> tuple[str, ...]:
        """Deduped ATT&CK technique tags (e.g. ``attack.t1021.001``) across all matched rules."""
        seen: list[str] = []
        for match in self.rule_matches:
            for tag in match.tags:
                if tag.startswith("attack.") and tag not in seen:
                    seen.append(tag)
        return tuple(seen)

    def with_triage_state(self, target: DetectionTriageState) -> Detection:
        """Return a new Detection with the triage FSM advanced to *target*.

        Raises DetectionStateError on an illegal transition -- callers
        (DetectionTriageService) are responsible for auditing both outcomes.
        """
        new_state = self.triage_state.transition_to(target)
        return self.model_copy(update={"triage_state": new_state, "updated_at": datetime.now(UTC)})


class DetectionCorrelation(BaseModel):
    """An immutable, audited mirror of one real SA correlation-engine match
    linking two already-synced Detection rows for the SAME org.

    Roadmap M2/F3 (docs/NEXTGEN_SOC_ROADMAP.md) -- evaluated OpenSearch
    Security Analytics' native correlation engine (real, live on the pinned
    2.11.1 cluster, see poc/security_analytics_correlation/) rather than
    building a bespoke entity graph. A real correlation-rule match is
    reported by SA as a (finding_a, finding_b, rule_ids) triple via
    ``GET /_plugins/_security_analytics/correlations`` -- a cluster-wide,
    UNSCOPED endpoint with no org/tenant filter of its own (confirmed: its
    only real params are start_timestamp/end_timestamp). Tenant isolation
    is therefore enforced the same way roadmap invariant #3 requires
    everywhere else: computed by CorrelationSyncService from which
    Detection rows *this org* already synced (via
    DetectionRepository.get_by_finding_id), never from anything the
    correlations API itself claims to scope.

    Deliberately a SIBLING fact type, not a mutation of either linked
    Detection -- Detection is frozen/immutable-once-created (roadmap
    invariant #6: a Detection is a frozen snapshot of what SA reported at
    sync time), and a correlation between two findings can genuinely be
    discovered *after* both underlying Detections already exist (the
    correlation engine is a real-time listener on NEW findings, confirmed
    empirically to NOT retroactively correlate pre-existing ones -- see the
    PoC README's "Real bugs/gaps found #2"). Recording it as a new,
    append-only link avoids retrofitting mutability onto an entity whose
    whole point is to never change after creation.
    """

    model_config = {"frozen": True}

    correlation_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    # Always the syncing caller's own TenantContext.org_id -- never derived
    # from the correlations API response (roadmap invariant #3), mirroring
    # Detection.org_id's own contract.
    org_id: uuid.UUID
    detection_id_a: uuid.UUID
    detection_id_b: uuid.UUID
    finding_id_a: str
    finding_id_b: str
    # The real SA correlation rule id(s) that produced this link -- a real
    # pair can be tagged by more than one rule simultaneously (the same
    # "don't collapse a real list into a single value" lesson
    # DetectionRuleMatch's own docstring already recorded for rule_matches).
    rule_ids: tuple[str, ...] = Field(default_factory=tuple)
    synced_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
