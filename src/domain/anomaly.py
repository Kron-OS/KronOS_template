"""Behavioral anomaly signal domain model (roadmap M6/G2).

**Deliberately NOT a `Detection` (`src/domain/detection.py`), not a subtype
of it, and never synced by anything resembling `DetectionSyncService`.**
`Detection` is a derived, recomputable opinion about an IMMUTABLE fact
(roadmap invariant #5) -- a real SA finding fired once, against one
document, and is frozen at sync time precisely because the thing it
mirrors has already stopped changing (roadmap invariant #6). An
OpenSearch Anomaly Detection (AD/RCF) result has no equivalent "this is
now a fixed, past fact" moment: RCF is an *online* model that
continuously updates its own internal state as more data streams in, so
the SAME historical data point can legitimately score differently on a
re-run months later (see ``poc/anomaly_detection_baseline/README.md``
"Design decision: BehavioralAnomalySignal is query-time-only, never
persisted" for the full reasoning, including why this is stronger than
G1's own "no consumer exists yet" reason for skipping persistence).

**Roadmap's own hard constraint, restated as a structural, mechanically
checkable property, not just a docstring warning:** "RCF ... is not
reproducible months later and must never be the evidentiary basis of a
finding. Triage prioritization and hunting leads only." G3 (the next
roadmap item, a GATE) will build a harness that must be able to
mechanically confirm this signal can never reach a court-facing verdict
path. Two independent, redundant markers exist for that harness to check,
so a future refactor accidentally dropping a docstring can't silently
defeat the guarantee:

- ``NOT_REPRODUCIBLE`` -- a class-level constant a static/import-time
  check can grep for or introspect without constructing an instance.
- ``not_reproducible`` -- a required, frozen instance field of type
  ``Literal[True]`` so a runtime harness inspecting an actual object (e.g.
  one that has already been serialized into an API response or a UI
  payload) can mechanically assert the marker survived serialization,
  which the class-level constant alone would not guarantee.

Mirrors ``Detection``'s general shape where it genuinely applies (org-scoped
via the caller's own authenticated ``TenantContext`` -- roadmap invariant
#3 -- has an id, has a timestamp) but is NOT frozen-as-replayable the way
`Detection`/`RiskFactor` are in the sense that matters: there is no
repository, no triage FSM, and no persistence layer for this type at all
(see the module's sibling ``src/application/anomaly_scoring.py`` for the
query-time-only orchestration this implies).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import ClassVar, Literal

from pydantic import BaseModel, Field


class AnomalyEntityDimension(BaseModel):
    """One ``category_field`` name/value pair a real AD result was attributed to.

    E.g. ``AnomalyEntityDimension(name="host.name", value="host-anomalous")``
    -- confirmed real shape from a live 2.11.1 multi-entity detector result
    (``poc/anomaly_detection_baseline/output.txt``): AD's own result
    document carries an ``entity`` array of exactly this ``{name, value}``
    shape, never a single flat field, mirroring
    ``DetectionRuleMatch``'s own "don't collapse a real list into a single
    value" lesson.
    """

    model_config = {"frozen": True}

    name: str
    value: str


class AnomalyFeatureObservation(BaseModel):
    """One scored feature's real observed value vs. the RCF model's own
    predicted-normal value at this data point.

    ``expected_value`` is ``None`` when the model had no prediction yet for
    this feature at this point (confirmed real: an early, shingle-not-yet-full
    result carries ``"error": "No full shingle in current detection
    window"`` and no ``expected_values`` at all -- see
    ``poc/anomaly_detection_baseline/output.txt``'s first captured result).
    An honest absence, never a fabricated default (same "never substitute a
    fabricated neutral value" constraint ``Detection.highest_rule_severity``
    already established for a different field).
    """

    model_config = {"frozen": True}

    feature_name: str
    observed_value: float
    expected_value: float | None = None


class BehavioralAnomalySignal(BaseModel):
    """One point-in-time OpenSearch AD/RCF observation for one org's own
    per-org detector -- a hunting lead, never a court-facing finding.

    See module docstring for why this is structurally, not just
    docstring-warned, separate from ``Detection``. ``anomaly_grade`` is
    AD's own real ``[0, 1]``-bounded severity score (0 = not anomalous, 1 =
    maximally anomalous, confirmed real range from
    ``poc/anomaly_detection_baseline/output.txt``); ``confidence`` is AD's
    own separate ``[0, 1]`` measure of how much the underlying model
    trusts that grade (low early in a detector's life, before its
    internal RCF forest has seen enough data -- NOT a KronOS-computed
    value, passed through verbatim from AD's own result document).
    """

    model_config = {"frozen": True}

    # Class-level marker -- see module docstring. A plain bool, not an
    # Enum/property: the whole point is a trivial, unambiguous
    # `BehavioralAnomalySignal.NOT_REPRODUCIBLE is True` check, not
    # something a future refactor could quietly reinterpret.
    NOT_REPRODUCIBLE: ClassVar[Literal[True]] = True

    signal_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    # Always the querying caller's own TenantContext values -- never
    # anything read out of the AD result document itself (roadmap
    # invariant #3), mirroring Detection.org_id's own contract exactly.
    org_id: uuid.UUID
    org_alias: str
    detector_id: str
    detector_name: str
    # None for a real-time job's result (this codebase does not currently
    # provision real-time jobs, only ensures the detector object exists --
    # see AnomalyDetectorProvisioner's own docstring for why); set for a
    # historical-analysis task's result, confirmed real field name
    # `task_id` (AnomalyResult.java / poc output).
    task_id: str | None = None
    entities: tuple[AnomalyEntityDimension, ...] = Field(default_factory=tuple)
    anomaly_grade: float = Field(ge=0.0, le=1.0)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    features: tuple[AnomalyFeatureObservation, ...] = Field(default_factory=tuple)
    data_start_time: datetime
    data_end_time: datetime
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    # Required, not defaulted-away: see module docstring's "belt-and-braces"
    # reasoning for why this duplicates NOT_REPRODUCIBLE at the instance
    # level rather than relying on the class constant alone.
    not_reproducible: Literal[True] = True
