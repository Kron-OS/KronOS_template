"""Permanent regression tests for the G3 GATE (roadmap M6/G3,
docs/NEXTGEN_SOC_ROADMAP.md): explainability + replayability harness.

`poc/explainability_replayability_gate/` proved these three properties ONCE
against real, live infrastructure (real OpenSearch 2.11.1, real Postgres
16) per CLAUDE.md SS F.2; this module keeps proving them on every future
change, using pure Pydantic-factory fixtures (CLAUDE.md SS B.5 -- no mocks
of domain objects, no real I/O needed since both replay claims are pure
functions of already-in-memory data):

1. F4: a Detection's risk_score reproduces from its OWN risk_factors tuple
   alone, via ``score_from_factors`` -- the SAME function
   ``DetectionRiskScorer.score()`` itself calls, so there is exactly one
   formula, never a parallel reimplementation that could drift.
2. C3: a CustomRule's cost_gate_verdict reproduces from its OWN sigma_yaml
   alone, via a brand-new ``RuleCostGate`` instance.
3. G2: none of the real Detection-related source files reference the
   anomaly module in any way (a permanent, grep-based import-boundary
   check -- this test FAILS the moment a future change adds such a
   reference), and ``BehavioralAnomalySignal``'s two non-reproducibility
   markers exist, enforce ``Literal[True]`` at construction time, and
   survive ``model_dump(mode="json")`` serialization.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.application.cost_gate import RuleCostGate
from src.application.risk_scoring import DetectionRiskScorer, score_from_factors
from src.domain.anomaly import AnomalyEntityDimension, BehavioralAnomalySignal
from src.domain.risk import RiskFactor

REPO_ROOT = Path(__file__).resolve().parents[2]

# Same real, empirically-derived Sigma shapes cost_gate's own unit tests use
# (tests/unit/application/test_cost_gate.py) -- one accepted, one rejected.
_REASONABLE_RULE = """
detection:
  selection:
    dest_port: 4444
  condition: selection
"""

_EXPENSIVE_RULE = """
detection:
  selection:
    process.command_line|contains: 'evil'
  condition: selection
"""

# The exact six real files the orchestrator's own grep (and this GATE's
# PoC) confirmed reference the anomaly module NOWHERE today. This list is
# the enforced boundary -- see poc/explainability_replayability_gate/README.md
# "Binding conditions" #1.
_DETECTION_RELATED_FILES = [
    "src/domain/detection.py",
    "src/application/detection_sync.py",
    "src/application/detection_triage.py",
    "src/adapter/repository/detection.py",
    "src/adapter/repository/postgres_detection.py",
    "src/external/routes/detections.py",
]


class TestF4RiskScoreReplayFromStoredFactorsAlone:
    """A Detection's frozen risk_score must reproduce from its own frozen
    risk_factors tuple alone -- no rule_severity/ioc_confidence/
    asset_criticality inputs, no re-fetch of anything."""

    def test_full_breakdown_replays_from_its_own_factors(self) -> None:
        scorer = DetectionRiskScorer()
        breakdown = scorer.score(
            rule_severity="high", ioc_confidence=80, asset_criticality="critical"
        )
        replayed = score_from_factors(breakdown.factors)
        assert replayed == breakdown.score

    def test_partial_degradation_breakdown_replays_from_its_own_factors(self) -> None:
        """The honest-degradation path (roadmap F4) -- some factors absent --
        must replay identically too, not just the all-present case."""
        scorer = DetectionRiskScorer()
        breakdown = scorer.score(rule_severity="high", ioc_confidence=None, asset_criticality=None)
        replayed = score_from_factors(breakdown.factors)
        assert replayed == breakdown.score
        assert replayed == pytest.approx(75.0)

    def test_all_absent_breakdown_replays_to_none_not_a_fabricated_zero(self) -> None:
        scorer = DetectionRiskScorer()
        breakdown = scorer.score(rule_severity=None, ioc_confidence=None, asset_criticality=None)
        replayed = score_from_factors(breakdown.factors)
        assert replayed is None
        assert breakdown.score is None

    def test_replay_is_unaffected_by_reconstructing_the_factors_tuple_independently(
        self,
    ) -> None:
        """Simulates the real PoC's negative control (drifted live enrichment)
        in pure, in-memory form: build a RiskFactor tuple that looks exactly
        like what would have been frozen onto a Detection at sync time, with
        no scorer/live-input involved at all, and confirm the replay formula
        reproduces the same score a live scorer call with equivalent inputs
        would have produced -- proving score_from_factors depends ONLY on
        (weight, normalized_value) pairs, never on anything external."""
        frozen_factors = (
            RiskFactor(name="rule_severity", weight=0.35, normalized_value=1.0, detail="x"),
            RiskFactor(name="ioc_confidence", weight=0.30, normalized_value=0.7, detail="x"),
            RiskFactor(name="asset_criticality", weight=0.20, normalized_value=0.75, detail="x"),
            RiskFactor(name="identity_privilege", weight=0.15, normalized_value=None, detail="x"),
        )
        replayed = score_from_factors(frozen_factors)
        assert replayed == pytest.approx(83.53, abs=0.01)
        # Re-running on the identical frozen tuple again must be
        # deterministic -- the whole point of a "replay".
        assert score_from_factors(frozen_factors) == replayed

    def test_detection_risk_scorer_score_uses_the_same_function_as_the_replay_path(
        self,
    ) -> None:
        """Guards against a future refactor silently reintroducing a second,
        divergent formula inside DetectionRiskScorer.score() instead of
        calling score_from_factors -- the single-source-of-truth property
        the G3 PoC's refactor established."""
        scorer = DetectionRiskScorer()
        breakdown = scorer.score(
            rule_severity="medium", ioc_confidence=55, asset_criticality="medium"
        )
        assert breakdown.score == score_from_factors(breakdown.factors)


class TestC3CostGateReplayFromStoredSigmaYamlAlone:
    """A CustomRule's frozen cost_gate_verdict must reproduce from its own
    frozen sigma_yaml alone, re-evaluated through a brand-new gate."""

    def test_accepted_rule_verdict_replays_identically(self) -> None:
        original_verdict = RuleCostGate().evaluate(_REASONABLE_RULE)
        replayed_verdict = RuleCostGate().evaluate(_REASONABLE_RULE)
        assert replayed_verdict == original_verdict
        assert replayed_verdict.accepted is True

    def test_rejected_rule_verdict_replays_identically_including_findings(self) -> None:
        original_verdict = RuleCostGate().evaluate(_EXPENSIVE_RULE)
        replayed_verdict = RuleCostGate().evaluate(_EXPENSIVE_RULE)
        assert replayed_verdict == original_verdict
        assert replayed_verdict.accepted is False
        assert replayed_verdict.findings == original_verdict.findings

    def test_replay_uses_a_fresh_gate_instance_no_shared_state_required(self) -> None:
        """RuleCostGate must be a pure function of its own input -- a second,
        independently-constructed instance (with its own default heuristics
        list) must produce the exact same verdict, never relying on any
        state carried over from the instance that produced the original."""
        gate_a = RuleCostGate()
        gate_b = RuleCostGate()
        assert gate_a.evaluate(_EXPENSIVE_RULE) == gate_b.evaluate(_EXPENSIVE_RULE)


class TestG2StructuralExclusionOfAnomalySignalsFromDetectionLand:
    """Permanent regression: G2's non-reproducible BehavioralAnomalySignal
    must never leak into anything Detection-related. Fails the moment a
    future change adds such a reference."""

    @pytest.mark.parametrize("rel_path", _DETECTION_RELATED_FILES)
    def test_detection_related_file_never_mentions_anomaly(self, rel_path: str) -> None:
        text = (REPO_ROOT / rel_path).read_text()
        assert "anomaly" not in text.lower(), (
            f"{rel_path} must never reference the anomaly module (roadmap G3's "
            "structural-exclusion invariant) -- found the substring 'anomaly' "
            "(case-insensitive)"
        )

    def test_not_reproducible_class_constant_exists_and_is_true(self) -> None:
        assert BehavioralAnomalySignal.NOT_REPRODUCIBLE is True

    def test_not_reproducible_instance_field_exists_and_is_true(self) -> None:
        signal = BehavioralAnomalySignal(
            org_id=uuid.uuid4(),
            org_alias="test-org",
            detector_id="det-1",
            detector_name="test-detector",
            entities=(AnomalyEntityDimension(name="host.name", value="host-anomalous"),),
            anomaly_grade=0.9,
            confidence=0.7,
            data_start_time=datetime.now(UTC),
            data_end_time=datetime.now(UTC),
        )
        assert signal.not_reproducible is True

    def test_not_reproducible_survives_json_mode_serialization(self) -> None:
        signal = BehavioralAnomalySignal(
            org_id=uuid.uuid4(),
            org_alias="test-org",
            detector_id="det-1",
            detector_name="test-detector",
            anomaly_grade=0.5,
            data_start_time=datetime.now(UTC),
            data_end_time=datetime.now(UTC),
        )
        dumped = signal.model_dump(mode="json")
        assert dumped["not_reproducible"] is True
        # The ClassVar is correctly NOT instance data -- must not appear in
        # the dump at all (confirms it stays a pure introspection marker,
        # never accidentally serialized as if it were per-instance state).
        assert "NOT_REPRODUCIBLE" not in dumped

    def test_forging_not_reproducible_false_is_rejected_at_construction(self) -> None:
        with pytest.raises(ValidationError):
            BehavioralAnomalySignal(
                org_id=uuid.uuid4(),
                org_alias="test-org",
                detector_id="det-1",
                detector_name="test-detector",
                anomaly_grade=0.5,
                data_start_time=datetime.now(UTC),
                data_end_time=datetime.now(UTC),
                not_reproducible=False,  # type: ignore[arg-type]
            )
