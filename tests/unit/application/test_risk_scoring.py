"""Unit tests for DetectionRiskScorer (pure domain logic, no mocks needed).

Roadmap M5/F4. Mirrors tests/unit/application/test_cost_gate.py's own style
(RuleCostGate's exact shape). See tests/unit/application/test_detection_sync.py
for the full, real, end-to-end scoring path (rule severity + real matched
OpenSearch documents' enrichment fields) through DetectionSyncService.
"""

from __future__ import annotations

import pytest

from src.application.risk_scoring import DetectionRiskScorer


@pytest.fixture
def scorer() -> DetectionRiskScorer:
    return DetectionRiskScorer()


class TestDetectionRiskScorerAllInputsPresent:
    def test_all_three_real_factors_present_computes_weighted_average(
        self, scorer: DetectionRiskScorer
    ) -> None:
        breakdown = scorer.score(
            rule_severity="high", ioc_confidence=80, asset_criticality="critical"
        )
        # (0.35*0.75 + 0.30*0.80 + 0.20*1.0) / 0.85 * 100 = 82.65
        assert breakdown.score == pytest.approx(82.65, abs=0.01)
        assert len(breakdown.factors) == 4

    def test_identical_inputs_produce_identical_score_deterministic(
        self, scorer: DetectionRiskScorer
    ) -> None:
        b1 = scorer.score(rule_severity="high", ioc_confidence=80, asset_criticality="critical")
        b2 = scorer.score(rule_severity="high", ioc_confidence=80, asset_criticality="critical")
        assert b1.score == b2.score

    def test_higher_asset_criticality_with_same_other_inputs_increases_score(
        self, scorer: DetectionRiskScorer
    ) -> None:
        """Same rule severity + higher asset criticality => higher score,
        the exact documented-delta requirement from this item's own brief."""
        low_asset = scorer.score(rule_severity="high", ioc_confidence=50, asset_criticality="low")
        critical_asset = scorer.score(
            rule_severity="high", ioc_confidence=50, asset_criticality="critical"
        )
        assert critical_asset.score is not None
        assert low_asset.score is not None
        assert critical_asset.score > low_asset.score

    def test_higher_ioc_confidence_with_same_other_inputs_increases_score(
        self, scorer: DetectionRiskScorer
    ) -> None:
        low_conf = scorer.score(
            rule_severity="medium", ioc_confidence=10, asset_criticality="medium"
        )
        high_conf = scorer.score(
            rule_severity="medium", ioc_confidence=90, asset_criticality="medium"
        )
        assert high_conf.score is not None
        assert low_conf.score is not None
        assert high_conf.score > low_conf.score

    def test_higher_rule_severity_with_same_other_inputs_increases_score(
        self, scorer: DetectionRiskScorer
    ) -> None:
        low_severity = scorer.score(
            rule_severity="low", ioc_confidence=50, asset_criticality="medium"
        )
        critical_severity = scorer.score(
            rule_severity="critical", ioc_confidence=50, asset_criticality="medium"
        )
        assert critical_severity.score is not None
        assert low_severity.score is not None
        assert critical_severity.score > low_severity.score

    def test_maximum_inputs_produce_maximum_score(self, scorer: DetectionRiskScorer) -> None:
        breakdown = scorer.score(
            rule_severity="critical", ioc_confidence=100, asset_criticality="critical"
        )
        assert breakdown.score == pytest.approx(100.0)

    def test_minimum_recognized_inputs_produce_minimum_score(
        self, scorer: DetectionRiskScorer
    ) -> None:
        breakdown = scorer.score(
            rule_severity="informational", ioc_confidence=0, asset_criticality=None
        )
        assert breakdown.score == pytest.approx(0.0)


class TestDetectionRiskScorerHonestDegradation:
    """Roadmap F4's binding constraint: an absent input is OMITTED from the
    formula, never defaulted to a fabricated neutral value."""

    def test_all_inputs_absent_yields_none_not_zero(self, scorer: DetectionRiskScorer) -> None:
        breakdown = scorer.score(rule_severity=None, ioc_confidence=None, asset_criticality=None)
        assert breakdown.score is None
        assert all(f.normalized_value is None for f in breakdown.factors)

    def test_only_rule_severity_present_scores_from_that_alone(
        self, scorer: DetectionRiskScorer
    ) -> None:
        breakdown = scorer.score(rule_severity="high", ioc_confidence=None, asset_criticality=None)
        assert breakdown.score == pytest.approx(75.0)

    def test_unrecognized_severity_tag_is_excluded_not_guessed(
        self, scorer: DetectionRiskScorer
    ) -> None:
        breakdown = scorer.score(
            rule_severity="not-a-real-level", ioc_confidence=50, asset_criticality=None
        )
        by_name = {f.name: f for f in breakdown.factors}
        assert by_name["rule_severity"].normalized_value is None
        assert "not a recognized Sigma level" in by_name["rule_severity"].detail

    def test_unrecognized_tenant_free_text_criticality_is_excluded_not_guessed(
        self, scorer: DetectionRiskScorer
    ) -> None:
        """Asset.criticality is deliberately tenant-defined free text
        (src/domain/asset.py) -- an unrecognized value must be excluded,
        never mapped to a guessed neutral value."""
        breakdown = scorer.score(
            rule_severity=None, ioc_confidence=None, asset_criticality="super-duper-bad"
        )
        by_name = {f.name: f for f in breakdown.factors}
        assert by_name["asset_criticality"].normalized_value is None
        assert breakdown.score is None

    def test_asset_criticality_is_case_insensitive_and_trimmed(
        self, scorer: DetectionRiskScorer
    ) -> None:
        breakdown = scorer.score(
            rule_severity=None, ioc_confidence=None, asset_criticality="  CRITICAL  "
        )
        by_name = {f.name: f for f in breakdown.factors}
        assert by_name["asset_criticality"].normalized_value == pytest.approx(1.0)

    def test_identity_privilege_always_absent_by_default(self, scorer: DetectionRiskScorer) -> None:
        """No caller in this codebase has a real identity-context signal yet
        (roadmap F1 STATUS: explicitly flagged, unbuilt follow-up scope)."""
        breakdown = scorer.score(rule_severity="high", ioc_confidence=None, asset_criticality=None)
        by_name = {f.name: f for f in breakdown.factors}
        assert by_name["identity_privilege"].normalized_value is None
        assert "no identity-context enricher exists yet" in by_name["identity_privilege"].detail

    def test_identity_privilege_contributes_when_a_real_value_is_supplied(
        self, scorer: DetectionRiskScorer
    ) -> None:
        """The parameter exists so a real future signal can plug in without
        redesigning the formula -- verify it actually changes the score."""
        without_identity = scorer.score(
            rule_severity="high", ioc_confidence=None, asset_criticality=None
        )
        with_identity = scorer.score(
            rule_severity="high",
            ioc_confidence=None,
            asset_criticality=None,
            identity_privilege=1.0,
        )
        assert with_identity.score is not None
        assert without_identity.score is not None
        assert with_identity.score != without_identity.score


class TestDetectionRiskScorerExplanation:
    def test_explanation_is_deterministic_and_human_readable(
        self, scorer: DetectionRiskScorer
    ) -> None:
        breakdown = scorer.score(
            rule_severity="high", ioc_confidence=80, asset_criticality="critical"
        )
        explanation = breakdown.explanation
        assert "rule_severity" in explanation
        assert "ioc_confidence" in explanation
        assert "asset_criticality" in explanation
        assert "identity_privilege" in explanation
        assert "absent" in explanation  # identity_privilege is always absent today
