"""Unit tests for RiskFactor/RiskScoreBreakdown (pure domain models, no I/O).

Roadmap M5/F4. See tests/unit/application/test_risk_scoring.py for the
scorer that produces these, and tests/unit/application/test_detection_sync.py
for the full real end-to-end path.
"""

from __future__ import annotations

import pytest

from src.domain.risk import RiskFactor, RiskScoreBreakdown


class TestRiskFactor:
    def test_frozen(self) -> None:
        factor = RiskFactor(name="rule_severity", weight=0.35, normalized_value=0.75, detail="x")
        with pytest.raises(Exception):  # noqa: B017
            factor.weight = 0.5  # type: ignore[misc]

    def test_normalized_value_defaults_to_none(self) -> None:
        factor = RiskFactor(name="identity_privilege", weight=0.15, detail="absent")
        assert factor.normalized_value is None


class TestRiskScoreBreakdown:
    def test_frozen(self) -> None:
        breakdown = RiskScoreBreakdown(score=50.0, factors=())
        with pytest.raises(Exception):  # noqa: B017
            breakdown.score = 10.0  # type: ignore[misc]

    def test_score_defaults_to_none(self) -> None:
        breakdown = RiskScoreBreakdown()
        assert breakdown.score is None
        assert breakdown.factors == ()

    def test_explanation_reports_present_factor_with_normalized_value(self) -> None:
        breakdown = RiskScoreBreakdown(
            score=75.0,
            factors=(
                RiskFactor(
                    name="rule_severity",
                    weight=0.35,
                    normalized_value=0.75,
                    detail="highest matched rule severity is 'high'",
                ),
            ),
        )
        assert "rule_severity" in breakdown.explanation
        assert "0.75" in breakdown.explanation
        assert "highest matched rule severity is 'high'" in breakdown.explanation

    def test_explanation_reports_absent_factor_distinctly(self) -> None:
        breakdown = RiskScoreBreakdown(
            score=None,
            factors=(
                RiskFactor(
                    name="identity_privilege",
                    weight=0.15,
                    normalized_value=None,
                    detail="no identity-context enricher exists yet",
                ),
            ),
        )
        assert "absent" in breakdown.explanation
        assert "no identity-context enricher exists yet" in breakdown.explanation
