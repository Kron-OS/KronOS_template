"""Risk-score domain model: a deterministic, explainable breakdown of the
factors behind one Detection's ``risk_score`` (roadmap M5/F4).

Mirrors ``src/domain/rule_pack.py``'s ``CostGateFinding``/``CostGateVerdict``
shape exactly -- a frozen "verdict" object carrying its own itemized
findings, computed by a pure application-layer scorer
(``src/application/risk_scoring.py::DetectionRiskScorer``, the
``RuleCostGate`` analogue) and then frozen onto the ``Detection`` it
describes at sync time. Zero framework imports (CLAUDE.md SS A.3): this
module only expresses data, never fetches or computes anything itself.

**Why every factor is always represented, even when absent.** CLAUDE.md's
own requirement is "deterministic, explainable" scoring -- a
``RiskFactor`` with ``normalized_value=None`` is the honest record of "this
input did not contribute, and here specifically is why" (e.g. "no
identity-context enricher exists yet"), never a silently-dropped factor a
reader would have no way to notice went missing. This is the same
"honestly disabled, never fabricated" idiom this codebase already uses for
optional collaborators elsewhere (``RFC3161TimestampService``,
``EnrichmentPipeline`` with zero enrichers).
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class RiskFactor(BaseModel):
    """One scoring input's contribution (or honest non-contribution) to a
    Detection's overall risk_score.

    ``weight`` is the factor's configured share of the total formula
    (``DetectionRiskScorer``'s own class constants) -- always present, even
    when this factor didn't contribute, so a reader can see what weight
    *would* have applied. ``normalized_value`` is ``None`` exactly when this
    factor was not present/recognized for this Detection; never a fabricated
    neutral default (roadmap F4's own binding constraint on the
    identity-privilege gap, applied identically to every other absent
    input).
    """

    model_config = {"frozen": True}

    name: str
    weight: float = Field(ge=0.0, le=1.0)
    normalized_value: float | None = Field(default=None, ge=0.0, le=1.0)
    detail: str


class RiskScoreBreakdown(BaseModel):
    """The full, reproducible output of one ``DetectionRiskScorer.score()`` call.

    ``score`` is ``None`` only in the degenerate case where NO factor had a
    usable value at all (e.g. a finding whose matched rule carries no
    recognized severity tag and whose matched documents carry no
    enrichment data) -- an honest "could not be scored", never a fabricated
    0.0 that would misleadingly read as "confirmed no risk". Otherwise
    ``score`` is 0-100, computed as the weighted average of only the
    factors that actually had a value (roadmap F4: absent inputs are
    omitted from the formula, never defaulted) -- reproducible from
    ``factors`` alone, which is the whole point of keeping this as
    structured data rather than just a number.
    """

    model_config = {"frozen": True}

    score: float | None = Field(default=None, ge=0.0, le=100.0)
    factors: tuple[RiskFactor, ...] = Field(default_factory=tuple)

    @property
    def explanation(self) -> str:
        """Human-readable, deterministic summary of every factor's contribution."""
        parts: list[str] = []
        for factor in self.factors:
            if factor.normalized_value is None:
                parts.append(
                    f"{factor.name} (weight {factor.weight:.2f}): absent -- {factor.detail}"
                )
            else:
                parts.append(
                    f"{factor.name} (weight {factor.weight:.2f}): "
                    f"{factor.detail} -- normalized {factor.normalized_value:.2f}"
                )
        return "; ".join(parts)
