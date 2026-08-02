"""DetectionRiskScorer: deterministic, explainable weighted risk score
(roadmap M5/F4).

**Objective (roadmap):** "Deterministic, explainable scoring combining asset
criticality, identity privilege, IOC confidence, rule severity."

Mirrors ``RuleCostGate``'s shape (``src/application/cost_gate.py``): a small,
pure, stateless class over already-resolved inputs -- no I/O of its own.
Resolving those inputs (fetching matched OpenSearch documents for
enrichment fields, extracting the matched rules' own severity tags) is
``DetectionSyncService``'s job (``src/application/detection_sync.py``),
exactly the same division of labor ``RuleCostGate.evaluate()`` has with its
caller ``RulePackService`` (parse the YAML, then hand the already-parsed
``detection:`` block to the gate).

**Real Sigma severity vocabulary** (confirmed against the live, pinned
OpenSearch 2.11.1 dev cluster's own 2077 pre-packaged Security Analytics
rules, not assumed from memory -- see ``poc/detection_risk_scoring/``):
``informational`` (23 rules), ``low`` (205), ``medium`` (720), ``high``
(972), ``critical`` (157). ``src/domain/detection.py``'s
``SIGMA_SEVERITY_LEVELS`` is the single source of truth for this ordering;
this module imports it rather than re-declaring it.

**Why weights are code constants, not ``Settings`` fields.** Unlike this
codebase's genuine per-deployment values (Keycloak URL, MinIO bucket
prefix), a scoring weight IS the algorithm -- CLAUDE.md's own "deterministic,
explainable" requirement means the formula that produced a frozen
``Detection.risk_score`` must be reproducible from what's actually in the
codebase at that commit, not from an ops-editable env var that could
silently drift per-environment/per-org and make two orgs' "same inputs"
scores incomparable. This mirrors ``RuleCostGate``'s own hardcoded
``_LEADING_WILDCARD_MODIFIERS`` -- a deliberate design decision, not an
oversight (see this item's roadmap STATUS note for the full reasoning).

**Honest degradation (roadmap F4's binding constraint).** Every factor
below is included in the weighted average ONLY when a real, present value
exists for it; an absent factor is *omitted* from the formula (its weight
is excluded from the normalization denominator too), never substituted
with a fabricated neutral/default value that would look like real signal.
``identity_privilege`` in particular is *always* absent today -- F1's own
STATUS note flagged identity-context enrichment as unbuilt follow-up
scope, and this scorer must never invent a stand-in for it.
"""

from __future__ import annotations

from src.domain.detection import SIGMA_SEVERITY_LEVELS
from src.domain.risk import RiskFactor, RiskScoreBreakdown

# Real Sigma level -> normalized [0, 1] score. Ordinal spacing (0.25 per
# step) over the 5-value vocabulary confirmed against the live cluster
# above -- not an arbitrary curve, a plain linear map over an ordered,
# finite, real enum.
SEVERITY_NORMALIZED_LEVELS: dict[str, float] = {
    level: index / (len(SIGMA_SEVERITY_LEVELS) - 1)
    for index, level in enumerate(SIGMA_SEVERITY_LEVELS)
}

# Asset.criticality (src/domain/asset.py) is deliberately tenant-defined
# free text ("Tenant-defined free-text criticality, e.g. 'high'") -- there
# is no server-enforced enum. Only these 4 conventional values are
# recognized here; an unrecognized tenant string is honestly excluded
# (never guessed) -- see DetectionRiskScorer.score()'s asset_criticality
# handling below.
ASSET_CRITICALITY_NORMALIZED_LEVELS: dict[str, float] = {
    "low": 0.25,
    "medium": 0.5,
    "high": 0.75,
    "critical": 1.0,
}


class DetectionRiskScorer:
    """Computes a 0-100 weighted risk score from up to 4 factors, 3 of which
    are real and wired today (rule severity, IOC confidence, asset
    criticality); the 4th (identity privilege) is honestly always absent
    (see module docstring) until a real identity-context enricher exists.

    Weights sum to 1.0 across the full, intended 4-factor formula; when
    ``identity_privilege`` is absent (always, currently) its 0.15 share is
    excluded from both the numerator and the denominator, so the score is
    the weighted average of ONLY the factors that actually had a value --
    never diluted by a phantom "0" for a factor that was never measured.
    """

    RULE_SEVERITY_WEIGHT = 0.35
    IOC_CONFIDENCE_WEIGHT = 0.30
    ASSET_CRITICALITY_WEIGHT = 0.20
    IDENTITY_PRIVILEGE_WEIGHT = 0.15

    def score(
        self,
        *,
        rule_severity: str | None,
        ioc_confidence: int | None,
        asset_criticality: str | None,
        identity_privilege: float | None = None,
    ) -> RiskScoreBreakdown:
        """Return a full, reproducible ``RiskScoreBreakdown``.

        Args:
            rule_severity: highest real Sigma ``level`` tag among the
                Detection's matched rules (``Detection.rule_severity``), or
                None if no matched rule carried a recognized severity tag.
            ioc_confidence: the real STIX 0-100 confidence value from the
                matched documents' own ``enrichment.ioc.confidence`` field
                (F2), or None if no matched document carried one.
            asset_criticality: the real tenant-defined criticality string
                from the matched documents' own ``enrichment.asset.criticality``
                field (F1), or None if no matched document carried one.
            identity_privilege: reserved for a future real identity-context
                signal (0.0-1.0, higher = more privileged); always None
                today -- no caller in this codebase has a real source for
                this yet, and none may fabricate one.
        """
        factors: list[RiskFactor] = []
        weighted_sum = 0.0
        weight_total = 0.0

        normalized_severity = (
            SEVERITY_NORMALIZED_LEVELS.get(rule_severity) if rule_severity is not None else None
        )
        if normalized_severity is not None:
            weighted_sum += self.RULE_SEVERITY_WEIGHT * normalized_severity
            weight_total += self.RULE_SEVERITY_WEIGHT
            severity_detail = f"highest matched rule severity is '{rule_severity}'"
        elif rule_severity is None:
            severity_detail = "no matched rule carried a recognized Sigma severity tag"
        else:
            severity_detail = (
                f"matched rule severity tag '{rule_severity}' is not a recognized Sigma level"
            )
        factors.append(
            RiskFactor(
                name="rule_severity",
                weight=self.RULE_SEVERITY_WEIGHT,
                normalized_value=normalized_severity,
                detail=severity_detail,
            )
        )

        normalized_confidence = None
        if ioc_confidence is not None:
            normalized_confidence = max(0.0, min(1.0, ioc_confidence / 100))
            weighted_sum += self.IOC_CONFIDENCE_WEIGHT * normalized_confidence
            weight_total += self.IOC_CONFIDENCE_WEIGHT
            confidence_detail = f"matched document(s) carry IOC confidence {ioc_confidence}/100"
        else:
            confidence_detail = "no matched document carried an enrichment.ioc.confidence value"
        factors.append(
            RiskFactor(
                name="ioc_confidence",
                weight=self.IOC_CONFIDENCE_WEIGHT,
                normalized_value=normalized_confidence,
                detail=confidence_detail,
            )
        )

        normalized_criticality = (
            ASSET_CRITICALITY_NORMALIZED_LEVELS.get(asset_criticality.strip().lower())
            if asset_criticality is not None
            else None
        )
        if normalized_criticality is not None:
            weighted_sum += self.ASSET_CRITICALITY_WEIGHT * normalized_criticality
            weight_total += self.ASSET_CRITICALITY_WEIGHT
            criticality_detail = (
                f"matched document(s) resolve to asset criticality '{asset_criticality}'"
            )
        elif asset_criticality is None:
            criticality_detail = "no matched document carried an enrichment.asset.criticality value"
        else:
            criticality_detail = (
                f"matched document asset criticality '{asset_criticality}' is tenant free-text "
                "and not one of the recognized levels (low/medium/high/critical) -- excluded, "
                "never guessed"
            )
        factors.append(
            RiskFactor(
                name="asset_criticality",
                weight=self.ASSET_CRITICALITY_WEIGHT,
                normalized_value=normalized_criticality,
                detail=criticality_detail,
            )
        )

        # Always absent today (see module docstring) -- the parameter exists
        # so a real future identity signal can be plugged in without
        # redesigning the formula, never to be defaulted by this scorer.
        normalized_identity = None
        if identity_privilege is not None:
            normalized_identity = max(0.0, min(1.0, identity_privilege))
            weighted_sum += self.IDENTITY_PRIVILEGE_WEIGHT * normalized_identity
            weight_total += self.IDENTITY_PRIVILEGE_WEIGHT
            identity_detail = f"identity privilege signal {identity_privilege:.2f}"
        else:
            identity_detail = (
                "no identity-context enricher exists yet (roadmap F1 STATUS: explicitly flagged, "
                "unbuilt follow-up scope) -- omitted from the formula, never defaulted"
            )
        factors.append(
            RiskFactor(
                name="identity_privilege",
                weight=self.IDENTITY_PRIVILEGE_WEIGHT,
                normalized_value=normalized_identity,
                detail=identity_detail,
            )
        )

        score = round(weighted_sum / weight_total * 100, 2) if weight_total > 0 else None
        return RiskScoreBreakdown(score=score, factors=tuple(factors))
