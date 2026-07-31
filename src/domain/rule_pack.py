"""Rule-pack lifecycle domain model: versioned, cost-gated, tenant-scoped
custom Sigma rules.

Roadmap M2/C3 (docs/NEXTGEN_SOC_ROADMAP.md). Builds on C1/C2's real,
verified mechanism (OpenSearch 2.11.1 Security Analytics compiles Sigma
server-side; KronOS deliberately never builds its own Sigma compiler --
roadmap SS0 decision 1). A ``RulePack`` is a named, versioned bundle of
Sigma rule definitions belonging to exactly one org. Two real risks this
model exists to close (see roadmap C3 entry):

(a) **Cost/DoS risk** -- a custom rule compiling to a catastrophically
    expensive OpenSearch query (leading wildcard, unanchored regex) is a
    trivial denial-of-service against the shared, multi-tenant cluster.
    ``CostGateVerdict`` records the outcome of a real, static check run
    BEFORE any rule is ever handed to OpenSearch (see
    ``src/application/cost_gate.py``).
(b) **Isolation-bypass risk** -- a rule is always a Sigma YAML document,
    never raw OpenSearch Query DSL. Sigma has no field for an index name or
    a tenant identifier, so the only way a custom rule could ever cross a
    tenant boundary is if the *detector* wrapping it were scoped to the
    wrong index pattern -- and that index pattern is always computed by
    KronOS from the authenticated ``TenantContext``, never from pack or
    rule content (mirrors ``StructuredArtifact.org_id`` per CLAUDE.md SS G.3,
    and ``Detection.org_id`` per C4 -- the identical invariant applied here).

Immutable, append-only versioning: ``RulePackVersion`` rows are never
updated or deleted once persisted (see ``RulePackRepository.save_version``'s
contract) -- creating a new version never loses a previous one, matching
roadmap invariant #6 (replayability: a detector built from "pack X version
N" must remain reproducible after pack X reaches version N+1).

Zero framework imports (CLAUDE.md SS A.3) -- pure Pydantic, no FastAPI/
httpx/SQLAlchemy here.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class RulePackSourceTier(StrEnum):
    """The two-tier trust model from
    reviews/Extensibility_Architecture_Proposal.md SS4, reused UNCHANGED per
    CLAUDE.md SS G.3 (that section explicitly mandates reusing this exact
    model for other trust-boundary decisions, not redesigning it).

    FIRST_PARTY content (OpenSearch's own 2,077 prepackaged Sigma rules) is
    referenced by id via SecurityAnalyticsDetectorProvisioner (C2) -- it
    never flows through this module at all, listed here only so the tier
    enum is complete and callers can't invent a fourth, unreviewed tier.
    """

    FIRST_PARTY = "first_party"
    TENANT_CUSTOM = "tenant_custom"
    SIGNED_THIRD_PARTY = "signed_third_party"


class CostGateDecision(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"


class CostGateFinding(BaseModel):
    """One heuristic's concrete, specific reason for flagging a rule.

    ``reason`` must name the actual compiled-query shape the heuristic is
    worried about (not a generic "looks risky") -- see
    ``src/application/cost_gate.py``, whose heuristics were built only after
    empirically confirming, against the real live OpenSearch 2.11.1
    cluster, what each flagged Sigma modifier actually compiles to.
    """

    model_config = {"frozen": True}

    heuristic: str
    reason: str


class CostGateVerdict(BaseModel):
    """The pre-execution cost-gate outcome for one rule's Sigma YAML.

    Computed and stored BEFORE the rule is ever pushed to OpenSearch
    (roadmap risk (a)) -- a REJECTED rule is retained in its
    ``RulePackVersion`` (never silently dropped, CLAUDE.md SS A.6/SS B.2:
    "no silent side effects") but is never eligible for
    ``RulePackService.publish_accepted_rules``.
    """

    model_config = {"frozen": True}

    decision: CostGateDecision
    findings: tuple[CostGateFinding, ...] = Field(default_factory=tuple)

    @property
    def accepted(self) -> bool:
        return self.decision == CostGateDecision.ACCEPTED


class CustomRule(BaseModel):
    """One Sigma rule authored or imported into a ``RulePackVersion``.

    ``sigma_yaml`` is the ONLY thing this rule is ever represented as on the
    wire to OpenSearch -- never a hand-built OpenSearch Query DSL body
    (roadmap risk (b): a raw-DSL passthrough path would bypass KronOS's own
    index-pattern tenant scoping entirely, since DSL can reference any
    index). ``opensearch_rule_id`` is the OpenSearch-assigned id returned by
    a real ``POST _plugins/_security_analytics/rules`` call -- confirmed
    empirically (poc/rule_pack_lifecycle/) to be independent of whatever
    ``id:`` the Sigma YAML itself declares -- so it stays ``None`` until
    ``RulePackService.publish_accepted_rules`` actually pushes it.
    """

    model_config = {"frozen": True}

    rule_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    title: str
    log_type: str
    sigma_yaml: str
    cost_gate_verdict: CostGateVerdict
    opensearch_rule_id: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def is_accepted(self) -> bool:
        return self.cost_gate_verdict.accepted

    def with_opensearch_rule_id(self, opensearch_rule_id: str) -> CustomRule:
        return self.model_copy(update={"opensearch_rule_id": opensearch_rule_id})


class RulePackVersion(BaseModel):
    """One immutable, append-only version of a pack's full rule content.

    ``org_id`` is always the authoring tenant's own ``TenantContext`` value
    (roadmap invariant #3), never anything read out of pack/rule content.
    ``content_sha256`` is only set for ``SIGNED_THIRD_PARTY`` imports -- the
    exact byte digest that was Cosign-signature-checked, kept for audit
    replayability of *what was actually verified*, not re-derived later.
    """

    model_config = {"frozen": True}

    pack_id: uuid.UUID
    version: int
    org_id: uuid.UUID
    source_tier: RulePackSourceTier
    rules: tuple[CustomRule, ...] = Field(default_factory=tuple)
    signature_verified: bool = False
    content_sha256: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def accepted_rules(self) -> tuple[CustomRule, ...]:
        return tuple(r for r in self.rules if r.is_accepted)

    def rules_for_log_type(self, log_type: str) -> tuple[CustomRule, ...]:
        return tuple(r for r in self.accepted_rules if r.log_type == log_type)


class RulePack(BaseModel):
    """A named bundle identity; ``RulePackVersion`` rows carry the actual content.

    Unique per ``(org_id, name)`` -- enforced by ``RulePackRepository``, not
    by this model (domain layer has no persistence concerns).
    """

    model_config = {"frozen": True}

    pack_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    org_id: uuid.UUID
    name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
