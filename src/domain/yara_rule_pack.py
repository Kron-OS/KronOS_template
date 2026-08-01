"""YARA rule-pack lifecycle domain model: versioned, signed, tenant-scoped
custom YARA-X rulesets.

Roadmap E4 (docs/NEXTGEN_SOC_ROADMAP.md): "Same trust model as C3, applied
to YARA rulesets." Mirrors ``src/domain/rule_pack.py`` (Sigma's
``RulePack``/``RulePackVersion``/``CustomRule``) shape-for-shape --
org-scoped, immutable/append-only versioning, ``RulePackSourceTier`` reused
UNCHANGED (CLAUDE.md SS G.3: this two-tier trust model, from
``reviews/Extensibility_Architecture_Proposal.md`` SS4, is reused for every
trust-boundary decision in this codebase, not redesigned per artifact
type).

**No cost/DoS gate here (deliberate, considered decision -- not an
oversight).** C3's ``RuleCostGate`` exists because a Sigma rule compiles to
an OpenSearch/Lucene query that runs against a *shared, multi-tenant*
cluster -- a single bad rule (leading wildcard, unanchored regex) can
degrade query latency for every tenant indefinitely, every time any
detector re-runs it. YARA-X rulesets have no equivalent shared-resource
amplification path: ``YaraXSandboxRunner`` (roadmap E2,
``src/external/sandbox/yara_x_runner.py``) compiles and scans entirely
inside one sandboxed, single-purpose subprocess
(``docker/yara/kronos-yarax-worker.py``) that is ALREADY wall-clock-bounded
two ways -- the in-worker ``Scanner.set_timeout()`` call, plus
``YaraXSandboxRunner``'s own outer subprocess timeout
(``timeout_seconds + _SUBPROCESS_TIMEOUT_MARGIN_SECONDS``) as a backstop if
the first one somehow doesn't fire. A pathological rule (e.g. catastrophic
backtracking) burns CPU/wall-clock in that ONE worker process for at most
that bound, then the call fails closed with ``YaraScanError`` -- contained
per-scan, per-member, never cluster-wide and never unbounded. Building a
parallel static-heuristic gate here would duplicate a mitigation that
already exists and is already real (not proposed), for a risk shape YARA-X
scanning does not actually have. If a future real incident shows the
existing timeout insufficient (e.g. a worker that hangs past its wall-clock
bound without the OS actually reclaiming it), that is a fix to
``YaraXSandboxRunner``'s own timeout enforcement, not a new gate here.

Immutable, append-only versioning: ``YaraRulePackVersion`` rows are never
updated or deleted once persisted (mirrors ``RulePackVersion``'s own
contract) -- creating version N+1 never loses version N (roadmap
invariant #6: a scan run against "pack X version N" must remain
reproducible after pack X reaches version N+1). "Publishing" a version
(see ``YaraRulePackRepository.publish_version``) is a SEPARATE, mutable
pointer -- flipping which already-persisted version is currently active
for scanning never mutates or deletes any version row, exactly mirroring
how C3's ``published_custom_rules`` table is a separate pointer table from
the immutable ``rule_pack_versions`` rows it points into.

Zero framework imports (CLAUDE.md SS A.3) -- pure Pydantic, no FastAPI/
httpx/SQLAlchemy/yara_x here.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, Field

from src.domain.rule_pack import RulePackSourceTier

__all__ = [
    "RulePackSourceTier",
    "YaraRule",
    "YaraRulePack",
    "YaraRulePackVersion",
]


class YaraRule(BaseModel):
    """One named YARA-X rule (one or more ``rule NAME { ... }`` blocks)
    authored or imported into a ``YaraRulePackVersion``.

    ``rule_source`` is the ONLY thing this rule is ever represented as --
    raw YARA-X-compilable text, concatenated with every other rule in the
    version to form the single combined string
    ``YaraRuleProvider.get_rule_source()`` returns (mirrors
    ``CustomRule.sigma_yaml``'s "never a hand-built query" invariant,
    applied here to "never anything but real YARA-X rule syntax").
    """

    model_config = {"frozen": True}

    rule_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    name: str
    rule_source: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class YaraRulePackVersion(BaseModel):
    """One immutable, append-only version of a YARA rule pack's full content.

    ``org_id`` is always the authoring tenant's own ``TenantContext`` value
    (mirrors ``RulePackVersion.org_id``), never anything read out of
    pack/rule content. ``content_sha256`` is only set for
    ``SIGNED_THIRD_PARTY`` imports -- the exact byte digest that was
    Cosign-signature-checked (mirrors ``RulePackVersion.content_sha256``).
    """

    model_config = {"frozen": True}

    pack_id: uuid.UUID
    version: int
    org_id: uuid.UUID
    source_tier: RulePackSourceTier
    rules: tuple[YaraRule, ...] = Field(default_factory=tuple)
    signature_verified: bool = False
    content_sha256: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def combined_rule_source(self) -> str | None:
        """Every rule's source, concatenated into one YARA-X-compilable
        string -- the exact shape ``YaraRuleProvider.get_rule_source()``
        must return (one compile+scan per member, not one per rule; see
        ``src/application/yara_rules.py``'s own docstring). ``None`` if this
        version has no rules, so a caller can distinguish "no ruleset" from
        an empty string.
        """
        if not self.rules:
            return None
        return "\n\n".join(r.rule_source for r in self.rules)


class YaraRulePack(BaseModel):
    """A named bundle identity; ``YaraRulePackVersion`` rows carry the
    actual content.

    Unique per ``(org_id, name)`` -- enforced by ``YaraRulePackRepository``,
    not by this model (domain layer has no persistence concerns).
    """

    model_config = {"frozen": True}

    pack_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    org_id: uuid.UUID
    name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
