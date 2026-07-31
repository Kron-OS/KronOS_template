"""Pre-execution cost gate for custom Sigma rules.

Roadmap M2/C3 (docs/NEXTGEN_SOC_ROADMAP.md). Does NOT compile Sigma --
roadmap SS0 already recorded the binding decision not to build a Sigma
compiler, since OpenSearch 2.11.1 Security Analytics does that server-side.
This module is a static *linter* over a Sigma rule's own ``detection:``
block, flagging shapes empirically confirmed (poc/rule_pack_lifecycle/) to
compile into genuinely expensive OpenSearch/Lucene query constructs --
confirmed by actually creating rules with these modifiers against the real
live cluster and reading the resulting compiled ``queries[].value`` back,
not guessed from Sigma spec documentation alone:

    |contains   -> "*term*"   (leading AND trailing wildcard)
    |endswith   -> "*term"    (leading wildcard)
    |startswith -> "term*"    (trailing wildcard only -- NOT flagged, this
                               is a cheap prefix query Lucene can seek
                               directly in the term dictionary for)
    |re         -> a raw OpenSearch/Lucene regex query

A leading wildcard or an unanchored regex forces OpenSearch to test every
term in the field's term dictionary one at a time (no seek, no prefix
optimization) -- on a shared, multi-tenant index this is a genuine,
trivially-triggered denial-of-service vector from a single bad rule, which
is exactly why this gate exists (roadmap risk (a)) and runs BEFORE the rule
is ever handed to OpenSearch's own custom-rule store (unlike OpenSearch
itself, which was empirically confirmed to accept both of these rule shapes
with zero validation or warning -- see poc/rule_pack_lifecycle/README.md).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

import yaml

from src.domain.rule_pack import CostGateDecision, CostGateFinding, CostGateVerdict

# Confirmed empirically against OpenSearch 2.11.1 (poc/rule_pack_lifecycle/):
# these two modifiers compile to a query with a **leading** wildcard.
_LEADING_WILDCARD_MODIFIERS = frozenset({"contains", "endswith"})


class CostGateHeuristic(ABC):
    """One pluggable expensive-pattern check over a parsed Sigma ``detection:`` block.

    Registering a new heuristic (e.g. a future "too many OR clauses" or
    "excessive field cardinality" check) means adding a class and listing it
    in ``RuleCostGate``'s constructor call -- zero edits to existing
    heuristics, matching ``ParserRegistry``'s no-if/elif idiom.
    """

    @abstractmethod
    def evaluate(self, detection: dict[str, Any]) -> CostGateFinding | None:
        """Return a CostGateFinding if *detection* matches this heuristic's
        expensive pattern, else None. Must never raise on malformed input --
        an unparseable detection block is the caller's concern (RuleCostGate
        surfaces it as a rejection with its own finding), not this method's."""


def _iter_field_values(detection: dict[str, Any]):
    """Yield (field_key, value) pairs across every named selection block.

    Sigma's ``detection`` block maps arbitrary selection names (``selection``,
    ``filter``, ``keywords``, ...) to either a dict of field: value pairs, or
    (for a bare keyword search) a plain list of strings. Only the dict shape
    carries a *field* a heuristic can reason about, so a plain-list selection
    is intentionally skipped here -- flagging bare keyword lists is out of
    scope for this pass (no leading-wildcard/regex modifier is possible on a
    keyword list, Sigma's modifiers only apply to field: value mappings).
    """
    for key, block in detection.items():
        if key == "condition" or not isinstance(block, dict):
            continue
        yield from block.items()


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


class LeadingWildcardHeuristic(CostGateHeuristic):
    """Flags ``|contains``/``|endswith`` modifiers and bare leading-``*`` literals."""

    def evaluate(self, detection: dict[str, Any]) -> CostGateFinding | None:
        for key, value in _iter_field_values(detection):
            parts = key.split("|")
            field, modifiers = parts[0], parts[1:]
            if any(m in _LEADING_WILDCARD_MODIFIERS for m in modifiers):
                return CostGateFinding(
                    heuristic="leading_wildcard",
                    reason=(
                        f"field '{field}' uses modifier(s) {modifiers}, confirmed against "
                        f"OpenSearch 2.11.1 to compile to a leading wildcard query "
                        f"(|contains -> '*x*', |endswith -> '*x') -- cannot use the "
                        f"term-dictionary prefix structure, forces a full per-term scan"
                    ),
                )
            if not modifiers:
                for v in _as_list(value):
                    if isinstance(v, str) and v.startswith("*"):
                        return CostGateFinding(
                            heuristic="leading_wildcard",
                            reason=f"field '{field}' has a literal leading-wildcard value {v!r}",
                        )
        return None


class UnanchoredRegexHeuristic(CostGateHeuristic):
    """Flags ``|re`` modifier patterns that are unanchored (don't start with ``^``).

    Confirmed empirically: ``|re: '.*\\.evil\\..*\\.com$'`` compiles to a raw
    OpenSearch regex query (``/.*\\.evil\\..*\\.com$/``). Lucene's regex
    automaton cannot seek past a leading ``.*`` the way a term/prefix query
    can seek in the term dictionary -- it degrades to the same
    full-term-dictionary-scan cost class as a leading wildcard.
    """

    def evaluate(self, detection: dict[str, Any]) -> CostGateFinding | None:
        for key, value in _iter_field_values(detection):
            field, modifiers = key.split("|")[0], key.split("|")[1:]
            if "re" not in modifiers:
                continue
            for v in _as_list(value):
                if isinstance(v, str) and not v.startswith("^"):
                    return CostGateFinding(
                        heuristic="unanchored_regex",
                        reason=(
                            f"field '{field}' regex {v!r} is unanchored (does not start "
                            f"with '^') -- confirmed against OpenSearch 2.11.1 to compile "
                            f"to a raw regex query with no prefix to seek on, forcing a "
                            f"full term-dictionary scan"
                        ),
                    )
        return None


class RuleCostGate:
    """Composition of ``CostGateHeuristic``s, run over a rule's raw Sigma YAML
    BEFORE it is ever handed to OpenSearch (roadmap risk (a))."""

    def __init__(self, heuristics: list[CostGateHeuristic] | None = None) -> None:
        self._heuristics = heuristics or [LeadingWildcardHeuristic(), UnanchoredRegexHeuristic()]

    def evaluate(self, sigma_yaml: str) -> CostGateVerdict:
        try:
            parsed = yaml.safe_load(sigma_yaml) or {}
        except yaml.YAMLError as exc:
            return CostGateVerdict(
                decision=CostGateDecision.REJECTED,
                findings=(CostGateFinding(heuristic="unparseable_yaml", reason=str(exc)),),
            )
        detection = parsed.get("detection", {}) if isinstance(parsed, dict) else {}
        findings = tuple(f for h in self._heuristics if (f := h.evaluate(detection)) is not None)
        decision = CostGateDecision.REJECTED if findings else CostGateDecision.ACCEPTED
        return CostGateVerdict(decision=decision, findings=findings)
