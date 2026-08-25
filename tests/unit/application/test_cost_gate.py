"""Unit tests for RuleCostGate (pure domain logic, no mocks needed)."""

from __future__ import annotations

from src.application.cost_gate import RuleCostGate
from src.domain.rule_pack import CostGateDecision

_REASONABLE = """
detection:
  selection:
    dest_port: 4444
  condition: selection
"""

_CONTAINS = """
detection:
  selection:
    process.command_line|contains: 'evil'
  condition: selection
"""

_ENDSWITH = """
detection:
  selection:
    process.command_line|endswith: 'evil.exe'
  condition: selection
"""

_STARTSWITH = """
detection:
  selection:
    process.command_line|startswith: 'evil'
  condition: selection
"""

_LITERAL_LEADING_WILDCARD = """
detection:
  selection:
    process.command_line: '*evil*'
  condition: selection
"""

_ANCHORED_REGEX = """
detection:
  selection:
    dns.question.name|re: '^evil\\.com$'
  condition: selection
"""

_UNANCHORED_REGEX = """
detection:
  selection:
    dns.question.name|re: '.*evil.*'
  condition: selection
"""


class TestRuleCostGate:
    def test_reasonable_rule_is_accepted(self) -> None:
        verdict = RuleCostGate().evaluate(_REASONABLE)
        assert verdict.decision == CostGateDecision.ACCEPTED
        assert verdict.accepted is True
        assert verdict.findings == ()

    def test_contains_modifier_is_rejected(self) -> None:
        verdict = RuleCostGate().evaluate(_CONTAINS)
        assert not verdict.accepted
        assert verdict.findings[0].heuristic == "leading_wildcard"

    def test_endswith_modifier_is_rejected(self) -> None:
        verdict = RuleCostGate().evaluate(_ENDSWITH)
        assert not verdict.accepted

    def test_startswith_modifier_is_not_rejected(self) -> None:
        """A trailing-only wildcard is a cheap prefix query -- must not be flagged."""
        verdict = RuleCostGate().evaluate(_STARTSWITH)
        assert verdict.accepted

    def test_literal_leading_wildcard_value_is_rejected(self) -> None:
        verdict = RuleCostGate().evaluate(_LITERAL_LEADING_WILDCARD)
        assert not verdict.accepted
        assert verdict.findings[0].heuristic == "leading_wildcard"

    def test_anchored_regex_is_not_rejected(self) -> None:
        verdict = RuleCostGate().evaluate(_ANCHORED_REGEX)
        assert verdict.accepted

    def test_unanchored_regex_is_rejected(self) -> None:
        verdict = RuleCostGate().evaluate(_UNANCHORED_REGEX)
        assert not verdict.accepted
        assert verdict.findings[0].heuristic == "unanchored_regex"

    def test_unparseable_yaml_is_rejected_not_raised(self) -> None:
        verdict = RuleCostGate().evaluate("not: valid: yaml: [")
        assert not verdict.accepted
        assert verdict.findings[0].heuristic == "unparseable_yaml"

    def test_empty_detection_block_is_accepted(self) -> None:
        verdict = RuleCostGate().evaluate("title: no detection block")
        assert verdict.accepted

    def test_condition_key_is_never_treated_as_a_field(self) -> None:
        verdict = RuleCostGate().evaluate(
            """
detection:
  condition: selection
"""
        )
        assert verdict.accepted

    def test_bare_keyword_list_selection_is_not_flagged(self) -> None:
        """A plain-list selection has no field a heuristic can reason about."""
        verdict = RuleCostGate().evaluate(
            """
detection:
  keywords:
    - some literal string
  condition: keywords
"""
        )
        assert verdict.accepted
