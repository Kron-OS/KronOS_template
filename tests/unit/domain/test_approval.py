"""Unit tests for the ApprovalDecision domain model (roadmap M7/H2)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.domain.approval import ApprovalDecision


class TestApprovalDecision:
    def test_authorized_decision_round_trips(self) -> None:
        decision = ApprovalDecision(
            authorized=True, policy_name="step_up_mfa", reason="ticket consumed"
        )
        assert decision.authorized is True
        assert decision.policy_name == "step_up_mfa"

    def test_denied_decision_round_trips(self) -> None:
        decision = ApprovalDecision(
            authorized=False, policy_name="step_up_mfa", reason="no ticket supplied"
        )
        assert decision.authorized is False

    def test_is_frozen(self) -> None:
        decision = ApprovalDecision(authorized=True, policy_name="p", reason="r")
        with pytest.raises(ValidationError):
            decision.authorized = False  # type: ignore[misc]

    def test_empty_policy_name_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ApprovalDecision(authorized=True, policy_name="", reason="r")

    def test_empty_reason_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ApprovalDecision(authorized=True, policy_name="p", reason="")
