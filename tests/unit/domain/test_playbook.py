"""Unit tests for the Playbook domain model (roadmap M7/H1)."""

from __future__ import annotations

from src.domain.playbook import (
    Playbook,
    PlaybookExecutionResult,
    PlaybookStep,
    PlaybookStepOutcome,
    PlaybookStepResult,
)


class TestPlaybookExecutionResultSucceeded:
    def test_succeeded_true_when_every_step_succeeds_and_not_halted(self) -> None:
        result = PlaybookExecutionResult(
            playbook_id=Playbook(name="p", steps=()).playbook_id,
            playbook_name="p",
            step_results=(
                PlaybookStepResult(
                    step_id="s1", action_name="echo", params={}, outcome=PlaybookStepOutcome.SUCCESS
                ),
            ),
            halted_early=False,
        )
        assert result.succeeded is True

    def test_succeeded_false_when_halted_early(self) -> None:
        result = PlaybookExecutionResult(
            playbook_id=Playbook(name="p", steps=()).playbook_id,
            playbook_name="p",
            step_results=(
                PlaybookStepResult(
                    step_id="s1",
                    action_name="always_fails",
                    params={},
                    outcome=PlaybookStepOutcome.FAILED,
                    error="boom",
                ),
            ),
            halted_early=True,
        )
        assert result.succeeded is False

    def test_succeeded_false_when_any_step_failed_even_without_halt_flag(self) -> None:
        """Defensive: even if halted_early were ever wrong, a FAILED step
        outcome alone must never read as succeeded."""
        result = PlaybookExecutionResult(
            playbook_id=Playbook(name="p", steps=()).playbook_id,
            playbook_name="p",
            step_results=(
                PlaybookStepResult(
                    step_id="s1", action_name="x", params={}, outcome=PlaybookStepOutcome.FAILED
                ),
            ),
            halted_early=False,
        )
        assert result.succeeded is False

    def test_succeeded_true_for_a_zero_step_playbook(self) -> None:
        result = PlaybookExecutionResult(
            playbook_id=Playbook(name="empty", steps=()).playbook_id,
            playbook_name="empty",
            step_results=(),
            halted_early=False,
        )
        assert result.succeeded is True


class TestPlaybookIsPureData:
    def test_playbook_and_steps_are_frozen(self) -> None:
        playbook = Playbook(
            name="test",
            steps=(PlaybookStep(step_id="s1", action_name="echo", params={"a": 1}),),
        )
        assert playbook.model_config.get("frozen") is True
        assert playbook.steps[0].model_config.get("frozen") is True

    def test_two_steps_can_reference_the_same_action_with_different_params(self) -> None:
        playbook = Playbook(
            name="test",
            steps=(
                PlaybookStep(step_id="s1", action_name="echo", params={"a": 1}),
                PlaybookStep(step_id="s2", action_name="echo", params={"a": 2}),
            ),
        )
        assert playbook.steps[0].action_name == playbook.steps[1].action_name
        assert playbook.steps[0].params != playbook.steps[1].params
