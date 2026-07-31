"""Unit tests for pluggable seal-trigger policies (roadmap M3/D3)."""

from __future__ import annotations

from src.application.sealing_trigger_policy import (
    CompositeTriggerPolicy,
    SizeBoundTriggerPolicy,
    TimeBoundTriggerPolicy,
)


class TestSizeBoundTriggerPolicy:
    def test_seals_once_threshold_reached(self) -> None:
        policy = SizeBoundTriggerPolicy(max_events=10)
        assert not policy.should_seal(pending_event_count=9, oldest_pending_age_seconds=0)
        assert policy.should_seal(pending_event_count=10, oldest_pending_age_seconds=0)
        assert policy.should_seal(pending_event_count=11, oldest_pending_age_seconds=0)


class TestTimeBoundTriggerPolicy:
    def test_seals_once_age_threshold_reached(self) -> None:
        policy = TimeBoundTriggerPolicy(max_age_seconds=60)
        assert not policy.should_seal(pending_event_count=3, oldest_pending_age_seconds=59)
        assert policy.should_seal(pending_event_count=3, oldest_pending_age_seconds=60)

    def test_never_seals_an_empty_segment(self) -> None:
        policy = TimeBoundTriggerPolicy(max_age_seconds=0)
        assert not policy.should_seal(pending_event_count=0, oldest_pending_age_seconds=999)


class TestCompositeTriggerPolicy:
    def test_seals_when_any_sub_policy_fires(self) -> None:
        policy = CompositeTriggerPolicy(
            [SizeBoundTriggerPolicy(max_events=1000), TimeBoundTriggerPolicy(max_age_seconds=60)]
        )
        # Size not met, but time is -- "whichever comes first".
        assert policy.should_seal(pending_event_count=5, oldest_pending_age_seconds=60)
        # Time not met, but size is.
        assert policy.should_seal(pending_event_count=1000, oldest_pending_age_seconds=1)

    def test_does_not_seal_when_no_sub_policy_fires(self) -> None:
        policy = CompositeTriggerPolicy(
            [SizeBoundTriggerPolicy(max_events=1000), TimeBoundTriggerPolicy(max_age_seconds=60)]
        )
        assert not policy.should_seal(pending_event_count=5, oldest_pending_age_seconds=1)

    def test_requires_at_least_one_policy(self) -> None:
        try:
            CompositeTriggerPolicy([])
        except ValueError:
            return
        raise AssertionError("expected ValueError for empty policy list")
