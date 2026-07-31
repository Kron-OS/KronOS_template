"""Pluggable seal-trigger policies for continuous-stream batch sealing
(roadmap M3/D3).

Mirrors ``RuleCostGate``'s composition idiom (``src/application/cost_gate.py``):
an ABC for one policy, concrete implementations for each real trigger shape,
and a composing class instead of an if/elif chain -- registering a new
trigger condition (e.g. a future "seal immediately on legal-hold attach")
means adding a class and listing it in ``CompositeTriggerPolicy``'s
constructor call, zero edits to existing policies.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class SealingTriggerPolicy(ABC):
    """Decides whether a pending, not-yet-sealed segment of a stream should be
    sealed right now.

    Called once per seal cycle by ``BatchSealingService`` with the *current*
    pending-but-unacked event count and the age (in seconds) of the oldest
    pending event -- never with the events themselves, so a policy can never
    accidentally look at, or make a decision based on, event payload content.
    """

    @abstractmethod
    def should_seal(self, *, pending_event_count: int, oldest_pending_age_seconds: float) -> bool:
        """Return True if the pending segment should be sealed now."""


class SizeBoundTriggerPolicy(SealingTriggerPolicy):
    """Seals once at least ``max_events`` are pending."""

    def __init__(self, max_events: int) -> None:
        self._max_events = max_events

    def should_seal(self, *, pending_event_count: int, oldest_pending_age_seconds: float) -> bool:
        return pending_event_count >= self._max_events


class TimeBoundTriggerPolicy(SealingTriggerPolicy):
    """Seals once the oldest pending event has waited at least ``max_age_seconds``.

    Requires at least one pending event -- an empty segment is never "sealed"
    (``BatchSealingService`` already short-circuits on zero messages, this
    guard is defense in depth for direct unit testing of the policy alone).
    """

    def __init__(self, max_age_seconds: float) -> None:
        self._max_age_seconds = max_age_seconds

    def should_seal(self, *, pending_event_count: int, oldest_pending_age_seconds: float) -> bool:
        return pending_event_count > 0 and oldest_pending_age_seconds >= self._max_age_seconds


class CompositeTriggerPolicy(SealingTriggerPolicy):
    """Seals as soon as ANY composed policy says so ("whichever comes first").

    The real, sensible default this roadmap item asked for -- size OR time --
    is just ``CompositeTriggerPolicy([SizeBoundTriggerPolicy(...),
    TimeBoundTriggerPolicy(...)])``; no dedicated "SizeOrTime" class needed.
    """

    def __init__(self, policies: list[SealingTriggerPolicy]) -> None:
        if not policies:
            raise ValueError("CompositeTriggerPolicy requires at least one policy")
        self._policies = policies

    def should_seal(self, *, pending_event_count: int, oldest_pending_age_seconds: float) -> bool:
        return any(
            p.should_seal(
                pending_event_count=pending_event_count,
                oldest_pending_age_seconds=oldest_pending_age_seconds,
            )
            for p in self._policies
        )
