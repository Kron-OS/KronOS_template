"""Abstract repository for audit log persistence."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from datetime import date, datetime

from src.domain.audit import AuditEvent


class AuditLogRepository(ABC):
    """Append-only audit log repository.

    Implementations must guarantee write-once semantics; existing events
    are never mutated or deleted.
    """

    @abstractmethod
    async def append(self, event: AuditEvent) -> AuditEvent:
        """Persist a new audit event and return it with the assigned sequence_number."""

    @abstractmethod
    async def get_latest_hash(self, org_id: uuid.UUID) -> str | None:
        """Return the row_hash of the most-recently appended event for this org."""

    @abstractmethod
    async def get_latest_sequence(self, org_id: uuid.UUID) -> int:
        """Return the sequence number of the most-recently appended event for this org."""

    @abstractmethod
    def stream_by_evidence(self, evidence_id: uuid.UUID) -> AsyncIterator[AuditEvent]:
        """Yield audit events for a given evidence item in chronological order."""

    @abstractmethod
    def stream_by_case(self, case_id: uuid.UUID) -> AsyncIterator[AuditEvent]:
        """Yield audit events for a given case in chronological order."""

    @abstractmethod
    def stream_by_org(self, org_id: uuid.UUID) -> AsyncIterator[AuditEvent]:
        """Yield ALL audit events for an org in chronological order (by sequence_number).

        Used by verify_chain and anchor_day — must return the complete org chain,
        not filtered by case_id.
        """

    async def list_by_date_range(
        self, start: datetime, end: datetime
    ) -> list[AuditEvent]:
        """Return all events with occurred_at in [start, end).

        Default implementation streams all events; Postgres implementation
        should override with a WHERE clause.
        """
        result: list[AuditEvent] = []
        all_events: list[AuditEvent] = []
        # Subclasses that store a flat list can be iterated; generic fallback.
        if hasattr(self, "_events"):
            all_events = list(getattr(self, "_events"))  # noqa: B009
        for ev in all_events:
            if start <= ev.occurred_at < end:
                result.append(ev)
        return result


class AnchorRepository(AuditLogRepository):
    """Extended audit log repository that also supports Merkle root anchoring."""

    @abstractmethod
    async def save_anchor(
        self, anchor_date: date, root_hash: str, tsa_token: bytes | None
    ) -> None:
        """Persist a daily Merkle root anchor."""

    @abstractmethod
    async def get_anchor(self, anchor_date: date) -> tuple[str, bytes | None] | None:
        """Return (root_hash, tsa_token) for the given date, or None if absent."""
