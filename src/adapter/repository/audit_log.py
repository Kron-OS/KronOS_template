"""Abstract repository for audit log persistence."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator, Callable
from datetime import date, datetime

from src.domain.audit import AuditEvent

# Builds the final AuditEvent from the (prev_row_hash, latest_sequence_number)
# observed under the per-org lock — used by append_atomic so hash-chain
# computation stays in the Application layer, not the repository.
EventBuilder = Callable[[str | None, int], AuditEvent]


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
    async def append_atomic(self, org_id: uuid.UUID, build_event: EventBuilder) -> AuditEvent:
        """Atomically read the org's chain tip, build, and persist the next event.

        Serializes concurrent writers for the same *org_id* so that no two
        callers ever observe the same (prev_hash, sequence_number) tip —
        implementations must hold an org-scoped lock across the read of the
        current tip, the call to *build_event(prev_hash, latest_sequence)*,
        and the insert, releasing it only once the event is durably persisted
        (or the operation fails). This is what prevents the hash-chain and
        ``sequence_number`` from ever forking under concurrent writes.
        """

    @abstractmethod
    def stream_by_evidence(
        self, evidence_id: uuid.UUID, org_id: uuid.UUID
    ) -> AsyncIterator[AuditEvent]:
        """Yield audit events for a given evidence item in chronological
        order, scoped to *org_id* -- defense-in-depth org scoping (mirrors
        ``EvidenceRepository.get_by_id``; see Gap Audit Milestone SS)."""

    @abstractmethod
    def stream_by_case(self, case_id: uuid.UUID, org_id: uuid.UUID) -> AsyncIterator[AuditEvent]:
        """Yield audit events for a given case in chronological order,
        scoped to *org_id* -- defense-in-depth org scoping (mirrors
        ``CaseRepository.get_by_id``; see Gap Audit Milestone SS)."""

    @abstractmethod
    def stream_by_org(self, org_id: uuid.UUID) -> AsyncIterator[AuditEvent]:
        """Yield ALL audit events for an org in chronological order (by sequence_number).

        Used by verify_chain and anchor_day — must return the complete org chain,
        not filtered by case_id.
        """

    async def list_by_date_range(self, start: datetime, end: datetime) -> list[AuditEvent]:
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
    """Extended audit log repository that also supports Merkle root anchoring.

    Anchors are scoped per (org_id, date): the hash chain and its
    sequence_number are per-org (see append_atomic), so a "day" Merkle root
    only makes sense computed over one org's events at a time — the
    Merkle-proof endpoint (AUDIT-05) validates a specific org's event against
    its own day's anchor.  ``org_id`` is nullable to allow a genuine
    cross-org/system-level anchor row if one is ever needed, but the daily
    beat task anchors one row per org that had activity that day.
    """

    @abstractmethod
    async def save_anchor(
        self,
        anchor_date: date,
        root_hash: str,
        tsa_token: bytes | None,
        *,
        org_id: uuid.UUID | None = None,
        event_count: int = 0,
    ) -> None:
        """Persist a daily Merkle root anchor for *org_id* (or a system anchor if None)."""

    @abstractmethod
    async def get_anchor(
        self, anchor_date: date, *, org_id: uuid.UUID | None = None
    ) -> tuple[str, bytes | None] | None:
        """Return (root_hash, tsa_token) for (*org_id*, anchor_date), or None if absent."""
