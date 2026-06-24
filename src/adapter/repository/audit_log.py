"""Abstract repository for audit log persistence."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

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
