"""Abstract and in-memory DeadLetterSink (roadmap M3/D5).

Mirrors the SealedBatchRepository/InMemorySealedBatchRepository pattern
(``src/adapter/repository/sealed_batch.py``): an ABC + a thread-unsafe
in-memory default so DI wiring never hard-fails before Postgres is
configured, plus a real Postgres implementation
(``postgres_dead_letter.py``) for production. Postgres was chosen over a
new storage backend because every other durable artifact in this pipeline
(``SealedBatch``, ``AuditEvent``, ``Detection``, ``RulePack``) is already
Postgres-backed -- a dead-lettered event is a small, structured, queryable
record (not a bulk blob needing WORM/Object-Lock the way a whole sealed
batch's raw payload does), so introducing a second durable store for this
one new entity would be inconsistent with zero real benefit.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from src.domain.dead_letter import DeadLetterEvent


class DeadLetterSink(ABC):
    """Append-only persistence for events that failed stream normalization."""

    @abstractmethod
    async def record(self, event: DeadLetterEvent) -> DeadLetterEvent:
        """Persist one dead-lettered event."""

    @abstractmethod
    async def list_for_batch(self, org_id: uuid.UUID, batch_id: uuid.UUID) -> list[DeadLetterEvent]:
        """Return every dead-lettered event for this org's batch, in
        ``event_offset`` order -- the real, queryable answer to "which
        events (and why) were dropped from this batch's indexing run."
        """


class InMemoryDeadLetterSink(DeadLetterSink):
    """Thread-unsafe in-memory double for unit tests."""

    def __init__(self) -> None:
        self._events: list[DeadLetterEvent] = []

    async def record(self, event: DeadLetterEvent) -> DeadLetterEvent:
        self._events.append(event)
        return event

    async def list_for_batch(self, org_id: uuid.UUID, batch_id: uuid.UUID) -> list[DeadLetterEvent]:
        return sorted(
            (e for e in self._events if e.org_id == org_id and e.batch_id == batch_id),
            key=lambda e: e.event_offset,
        )
