"""Abstract and in-memory SealedBatch repository (roadmap M3/D3).

Mirrors the DetectionRepository/CaseRepository pattern: an ABC + a
thread-unsafe in-memory default so DI wiring never hard-fails before
Postgres is configured, plus a real Postgres implementation
(postgres_sealed_batch.py) for production.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from src.domain.sealed_batch import SealedBatch


class SealedBatchRepository(ABC):
    """Append-only SealedBatch persistence, keyed by (org_id, source_id).

    Sealed batches are never mutated or deleted once saved (roadmap
    invariant #5 -- a sealed batch is a primary evidentiary artifact, same
    rigor as ``Evidence``).
    """

    @abstractmethod
    async def save(self, batch: SealedBatch) -> SealedBatch:
        """Persist a new SealedBatch."""

    @abstractmethod
    async def get_by_id(self, batch_id: uuid.UUID, org_id: uuid.UUID) -> SealedBatch | None:
        """Return the batch if it belongs to org_id, otherwise None."""

    @abstractmethod
    async def get_last_sealed(self, org_id: uuid.UUID, source_id: str) -> SealedBatch | None:
        """Return the most recently sealed batch for this (org, source), if any.

        Used as the sealing watermark: the next seal cycle's MAXLEN-trim gap
        check compares the stream's current earliest retained message id
        against this batch's ``last_message_id``.
        """


class InMemorySealedBatchRepository(SealedBatchRepository):
    """Thread-unsafe in-memory double for unit tests."""

    def __init__(self) -> None:
        self._batches: dict[uuid.UUID, SealedBatch] = {}

    async def save(self, batch: SealedBatch) -> SealedBatch:
        self._batches[batch.batch_id] = batch
        return batch

    async def get_by_id(self, batch_id: uuid.UUID, org_id: uuid.UUID) -> SealedBatch | None:
        batch = self._batches.get(batch_id)
        return batch if batch is not None and batch.org_id == org_id else None

    async def get_last_sealed(self, org_id: uuid.UUID, source_id: str) -> SealedBatch | None:
        candidates = [
            b
            for b in self._batches.values()
            if b.org_id == org_id and b.source_id == source_id
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda b: b.sealed_at)
