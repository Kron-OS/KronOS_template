"""Abstract and in-memory DetectionCorrelation repository.

Roadmap M2/F3. Mirrors DetectionRepository's own shape exactly (ABC + a
thread-unsafe in-memory default so DI wiring never hard-fails before
Postgres is configured, plus a real Postgres implementation,
postgres_detection_correlation.py, for production).
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from src.domain.detection import DetectionCorrelation


class DetectionCorrelationRepository(ABC):
    """Org-scoped DetectionCorrelation persistence, deduped by the real
    (org_id, finding_id_a, finding_id_b) triple regardless of ordering."""

    @abstractmethod
    async def save(self, correlation: DetectionCorrelation) -> DetectionCorrelation:
        """Persist a new correlation link. Must raise if a link between the
        same two finding_ids (in either order) already exists for this org --
        this is the idempotency backstop CorrelationSyncService relies on
        under races, mirroring DetectionRepository.save()'s own contract."""

    @abstractmethod
    async def exists_for_pair(
        self, org_id: uuid.UUID, finding_id_a: str, finding_id_b: str
    ) -> bool:
        """True if a correlation link already exists for this org between
        these two finding_ids, in EITHER order (SA reports a pair without a
        stable ordering -- confirmed by a real run: the same real pair can
        surface as (a, b) or (b, a) depending on which finding_id the
        `findings/correlate` query was anchored on)."""

    @abstractmethod
    def stream_by_org(self, org_id: uuid.UUID) -> AsyncIterator[DetectionCorrelation]:
        """Yield all correlation links for an org."""

    @abstractmethod
    def stream_by_detection(
        self, detection_id: uuid.UUID, org_id: uuid.UUID
    ) -> AsyncIterator[DetectionCorrelation]:
        """Yield every correlation link involving this Detection (as either
        side of the pair) -- the lookup a triage view needs."""


class InMemoryDetectionCorrelationRepository(DetectionCorrelationRepository):
    """Thread-unsafe in-memory impl for unit tests and until Postgres is wired."""

    def __init__(self) -> None:
        self._store: dict[uuid.UUID, DetectionCorrelation] = {}

    async def save(self, correlation: DetectionCorrelation) -> DetectionCorrelation:
        if await self.exists_for_pair(
            correlation.org_id, correlation.finding_id_a, correlation.finding_id_b
        ):
            from src.exceptions import StorageError  # noqa: PLC0415

            raise StorageError(
                "Correlation link already exists for this finding pair",
                context={
                    "org_id": str(correlation.org_id),
                    "finding_id_a": correlation.finding_id_a,
                    "finding_id_b": correlation.finding_id_b,
                },
            )
        self._store[correlation.correlation_id] = correlation
        return correlation

    async def exists_for_pair(
        self, org_id: uuid.UUID, finding_id_a: str, finding_id_b: str
    ) -> bool:
        pair = {finding_id_a, finding_id_b}
        return any(
            c.org_id == org_id and {c.finding_id_a, c.finding_id_b} == pair
            for c in self._store.values()
        )

    async def stream_by_org(self, org_id: uuid.UUID) -> AsyncIterator[DetectionCorrelation]:
        for correlation in sorted(self._store.values(), key=lambda c: c.synced_at):
            if correlation.org_id == org_id:
                yield correlation

    async def stream_by_detection(
        self, detection_id: uuid.UUID, org_id: uuid.UUID
    ) -> AsyncIterator[DetectionCorrelation]:
        for correlation in sorted(self._store.values(), key=lambda c: c.synced_at):
            if correlation.org_id == org_id and detection_id in (
                correlation.detection_id_a,
                correlation.detection_id_b,
            ):
                yield correlation
