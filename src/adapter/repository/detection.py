"""Abstract and in-memory Detection repository.

Mirrors the CaseRepository/EvidenceRepository pattern (src/adapter/repository/
case_repository.py, evidence.py): an ABC + a thread-unsafe in-memory
default so DI wiring never hard-fails before Postgres is configured, plus
a real Postgres implementation (postgres_detection.py) for production.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from src.domain.detection import Detection, DetectionTriageState


class DetectionRepository(ABC):
    """Org-scoped Detection persistence, keyed additionally by the real SA finding id."""

    @abstractmethod
    async def save(self, detection: Detection) -> Detection:
        """Persist a new Detection. Must raise if (org_id, finding_id) already exists --
        this is the idempotency backstop DetectionSyncService relies on under races."""

    @abstractmethod
    async def get_by_id(self, detection_id: uuid.UUID, org_id: uuid.UUID) -> Detection | None:
        """Return the Detection if it belongs to org_id, otherwise None."""

    @abstractmethod
    async def get_by_finding_id(self, finding_id: str, org_id: uuid.UUID) -> Detection | None:
        """Return the Detection already synced from this real SA finding, if any.

        The primary idempotency check DetectionSyncService calls before
        ever constructing a new Detection for a given finding.
        """

    @abstractmethod
    async def update(
        self, detection: Detection, *, expected_state: DetectionTriageState | None = None
    ) -> Detection:
        """Replace the stored Detection. When *expected_state* is given, the write is
        conditioned on the persisted row's triage_state matching it (optimistic
        concurrency, mirroring EvidenceRepository.update)."""

    @abstractmethod
    def stream_by_org(self, org_id: uuid.UUID) -> AsyncIterator[Detection]:
        """Yield all Detections for an org."""

    @abstractmethod
    def stream_by_case(self, case_id: uuid.UUID, org_id: uuid.UUID) -> AsyncIterator[Detection]:
        """Yield all Detections correlated to a case."""


class InMemoryDetectionRepository(DetectionRepository):
    """Thread-unsafe in-memory impl for unit tests and until Postgres is wired."""

    def __init__(self) -> None:
        self._store: dict[uuid.UUID, Detection] = {}

    async def save(self, detection: Detection) -> Detection:
        existing = await self.get_by_finding_id(detection.finding_id, detection.org_id)
        if existing is not None:
            from src.exceptions import StorageError  # noqa: PLC0415

            raise StorageError(
                "Detection already exists for this finding",
                context={"finding_id": detection.finding_id, "org_id": str(detection.org_id)},
            )
        self._store[detection.detection_id] = detection
        return detection

    async def get_by_id(self, detection_id: uuid.UUID, org_id: uuid.UUID) -> Detection | None:
        detection = self._store.get(detection_id)
        if detection is None or detection.org_id != org_id:
            return None
        return detection

    async def get_by_finding_id(self, finding_id: str, org_id: uuid.UUID) -> Detection | None:
        for detection in self._store.values():
            if detection.org_id == org_id and detection.finding_id == finding_id:
                return detection
        return None

    async def update(
        self, detection: Detection, *, expected_state: DetectionTriageState | None = None
    ) -> Detection:
        current = self._store.get(detection.detection_id)
        if current is None:
            from src.exceptions import StorageError  # noqa: PLC0415

            raise StorageError(
                "Detection not found for update",
                context={"detection_id": str(detection.detection_id)},
            )
        if expected_state is not None and current.triage_state != expected_state:
            from src.exceptions import ConcurrentModificationError  # noqa: PLC0415

            # Gap Audit 2026-08-28: distinct from the "not found" branch
            # above -- mirrors postgres_detection.py's own real fix so a
            # route can map this specific condition to 409, not 503.
            raise ConcurrentModificationError(
                "Detection triage state changed concurrently",
                context={
                    "detection_id": str(detection.detection_id),
                    "expected_state": expected_state.value,
                },
            )
        self._store[detection.detection_id] = detection
        return detection

    async def stream_by_org(self, org_id: uuid.UUID) -> AsyncIterator[Detection]:
        for detection in sorted(self._store.values(), key=lambda d: d.synced_at):
            if detection.org_id == org_id:
                yield detection

    async def stream_by_case(
        self, case_id: uuid.UUID, org_id: uuid.UUID
    ) -> AsyncIterator[Detection]:
        for detection in sorted(self._store.values(), key=lambda d: d.synced_at):
            if detection.org_id == org_id and detection.case_id == case_id:
                yield detection
