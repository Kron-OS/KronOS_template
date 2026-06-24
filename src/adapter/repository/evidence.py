"""Abstract repository for evidence metadata persistence."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from src.domain.evidence import Evidence, EvidenceState


class EvidenceRepository(ABC):
    """Evidence metadata CRUD, scoped to org_id at every access."""

    @abstractmethod
    async def save(self, evidence: Evidence) -> Evidence:
        """Persist a new evidence entity and return it."""

    @abstractmethod
    async def update(self, evidence: Evidence) -> Evidence:
        """Replace the stored evidence entity with the supplied version."""

    @abstractmethod
    async def get_by_id(self, evidence_id: uuid.UUID, org_id: uuid.UUID) -> Evidence | None:
        """Return evidence if it exists and belongs to org_id, otherwise None."""

    @abstractmethod
    def stream_by_case(self, case_id: uuid.UUID, org_id: uuid.UUID) -> AsyncIterator[Evidence]:
        """Yield all evidence for a case in creation order."""

    @abstractmethod
    def stream_by_state(self, state: EvidenceState, org_id: uuid.UUID) -> AsyncIterator[Evidence]:
        """Yield all evidence in a given state for an org (used by recovery tasks)."""
