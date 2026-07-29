"""Abstract repository for StructuredArtifact persistence."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from src.domain.artifact import StructuredArtifact


class ArtifactRepository(ABC):
    """Persists non-timeline StructuredArtifact objects.

    See reviews/Data_Source_Module_System.md for why these are stored
    separately from TimelineRecord (Postgres JSONB, not OpenSearch).
    """

    @abstractmethod
    async def save(self, artifact: StructuredArtifact) -> StructuredArtifact:
        """Persist one artifact."""

    @abstractmethod
    async def list_by_evidence(
        self, evidence_id: uuid.UUID, org_id: uuid.UUID
    ) -> list[StructuredArtifact]:
        """Return every artifact captured from a given evidence file, org-scoped."""


class InMemoryArtifactRepository(ArtifactRepository):
    """Process-local artifact store for tests and the DI default (mirrors
    InMemoryCaseRepository) -- never used in production, which must
    configure PostgresArtifactRepository via configure_dependencies()."""

    def __init__(self) -> None:
        self._artifacts: dict[uuid.UUID, StructuredArtifact] = {}

    async def save(self, artifact: StructuredArtifact) -> StructuredArtifact:
        self._artifacts[artifact.artifact_id] = artifact
        return artifact

    async def list_by_evidence(
        self, evidence_id: uuid.UUID, org_id: uuid.UUID
    ) -> list[StructuredArtifact]:
        return [
            a
            for a in self._artifacts.values()
            if a.kronos.evidence_id == evidence_id and a.kronos.org_id == org_id
        ]
