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

    @abstractmethod
    async def list_by_case(
        self, case_id: uuid.UUID, org_id: uuid.UUID
    ) -> list[StructuredArtifact]:
        """Return every artifact captured across a whole case, org-scoped.

        Backs the case-level Artifacts view (Gap Audit Milestone AAAAA):
        a case can hold several evidence files each with their own
        artifacts (e.g. two memory dumps), and the view needs to know
        which evidence files have any before a user picks one -- fetching
        per-evidence via list_by_evidence for every evidence row in the
        case would be an N+1 call pattern for that.
        """


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

    async def list_by_case(
        self, case_id: uuid.UUID, org_id: uuid.UUID
    ) -> list[StructuredArtifact]:
        return [
            a
            for a in self._artifacts.values()
            if a.kronos.case_id == case_id and a.kronos.org_id == org_id
        ]
