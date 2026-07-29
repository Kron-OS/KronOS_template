"""Unit tests for ArtifactIngestService."""

from __future__ import annotations

import uuid

import pytest

from src.adapter.repository.artifact_repository import InMemoryArtifactRepository
from src.application.artifact_ingest import _MAX_CONTENT_BYTES, ArtifactIngestService
from src.application.audit_log import AuditLogService
from src.domain.audit import AuditEventType
from src.exceptions import StorageError, ValidationError
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_structured_artifact, make_tenant_context


async def _artifacts(*items):  # type: ignore[no-untyped-def]
    for item in items:
        yield item


class TestArtifactIngestService:
    def setup_method(self) -> None:
        self.repo = InMemoryArtifactRepository()
        self.audit_repo = InMemoryAuditLogRepository()
        self.audit = AuditLogService(self.audit_repo)
        self.svc = ArtifactIngestService(repository=self.repo, audit_log=self.audit)
        self.tenant = make_tenant_context()
        self.evidence_id = uuid.uuid4()

    async def test_returns_correct_count(self) -> None:
        artifacts = [make_structured_artifact(evidence_id=self.evidence_id) for _ in range(3)]
        count = await self.svc.ingest_artifacts(
            _artifacts(*artifacts), self.tenant, self.evidence_id
        )
        assert count == 3

    async def test_zero_artifacts_is_a_true_noop(self) -> None:
        # The default extract_artifacts() yields nothing for every existing
        # parser -- this must not add audit-log noise to every single parse.
        count = await self.svc.ingest_artifacts(_artifacts(), self.tenant, self.evidence_id)
        assert count == 0
        assert self.audit_repo._events == []

    async def test_persists_to_repository(self) -> None:
        artifact = make_structured_artifact(evidence_id=self.evidence_id, org_id=self.tenant.org_id)
        await self.svc.ingest_artifacts(_artifacts(artifact), self.tenant, self.evidence_id)
        stored = await self.repo.list_by_evidence(self.evidence_id, self.tenant.org_id)
        assert len(stored) == 1
        assert stored[0].kind == artifact.kind

    async def test_logs_artifact_ingest_started_and_completed(self) -> None:
        artifact = make_structured_artifact(evidence_id=self.evidence_id)
        await self.svc.ingest_artifacts(_artifacts(artifact), self.tenant, self.evidence_id)
        event_types = [e.event_type for e in self.audit_repo._events]
        assert AuditEventType.ARTIFACT_INGEST_STARTED in event_types
        assert AuditEventType.ARTIFACT_INGEST_COMPLETED in event_types

    async def test_completed_event_has_artifact_count(self) -> None:
        artifacts = [make_structured_artifact(evidence_id=self.evidence_id) for _ in range(4)]
        await self.svc.ingest_artifacts(_artifacts(*artifacts), self.tenant, self.evidence_id)
        completed = next(
            e
            for e in self.audit_repo._events
            if e.event_type == AuditEventType.ARTIFACT_INGEST_COMPLETED
        )
        assert completed.details["artifact_count"] == 4

    async def test_rejects_oversized_content(self) -> None:
        huge = make_structured_artifact(
            evidence_id=self.evidence_id,
            content={"blob": "x" * (_MAX_CONTENT_BYTES + 1)},
        )
        with pytest.raises(ValidationError, match="exceeds maximum size"):
            await self.svc.ingest_artifacts(_artifacts(huge), self.tenant, self.evidence_id)

    async def test_oversized_content_logs_artifact_ingest_failed(self) -> None:
        huge = make_structured_artifact(
            evidence_id=self.evidence_id,
            content={"blob": "x" * (_MAX_CONTENT_BYTES + 1)},
        )
        with pytest.raises(ValidationError):
            await self.svc.ingest_artifacts(_artifacts(huge), self.tenant, self.evidence_id)
        event_types = [e.event_type for e in self.audit_repo._events]
        assert AuditEventType.ARTIFACT_INGEST_FAILED in event_types
        assert AuditEventType.ARTIFACT_INGEST_COMPLETED not in event_types

    async def test_repository_failure_raises_storage_error_and_logs_failed(self) -> None:
        class _BrokenRepo(InMemoryArtifactRepository):
            async def save(self, artifact):  # type: ignore[override]
                raise RuntimeError("db down")

        broken_svc = ArtifactIngestService(repository=_BrokenRepo(), audit_log=self.audit)
        artifact = make_structured_artifact(evidence_id=self.evidence_id)
        with pytest.raises(StorageError):
            await broken_svc.ingest_artifacts(_artifacts(artifact), self.tenant, self.evidence_id)
        event_types = [e.event_type for e in self.audit_repo._events]
        assert AuditEventType.ARTIFACT_INGEST_FAILED in event_types
