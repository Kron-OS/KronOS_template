"""Unit tests for the DI container (dependencies.py)."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from src.adapter.storage.storage import EvidenceStorage, PresignedUploadResponse
from src.domain.evidence import Evidence
from src.external.dependencies import (
    configure_dependencies,
    get_audit_log_repository,
    get_evidence_repository,
    get_evidence_storage,
    reset_dependencies,
)
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository


class _StubStorage(EvidenceStorage):
    async def request_presigned_upload(
        self, evidence: Evidence, expires_in_seconds: int = 3600
    ) -> PresignedUploadResponse:
        return PresignedUploadResponse("http://stub", "key", expires_in_seconds)

    async def stream_object(  # type: ignore[override]
        self,
        object_key: str,
        chunk_size: int = 65536,
        *,
        bucket: str = "quarantine",
    ) -> AsyncIterator[bytes]:
        async def _gen() -> AsyncIterator[bytes]:
            yield b"stub"

        return _gen()

    async def promote_to_evidence_bucket(self, quarantine_key: str, evidence: Evidence) -> str:
        return "promoted/key"

    async def delete_from_quarantine(self, quarantine_key: str) -> None:
        pass

    async def object_exists(self, object_key: str, *, bucket: str = "quarantine") -> bool:
        return True


class TestDIContainer:
    def setup_method(self) -> None:
        reset_dependencies()

    def teardown_method(self) -> None:
        reset_dependencies()

    def test_unconfigured_audit_repo_raises(self) -> None:
        with pytest.raises(RuntimeError, match="AuditLogRepository is not configured"):
            get_audit_log_repository()

    def test_unconfigured_evidence_repo_raises(self) -> None:
        with pytest.raises(RuntimeError, match="EvidenceRepository is not configured"):
            get_evidence_repository()

    def test_unconfigured_storage_raises(self) -> None:
        with pytest.raises(RuntimeError, match="EvidenceStorage is not configured"):
            get_evidence_storage()

    def test_configure_and_retrieve_audit_repo(self) -> None:
        repo = InMemoryAuditLogRepository()
        configure_dependencies(
            audit_log_repository=repo,
            evidence_repository=InMemoryEvidenceRepository(),
            evidence_storage=_StubStorage(),
        )
        retrieved = get_audit_log_repository()
        assert retrieved is repo

    def test_configure_and_retrieve_evidence_repo(self) -> None:
        ev_repo = InMemoryEvidenceRepository()
        configure_dependencies(
            audit_log_repository=InMemoryAuditLogRepository(),
            evidence_repository=ev_repo,
            evidence_storage=_StubStorage(),
        )
        retrieved = get_evidence_repository()
        assert retrieved is ev_repo

    def test_configure_and_retrieve_storage(self) -> None:
        storage = _StubStorage()
        configure_dependencies(
            audit_log_repository=InMemoryAuditLogRepository(),
            evidence_repository=InMemoryEvidenceRepository(),
            evidence_storage=storage,
        )
        retrieved = get_evidence_storage()
        assert retrieved is storage

    def test_reset_clears_bindings(self) -> None:
        configure_dependencies(
            audit_log_repository=InMemoryAuditLogRepository(),
            evidence_repository=InMemoryEvidenceRepository(),
            evidence_storage=_StubStorage(),
        )
        reset_dependencies()
        with pytest.raises(RuntimeError):
            get_audit_log_repository()


class TestPresignedUploadResponse:
    def test_fields(self) -> None:
        resp = PresignedUploadResponse("http://example.com/upload", "key/path", 3600)
        assert resp.url == "http://example.com/upload"
        assert resp.object_key == "key/path"
        assert resp.expires_in_seconds == 3600
