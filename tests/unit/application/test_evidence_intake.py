"""Unit tests for EvidenceIntakeService — full workflow with in-memory fakes."""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

import pytest

from src.application.evidence_intake import EvidenceIntakeService
from src.application.hashing import HashService
from src.application.scanning import NoOpScanner, ScanResult
from src.application.validation import default_validator_chain
from src.domain.audit import AuditEventType
from src.domain.evidence import EvidenceState
from src.exceptions import ValidationError
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository
from tests.fixtures.factories import make_tenant_context

# ---------------------------------------------------------------------------
# Sample forensic content
# ---------------------------------------------------------------------------

_EVTX_HEADER = b"ElfFile\x00" + b"\x00" * 1024
_JSON_CONTENT = b'{"Records": []}'  # CloudTrail stub
_EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_repo() -> InMemoryAuditLogRepository:
    return InMemoryAuditLogRepository()


@pytest.fixture
def evidence_repo() -> InMemoryEvidenceRepository:
    return InMemoryEvidenceRepository()


@pytest.fixture
def local_storage(tmp_path: Path):  # type: ignore[no-untyped-def]
    from src.adapter.storage.local import LocalEvidenceStorage

    return LocalEvidenceStorage(base_dir=tmp_path)


@pytest.fixture
def intake(audit_repo, evidence_repo, local_storage):  # type: ignore[no-untyped-def]
    from src.application.audit_log import AuditLogService

    return EvidenceIntakeService(
        evidence_repository=evidence_repo,
        storage=local_storage,
        audit_log=AuditLogService(audit_repo),
        validator=default_validator_chain(max_upload_bytes=100_000),
        scanner=NoOpScanner(),
        hash_service=HashService(),
        max_upload_bytes=100_000,
    )


@pytest.fixture
def tenant():  # type: ignore[no-untyped-def]
    return make_tenant_context()


# ---------------------------------------------------------------------------
# Helper to simulate a client upload
# ---------------------------------------------------------------------------


def _simulate_upload(local_storage, object_key: str, data: bytes) -> None:
    """Write bytes directly to the local quarantine (simulates client PUT)."""
    local_storage.write_quarantine(object_key, data)


# ---------------------------------------------------------------------------
# Tests: request_upload
# ---------------------------------------------------------------------------


class TestRequestUpload:
    @pytest.mark.asyncio
    async def test_creates_uploading_evidence(self, intake, evidence_repo, tenant) -> None:
        evidence, presigned = await intake.request_upload(
            filename="system.evtx",
            content_type="application/octet-stream",
            size_bytes=len(_EVTX_HEADER),
            case_id=uuid.uuid4(),
            tenant=tenant,
        )
        assert evidence.state == EvidenceState.UPLOADING
        assert evidence.evidence_id in evidence_repo._store

    @pytest.mark.asyncio
    async def test_returns_presigned_url(self, intake, tenant) -> None:
        _, presigned = await intake.request_upload(
            filename="system.evtx",
            content_type="application/octet-stream",
            size_bytes=1024,
            case_id=uuid.uuid4(),
            tenant=tenant,
        )
        assert presigned.url
        assert presigned.object_key

    @pytest.mark.asyncio
    async def test_audit_event_logged(self, intake, audit_repo, tenant) -> None:
        await intake.request_upload(
            filename="system.evtx",
            content_type="application/octet-stream",
            size_bytes=1024,
            case_id=uuid.uuid4(),
            tenant=tenant,
        )
        types = [e.event_type for e in audit_repo.events]
        assert AuditEventType.EVIDENCE_UPLOAD_REQUESTED in types

    @pytest.mark.asyncio
    async def test_evidence_org_matches_tenant(self, intake, evidence_repo, tenant) -> None:
        evidence, _ = await intake.request_upload(
            filename="test.json",
            content_type="application/json",
            size_bytes=16,
            case_id=uuid.uuid4(),
            tenant=tenant,
        )
        assert evidence.metadata.org_id == tenant.org_id


# ---------------------------------------------------------------------------
# Tests: finalize_upload — happy path
# ---------------------------------------------------------------------------


class TestFinalizeUploadHappyPath:
    @pytest.mark.asyncio
    async def test_full_flow_reaches_received(self, intake, local_storage, tenant) -> None:
        evidence, presigned = await intake.request_upload(
            filename="cloudtrail.json",
            content_type="application/json",
            size_bytes=len(_JSON_CONTENT),
            case_id=uuid.uuid4(),
            tenant=tenant,
        )
        _simulate_upload(local_storage, presigned.object_key, _JSON_CONTENT)

        result = await intake.finalize_upload(
            evidence_id=evidence.evidence_id,
            client_sha256=_sha256(_JSON_CONTENT),
            tenant=tenant,
        )
        assert result.state == EvidenceState.RECEIVED

    @pytest.mark.asyncio
    async def test_sha256_stored_on_evidence(self, intake, local_storage, tenant) -> None:
        evidence, presigned = await intake.request_upload(
            filename="cloudtrail.json",
            content_type="application/json",
            size_bytes=len(_JSON_CONTENT),
            case_id=uuid.uuid4(),
            tenant=tenant,
        )
        _simulate_upload(local_storage, presigned.object_key, _JSON_CONTENT)

        result = await intake.finalize_upload(
            evidence_id=evidence.evidence_id,
            client_sha256=_sha256(_JSON_CONTENT),
            tenant=tenant,
        )
        assert result.sha256 == _sha256(_JSON_CONTENT)
        assert result.md5 is not None

    @pytest.mark.asyncio
    async def test_at_least_5_audit_events(self, intake, audit_repo, local_storage, tenant) -> None:
        evidence, presigned = await intake.request_upload(
            filename="cloudtrail.json",
            content_type="application/json",
            size_bytes=len(_JSON_CONTENT),
            case_id=uuid.uuid4(),
            tenant=tenant,
        )
        _simulate_upload(local_storage, presigned.object_key, _JSON_CONTENT)
        await intake.finalize_upload(
            evidence_id=evidence.evidence_id,
            client_sha256=_sha256(_JSON_CONTENT),
            tenant=tenant,
        )
        evidence_events = [e for e in audit_repo.events if e.evidence_id == evidence.evidence_id]
        assert len(evidence_events) >= 5

    @pytest.mark.asyncio
    async def test_evtx_file_accepted(self, intake, local_storage, tenant) -> None:
        evidence, presigned = await intake.request_upload(
            filename="system.evtx",
            content_type="application/octet-stream",
            size_bytes=len(_EVTX_HEADER),
            case_id=uuid.uuid4(),
            tenant=tenant,
        )
        _simulate_upload(local_storage, presigned.object_key, _EVTX_HEADER)
        result = await intake.finalize_upload(
            evidence_id=evidence.evidence_id,
            client_sha256=_sha256(_EVTX_HEADER),
            tenant=tenant,
        )
        assert result.state == EvidenceState.RECEIVED

    @pytest.mark.asyncio
    async def test_quarantine_key_cleared_after_promotion(
        self, intake, local_storage, tenant
    ) -> None:
        evidence, presigned = await intake.request_upload(
            filename="cloudtrail.json",
            content_type="application/json",
            size_bytes=len(_JSON_CONTENT),
            case_id=uuid.uuid4(),
            tenant=tenant,
        )
        _simulate_upload(local_storage, presigned.object_key, _JSON_CONTENT)
        result = await intake.finalize_upload(
            evidence_id=evidence.evidence_id,
            client_sha256=_sha256(_JSON_CONTENT),
            tenant=tenant,
        )
        assert result.minio_quarantine_key is None
        assert result.minio_evidence_key is not None


# ---------------------------------------------------------------------------
# Tests: finalize_upload — error paths
# ---------------------------------------------------------------------------


class TestFinalizeUploadErrors:
    @pytest.mark.asyncio
    async def test_hash_mismatch_sets_error_state(self, intake, local_storage, tenant) -> None:
        evidence, presigned = await intake.request_upload(
            filename="cloudtrail.json",
            content_type="application/json",
            size_bytes=len(_JSON_CONTENT),
            case_id=uuid.uuid4(),
            tenant=tenant,
        )
        _simulate_upload(local_storage, presigned.object_key, _JSON_CONTENT)

        with pytest.raises(ValidationError, match="mismatch"):
            await intake.finalize_upload(
                evidence_id=evidence.evidence_id,
                client_sha256="a" * 64,  # wrong hash
                tenant=tenant,
            )

    @pytest.mark.asyncio
    async def test_hash_mismatch_logs_event(
        self, intake, audit_repo, local_storage, tenant
    ) -> None:
        evidence, presigned = await intake.request_upload(
            filename="cloudtrail.json",
            content_type="application/json",
            size_bytes=len(_JSON_CONTENT),
            case_id=uuid.uuid4(),
            tenant=tenant,
        )
        _simulate_upload(local_storage, presigned.object_key, _JSON_CONTENT)

        with pytest.raises(ValidationError):
            await intake.finalize_upload(
                evidence_id=evidence.evidence_id,
                client_sha256="b" * 64,
                tenant=tenant,
            )
        types = [e.event_type for e in audit_repo.events]
        assert AuditEventType.EVIDENCE_HASH_MISMATCH in types

    @pytest.mark.asyncio
    async def test_invalid_magic_bytes_rejected(self, intake, local_storage, tenant) -> None:
        bad_data = b"\xff\xfe\x00\x01" * 500  # unknown binary
        evidence, presigned = await intake.request_upload(
            filename="trojan.evtx",  # extension OK, content not
            content_type="application/octet-stream",
            size_bytes=len(bad_data),
            case_id=uuid.uuid4(),
            tenant=tenant,
        )
        _simulate_upload(local_storage, presigned.object_key, bad_data)

        with pytest.raises(ValidationError, match="magic bytes"):
            await intake.finalize_upload(
                evidence_id=evidence.evidence_id,
                client_sha256=_sha256(bad_data),
                tenant=tenant,
            )

    @pytest.mark.asyncio
    async def test_infected_file_sets_error(
        self, intake, audit_repo, local_storage, evidence_repo, tenant
    ) -> None:
        """Scan failure (mock infected scanner) transitions evidence to ERROR."""
        from src.application.audit_log import AuditLogService

        class InfectedScanner(NoOpScanner):
            async def scan_stream(self, stream):  # type: ignore[override]
                async for _ in stream:
                    pass
                return ScanResult(is_clean=False, threat_name="Win.Eicar-Test")

        infected_intake = EvidenceIntakeService(
            evidence_repository=evidence_repo,
            storage=local_storage,
            audit_log=AuditLogService(audit_repo),
            validator=default_validator_chain(100_000),
            scanner=InfectedScanner(),
            hash_service=HashService(),
            max_upload_bytes=100_000,
        )
        evidence, presigned = await infected_intake.request_upload(
            filename="cloudtrail.json",
            content_type="application/json",
            size_bytes=len(_JSON_CONTENT),
            case_id=uuid.uuid4(),
            tenant=tenant,
        )
        _simulate_upload(local_storage, presigned.object_key, _JSON_CONTENT)

        with pytest.raises(ValidationError, match="infected"):
            await infected_intake.finalize_upload(
                evidence_id=evidence.evidence_id,
                client_sha256=_sha256(_JSON_CONTENT),
                tenant=tenant,
            )
        stored = await evidence_repo.get_by_id(evidence.evidence_id, tenant.org_id)
        assert stored is not None
        assert stored.state == EvidenceState.ERROR
        types = [e.event_type for e in audit_repo.events]
        assert AuditEventType.EVIDENCE_SCAN_FAILED in types

    @pytest.mark.asyncio
    async def test_finalize_wrong_org_returns_none(self, intake, local_storage, tenant) -> None:
        evidence, presigned = await intake.request_upload(
            filename="cloudtrail.json",
            content_type="application/json",
            size_bytes=len(_JSON_CONTENT),
            case_id=uuid.uuid4(),
            tenant=tenant,
        )
        other_tenant = make_tenant_context()  # different org_id
        with pytest.raises(ValidationError, match="not found"):
            await intake.finalize_upload(
                evidence_id=evidence.evidence_id,
                client_sha256=_sha256(_JSON_CONTENT),
                tenant=other_tenant,
            )

    @pytest.mark.asyncio
    async def test_blocked_extension_rejected(self, intake, local_storage, tenant) -> None:
        evidence, presigned = await intake.request_upload(
            filename="malware.exe",
            content_type="application/octet-stream",
            size_bytes=100,
            case_id=uuid.uuid4(),
            tenant=tenant,
        )
        _simulate_upload(local_storage, presigned.object_key, b"\x4d\x5a" + b"\x00" * 98)

        with pytest.raises(ValidationError, match="extension"):
            await intake.finalize_upload(
                evidence_id=evidence.evidence_id,
                client_sha256=_sha256(b"\x4d\x5a" + b"\x00" * 98),
                tenant=tenant,
            )
