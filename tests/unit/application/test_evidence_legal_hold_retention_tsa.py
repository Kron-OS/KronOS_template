"""Unit tests for EVID-1 (retention/legal-hold gated soft-delete), EVID-2
(legal hold), and EVID-3/AUDIT-11 (RFC 3161 timestamping) in
EvidenceIntakeService.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from src.application.audit_log import AuditLogService
from src.application.evidence_intake import EvidenceIntakeService
from src.application.hashing import HashService
from src.application.scanning import NoOpScanner
from src.application.validation import default_validator_chain
from src.domain.audit import AuditEventType
from src.domain.evidence import EvidenceState
from src.domain.user import Role
from src.exceptions import AuthorizationError, EvidenceStateError, ValidationError
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository
from tests.fixtures.factories import make_evidence, make_tenant_context

_JSON_CONTENT = b'{"Records": []}'


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class _FakeTimestampService:
    """Stub RFC3161TimestampService: records calls, returns a fixed token."""

    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[bytes] = []
        self._fail = fail

    async def timestamp(self, digest: bytes) -> bytes:
        self.calls.append(digest)
        if self._fail:
            from src.exceptions import StorageError

            raise StorageError("TSA unreachable")
        return b"TOKEN:" + digest


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


def _make_intake(
    audit_repo: InMemoryAuditLogRepository,
    evidence_repo: InMemoryEvidenceRepository,
    local_storage,  # type: ignore[no-untyped-def]
    *,
    timestamp_service=None,  # type: ignore[no-untyped-def]
    default_retention_days: int = 365,
) -> EvidenceIntakeService:
    return EvidenceIntakeService(
        evidence_repository=evidence_repo,
        storage=local_storage,
        audit_log=AuditLogService(audit_repo),
        validator=default_validator_chain(max_upload_bytes=100_000),
        scanner=NoOpScanner(),
        hash_service=HashService(),
        max_upload_bytes=100_000,
        timestamp_service=timestamp_service,
        default_retention_days=default_retention_days,
    )


async def _upload_and_finalize(intake, local_storage, tenant, case_id=None):  # type: ignore[no-untyped-def]
    evidence, presigned = await intake.request_upload(
        filename="cloudtrail.json",
        content_type="application/json",
        size_bytes=len(_JSON_CONTENT),
        case_id=case_id or uuid.uuid4(),
        tenant=tenant,
    )
    local_storage.write_quarantine(presigned.object_key, _JSON_CONTENT)
    return await intake.finalize_upload(
        evidence_id=evidence.evidence_id,
        client_sha256=_sha256(_JSON_CONTENT),
        tenant=tenant,
    )


# ---------------------------------------------------------------------------
# EVID-3 / AUDIT-11: RFC 3161 timestamping wired into intake
# ---------------------------------------------------------------------------


class TestRFC3161Timestamping:
    @pytest.mark.asyncio
    async def test_hash_verified_transition_anchors_timestamp(
        self, audit_repo, evidence_repo, local_storage
    ) -> None:
        tsa = _FakeTimestampService()
        intake = _make_intake(audit_repo, evidence_repo, local_storage, timestamp_service=tsa)
        tenant = make_tenant_context()

        evidence = await _upload_and_finalize(intake, local_storage, tenant)

        assert evidence.rfc3161_token == b"TOKEN:" + bytes.fromhex(evidence.sha256)
        assert len(tsa.calls) == 1
        types = [e.event_type for e in audit_repo.events]
        assert AuditEventType.EVIDENCE_TSA_ANCHORED in types

    @pytest.mark.asyncio
    async def test_no_timestamp_service_means_no_token(
        self, audit_repo, evidence_repo, local_storage
    ) -> None:
        intake = _make_intake(audit_repo, evidence_repo, local_storage, timestamp_service=None)
        tenant = make_tenant_context()

        evidence = await _upload_and_finalize(intake, local_storage, tenant)

        assert evidence.rfc3161_token is None
        types = [e.event_type for e in audit_repo.events]
        assert AuditEventType.EVIDENCE_TSA_ANCHORED not in types

    @pytest.mark.asyncio
    async def test_tsa_outage_does_not_block_intake(
        self, audit_repo, evidence_repo, local_storage
    ) -> None:
        """A TSA failure must not fail the upload — the file is already
        hashed and verified; timestamping is best-effort, not fabricated."""
        tsa = _FakeTimestampService(fail=True)
        intake = _make_intake(audit_repo, evidence_repo, local_storage, timestamp_service=tsa)
        tenant = make_tenant_context()

        evidence = await _upload_and_finalize(intake, local_storage, tenant)

        assert evidence.state == EvidenceState.RECEIVED
        assert evidence.rfc3161_token is None


# ---------------------------------------------------------------------------
# EVID-3: Object Lock retain-until set at promotion
# ---------------------------------------------------------------------------


class TestObjectLockAtPromotion:
    @pytest.mark.asyncio
    async def test_promotion_sets_object_lock_until(
        self, audit_repo, evidence_repo, local_storage
    ) -> None:
        intake = _make_intake(
            audit_repo, evidence_repo, local_storage, default_retention_days=30
        )
        tenant = make_tenant_context()
        before = datetime.now(UTC)

        evidence = await _upload_and_finalize(intake, local_storage, tenant)

        assert evidence.object_lock_until is not None
        expected_min = before + timedelta(days=30) - timedelta(minutes=1)
        expected_max = before + timedelta(days=30) + timedelta(minutes=1)
        assert expected_min <= evidence.object_lock_until <= expected_max


# ---------------------------------------------------------------------------
# EVID-2: Legal hold
# ---------------------------------------------------------------------------


class TestSetLegalHold:
    @pytest.mark.asyncio
    async def test_org_admin_can_set_and_clear_hold(
        self, audit_repo, evidence_repo, local_storage
    ) -> None:
        intake = _make_intake(audit_repo, evidence_repo, local_storage)
        tenant = make_tenant_context(roles={Role.ORG_ADMIN})
        evidence = await _upload_and_finalize(intake, local_storage, tenant)

        held = await intake.set_legal_hold(evidence.evidence_id, True, tenant)
        assert held.legal_hold is True
        assert local_storage.is_legal_hold_set(evidence.minio_evidence_key) is True

        cleared = await intake.set_legal_hold(evidence.evidence_id, False, tenant)
        assert cleared.legal_hold is False
        assert local_storage.is_legal_hold_set(evidence.minio_evidence_key) is False

        types = [e.event_type for e in audit_repo.events]
        assert AuditEventType.EVIDENCE_LEGAL_HOLD_SET in types
        assert AuditEventType.EVIDENCE_LEGAL_HOLD_CLEARED in types

    @pytest.mark.asyncio
    async def test_case_lead_can_set_hold(self, audit_repo, evidence_repo, local_storage) -> None:
        intake = _make_intake(audit_repo, evidence_repo, local_storage)
        tenant = make_tenant_context(roles={Role.CASE_LEAD})
        evidence = await _upload_and_finalize(intake, local_storage, tenant)

        held = await intake.set_legal_hold(evidence.evidence_id, True, tenant)
        assert held.legal_hold is True

    @pytest.mark.asyncio
    async def test_analyst_cannot_set_hold(self, audit_repo, evidence_repo, local_storage) -> None:
        intake = _make_intake(audit_repo, evidence_repo, local_storage)
        tenant = make_tenant_context(roles={Role.ANALYST})
        evidence = await _upload_and_finalize(intake, local_storage, tenant)

        with pytest.raises(AuthorizationError):
            await intake.set_legal_hold(evidence.evidence_id, True, tenant)

    @pytest.mark.asyncio
    async def test_cannot_hold_evidence_not_yet_promoted(
        self, audit_repo, evidence_repo, local_storage
    ) -> None:
        intake = _make_intake(audit_repo, evidence_repo, local_storage)
        tenant = make_tenant_context(roles={Role.ORG_ADMIN})
        evidence = make_evidence(state=EvidenceState.UPLOADING, org_id=tenant.org_id)
        await evidence_repo.save(evidence)

        with pytest.raises(ValidationError):
            await intake.set_legal_hold(evidence.evidence_id, True, tenant)

    @pytest.mark.asyncio
    async def test_hold_on_missing_evidence_raises(
        self, audit_repo, evidence_repo, local_storage
    ) -> None:
        intake = _make_intake(audit_repo, evidence_repo, local_storage)
        tenant = make_tenant_context(roles={Role.ORG_ADMIN})

        with pytest.raises(ValidationError):
            await intake.set_legal_hold(uuid.uuid4(), True, tenant)


# ---------------------------------------------------------------------------
# EVID-1: delete_evidence retention/legal-hold gate + soft-delete
# ---------------------------------------------------------------------------


class TestDeleteEvidenceRetentionGate:
    @pytest.mark.asyncio
    async def test_legal_hold_blocks_delete(
        self, audit_repo, evidence_repo, local_storage
    ) -> None:
        intake = _make_intake(audit_repo, evidence_repo, local_storage)
        tenant = make_tenant_context(roles={Role.ORG_ADMIN})
        evidence = await _upload_and_finalize(intake, local_storage, tenant)
        await intake.set_legal_hold(evidence.evidence_id, True, tenant)

        with pytest.raises(AuthorizationError, match="legal hold"):
            await intake.delete_evidence(evidence.evidence_id, tenant)

        stored = await evidence_repo.get_by_id(evidence.evidence_id, tenant.org_id)
        assert stored.state != EvidenceState.PURGED

    @pytest.mark.asyncio
    async def test_active_retention_blocks_delete(
        self, audit_repo, evidence_repo, local_storage
    ) -> None:
        intake = _make_intake(
            audit_repo, evidence_repo, local_storage, default_retention_days=365
        )
        tenant = make_tenant_context(roles={Role.ORG_ADMIN})
        evidence = await _upload_and_finalize(intake, local_storage, tenant)

        with pytest.raises(EvidenceStateError, match="retention"):
            await intake.delete_evidence(evidence.evidence_id, tenant)

    @pytest.mark.asyncio
    async def test_delete_after_retention_expiry_soft_deletes(
        self, audit_repo, evidence_repo, local_storage
    ) -> None:
        intake = _make_intake(audit_repo, evidence_repo, local_storage)
        tenant = make_tenant_context(roles={Role.ORG_ADMIN})
        evidence = await _upload_and_finalize(intake, local_storage, tenant)

        # Simulate the retention period having already elapsed.
        expired = evidence.with_object_lock_until(datetime.now(UTC) - timedelta(days=1))
        await evidence_repo.update(expired, expected_state=evidence.state)

        await intake.delete_evidence(evidence.evidence_id, tenant, step_up_verified=True)

        stored = await evidence_repo.get_by_id(evidence.evidence_id, tenant.org_id)
        assert stored is not None
        assert stored.state == EvidenceState.PURGED  # row survives — soft delete

        deleted_events = [e for e in audit_repo.events if e.event_type == AuditEventType.EVIDENCE_DELETED]
        assert len(deleted_events) == 1
        details = deleted_events[0].details
        assert details["sha256"] == evidence.sha256
        assert details["object_key"] == evidence.minio_evidence_key
        assert details["bucket"] is not None
        assert details["step_up_verified"] is True

    @pytest.mark.asyncio
    async def test_delete_denied_events_logged(
        self, audit_repo, evidence_repo, local_storage
    ) -> None:
        intake = _make_intake(audit_repo, evidence_repo, local_storage)
        tenant = make_tenant_context(roles={Role.ORG_ADMIN})
        evidence = await _upload_and_finalize(intake, local_storage, tenant)

        with pytest.raises(EvidenceStateError):
            await intake.delete_evidence(evidence.evidence_id, tenant)

        denied = [e for e in audit_repo.events if e.event_type == AuditEventType.EVIDENCE_DELETE_DENIED]
        assert len(denied) == 1
        assert denied[0].details["reason"] == "retention_period_active"
