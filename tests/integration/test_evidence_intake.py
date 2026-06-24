"""Integration tests for the full evidence intake workflow.

Requires: Docker (Postgres 16 + MinIO containers via testcontainers).
Run with:  pytest tests/integration/ -v -m integration
"""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

_JSON_CONTENT = b'{"Records": [{"eventTime": "2024-01-01T00:00:00Z"}]}'
_EVTX_HEADER = b"ElfFile\x00" + b"\x00" * 2048


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_tenant(org_id: uuid.UUID | None = None) -> object:
    from tests.fixtures.factories import make_tenant_context

    if org_id:
        from src.domain.user import Role, TenantContext

        return TenantContext(
            org_id=org_id,
            org_alias="testorg",
            user_id=uuid.uuid4(),
            username="testuser",
            roles=frozenset({Role.ANALYST}),
            correlation_id=str(uuid.uuid4()),
        )
    return make_tenant_context()


def _make_intake(postgres_engine, local_storage):  # type: ignore[no-untyped-def]
    from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository
    from src.adapter.repository.postgres_evidence import PostgresEvidenceRepository
    from src.application.audit_log import AuditLogService
    from src.application.evidence_intake import EvidenceIntakeService
    from src.application.hashing import HashService
    from src.application.scanning import NoOpScanner
    from src.application.validation import default_validator_chain

    evidence_repo = PostgresEvidenceRepository(postgres_engine)
    audit_repo = PostgresAuditLogRepository(postgres_engine)
    audit_svc = AuditLogService(audit_repo)

    return EvidenceIntakeService(
        evidence_repository=evidence_repo,
        storage=local_storage,
        audit_log=audit_svc,
        validator=default_validator_chain(10_000_000),
        scanner=NoOpScanner(),
        hash_service=HashService(),
        max_upload_bytes=10_000_000,
    )


@pytest.fixture
def local_storage(tmp_path: Path):  # type: ignore[no-untyped-def]
    from src.adapter.storage.local import LocalEvidenceStorage

    return LocalEvidenceStorage(base_dir=tmp_path)


@pytest.mark.asyncio
async def test_full_upload_flow_postgres(postgres_engine, local_storage) -> None:
    """Complete upload → finalize → RECEIVED with real Postgres."""
    intake = _make_intake(postgres_engine, local_storage)
    tenant = _make_tenant()

    evidence, presigned = await intake.request_upload(
        filename="cloudtrail.json",
        content_type="application/json",
        size_bytes=len(_JSON_CONTENT),
        case_id=uuid.uuid4(),
        tenant=tenant,
    )
    local_storage.write_quarantine(presigned.object_key, _JSON_CONTENT)

    result = await intake.finalize_upload(
        evidence_id=evidence.evidence_id,
        client_sha256=_sha256(_JSON_CONTENT),
        tenant=tenant,
    )
    assert result.state.value == "RECEIVED"
    assert result.sha256 == _sha256(_JSON_CONTENT)


@pytest.mark.asyncio
async def test_evidence_persisted_in_postgres(postgres_engine, local_storage) -> None:
    """Evidence created in request_upload is readable from Postgres."""
    from src.adapter.repository.postgres_evidence import PostgresEvidenceRepository

    intake = _make_intake(postgres_engine, local_storage)
    tenant = _make_tenant()

    evidence, _ = await intake.request_upload(
        filename="cloudtrail.json",
        content_type="application/json",
        size_bytes=len(_JSON_CONTENT),
        case_id=uuid.uuid4(),
        tenant=tenant,
    )
    repo = PostgresEvidenceRepository(postgres_engine)
    stored = await repo.get_by_id(evidence.evidence_id, tenant.org_id)
    assert stored is not None
    assert stored.evidence_id == evidence.evidence_id


@pytest.mark.asyncio
async def test_audit_events_persisted(postgres_engine, local_storage) -> None:
    """After finalize, at least 5 audit events exist for the evidence."""
    from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository

    intake = _make_intake(postgres_engine, local_storage)
    tenant = _make_tenant()

    evidence, presigned = await intake.request_upload(
        filename="cloudtrail.json",
        content_type="application/json",
        size_bytes=len(_JSON_CONTENT),
        case_id=uuid.uuid4(),
        tenant=tenant,
    )
    local_storage.write_quarantine(presigned.object_key, _JSON_CONTENT)
    await intake.finalize_upload(
        evidence_id=evidence.evidence_id,
        client_sha256=_sha256(_JSON_CONTENT),
        tenant=tenant,
    )

    audit_repo = PostgresAuditLogRepository(postgres_engine)
    events = [e async for e in audit_repo.stream_by_evidence(evidence.evidence_id)]
    assert len(events) >= 5


@pytest.mark.asyncio
async def test_hash_chain_intact_after_upload(postgres_engine, local_storage) -> None:
    """Audit hash chain is unbroken after a complete upload cycle."""
    from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository
    from src.application.audit_log import AuditLogService

    intake = _make_intake(postgres_engine, local_storage)
    tenant = _make_tenant()

    evidence, presigned = await intake.request_upload(
        filename="cloudtrail.json",
        content_type="application/json",
        size_bytes=len(_JSON_CONTENT),
        case_id=uuid.uuid4(),
        tenant=tenant,
    )
    local_storage.write_quarantine(presigned.object_key, _JSON_CONTENT)
    await intake.finalize_upload(
        evidence_id=evidence.evidence_id,
        client_sha256=_sha256(_JSON_CONTENT),
        tenant=tenant,
    )

    audit_repo = PostgresAuditLogRepository(postgres_engine)
    audit_svc = AuditLogService(audit_repo)
    ok, detail = await audit_svc.verify_chain(tenant.org_id)
    assert ok, f"Hash chain broken: {detail}"


@pytest.mark.asyncio
async def test_hash_mismatch_sets_error_state_in_postgres(postgres_engine, local_storage) -> None:
    from src.adapter.repository.postgres_evidence import PostgresEvidenceRepository
    from src.domain.evidence import EvidenceState
    from src.exceptions import ValidationError

    intake = _make_intake(postgres_engine, local_storage)
    tenant = _make_tenant()

    evidence, presigned = await intake.request_upload(
        filename="cloudtrail.json",
        content_type="application/json",
        size_bytes=len(_JSON_CONTENT),
        case_id=uuid.uuid4(),
        tenant=tenant,
    )
    local_storage.write_quarantine(presigned.object_key, _JSON_CONTENT)

    with pytest.raises(ValidationError):
        await intake.finalize_upload(
            evidence_id=evidence.evidence_id,
            client_sha256="f" * 64,
            tenant=tenant,
        )

    repo = PostgresEvidenceRepository(postgres_engine)
    stored = await repo.get_by_id(evidence.evidence_id, tenant.org_id)
    assert stored is not None
    assert stored.state == EvidenceState.ERROR


@pytest.mark.asyncio
async def test_concurrent_uploads_different_cases(postgres_engine, local_storage) -> None:
    """Two concurrent uploads to different cases don't collide."""
    import asyncio

    intake = _make_intake(postgres_engine, local_storage)
    tenant1 = _make_tenant()
    tenant2 = _make_tenant()

    async def upload(tenant, content: bytes, filename: str):  # type: ignore[no-untyped-def]
        ev, presigned = await intake.request_upload(
            filename=filename,
            content_type="application/json",
            size_bytes=len(content),
            case_id=uuid.uuid4(),
            tenant=tenant,
        )
        local_storage.write_quarantine(presigned.object_key, content)
        return await intake.finalize_upload(
            evidence_id=ev.evidence_id,
            client_sha256=_sha256(content),
            tenant=tenant,
        )

    c1 = b'{"Records": [1]}'
    c2 = b'{"Records": [2]}'
    r1, r2 = await asyncio.gather(
        upload(tenant1, c1, "file1.json"),
        upload(tenant2, c2, "file2.json"),
    )
    assert r1.sha256 == _sha256(c1)
    assert r2.sha256 == _sha256(c2)


@pytest.mark.asyncio
async def test_org_isolation_in_postgres(postgres_engine, local_storage) -> None:
    """An org cannot read another org's evidence."""
    from src.adapter.repository.postgres_evidence import PostgresEvidenceRepository

    intake = _make_intake(postgres_engine, local_storage)
    tenant1 = _make_tenant()
    tenant2 = _make_tenant()

    evidence, _ = await intake.request_upload(
        filename="secret.json",
        content_type="application/json",
        size_bytes=len(_JSON_CONTENT),
        case_id=uuid.uuid4(),
        tenant=tenant1,
    )

    repo = PostgresEvidenceRepository(postgres_engine)
    result = await repo.get_by_id(evidence.evidence_id, tenant2.org_id)
    assert result is None


@pytest.mark.asyncio
async def test_evtx_accepted_end_to_end(postgres_engine, local_storage) -> None:
    intake = _make_intake(postgres_engine, local_storage)
    tenant = _make_tenant()

    evidence, presigned = await intake.request_upload(
        filename="system.evtx",
        content_type="application/octet-stream",
        size_bytes=len(_EVTX_HEADER),
        case_id=uuid.uuid4(),
        tenant=tenant,
    )
    local_storage.write_quarantine(presigned.object_key, _EVTX_HEADER)
    result = await intake.finalize_upload(
        evidence_id=evidence.evidence_id,
        client_sha256=_sha256(_EVTX_HEADER),
        tenant=tenant,
    )
    assert result.sha256 == _sha256(_EVTX_HEADER)


@pytest.mark.asyncio
async def test_stream_by_case_returns_evidence(postgres_engine, local_storage) -> None:
    from src.adapter.repository.postgres_evidence import PostgresEvidenceRepository

    intake = _make_intake(postgres_engine, local_storage)
    tenant = _make_tenant()
    case_id = uuid.uuid4()

    for i in range(3):
        content = f'{{"i": {i}}}'.encode()
        ev, presigned = await intake.request_upload(
            filename=f"file{i}.json",
            content_type="application/json",
            size_bytes=len(content),
            case_id=case_id,
            tenant=tenant,
        )
        local_storage.write_quarantine(presigned.object_key, content)
        await intake.finalize_upload(
            evidence_id=ev.evidence_id,
            client_sha256=_sha256(content),
            tenant=tenant,
        )

    repo = PostgresEvidenceRepository(postgres_engine)
    items = [e async for e in repo.stream_by_case(case_id, tenant.org_id)]
    assert len(items) == 3
