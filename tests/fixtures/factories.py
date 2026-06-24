"""Pydantic-based object factories for tests — no mocks of domain objects."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from src.domain.audit import AuditEvent, AuditEventType
from src.domain.case import Case, CaseMetadata, CaseStatus
from src.domain.evidence import Evidence, EvidenceMetadata, EvidenceState
from src.domain.timeline import KronosProvenance, TimelineRecord
from src.domain.user import Role, TenantContext, User


def make_org_id() -> uuid.UUID:
    return uuid.uuid4()


def make_user(
    org_id: uuid.UUID | None = None,
    roles: set[Role] | None = None,
) -> User:
    oid = org_id or uuid.uuid4()
    return User(
        user_id=uuid.uuid4(),
        username="testuser",
        email="test@example.com",
        org_id=oid,
        org_alias="testorg",
        roles=frozenset(roles or {Role.ANALYST}),
    )


def make_tenant_context(
    org_id: uuid.UUID | None = None,
    roles: set[Role] | None = None,
) -> TenantContext:
    oid = org_id or uuid.uuid4()
    return TenantContext(
        org_id=oid,
        org_alias="testorg",
        user_id=uuid.uuid4(),
        username="testuser",
        roles=frozenset(roles or {Role.ANALYST}),
        correlation_id=str(uuid.uuid4()),
    )


def make_evidence_metadata(
    org_id: uuid.UUID | None = None,
    case_id: uuid.UUID | None = None,
) -> EvidenceMetadata:
    return EvidenceMetadata(
        original_filename="test.evtx",
        content_type="application/octet-stream",
        size_bytes=1024,
        uploader_user_id=uuid.uuid4(),
        case_id=case_id or uuid.uuid4(),
        org_id=org_id or uuid.uuid4(),
        org_alias="testorg",
    )


def make_evidence(
    state: EvidenceState = EvidenceState.UPLOADING,
    org_id: uuid.UUID | None = None,
) -> Evidence:
    return Evidence(
        metadata=make_evidence_metadata(org_id=org_id),
        state=state,
    )


def make_audit_event(
    event_type: AuditEventType = AuditEventType.EVIDENCE_UPLOAD_REQUESTED,
    org_id: uuid.UUID | None = None,
    sequence_number: int = 1,
    prev_row_hash: str | None = None,
    row_hash: str | None = None,
) -> AuditEvent:
    return AuditEvent(
        event_type=event_type,
        org_id=org_id or uuid.uuid4(),
        actor_user_id=uuid.uuid4(),
        actor_username="testuser",
        sequence_number=sequence_number,
        prev_row_hash=prev_row_hash,
        row_hash=row_hash,
    )


def make_case(
    org_id: uuid.UUID | None = None,
    status: CaseStatus = CaseStatus.OPEN,
) -> Case:
    oid = org_id or uuid.uuid4()
    return Case(
        org_id=oid,
        org_alias="testorg",
        owner_user_id=uuid.uuid4(),
        metadata=CaseMetadata(
            title="Test Case",
            description="Unit-test case",
            reference_number="CASE-001",
        ),
        status=status,
    )


def make_timeline_record(
    evidence_id: uuid.UUID | None = None,
    record_index: int = 0,
) -> TimelineRecord:
    eid = evidence_id or uuid.uuid4()
    return TimelineRecord(
        **{
            "@timestamp": datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            "message": "Test event",
            "event.kind": "event",
            "event.category": ["authentication"],
            "event.type": ["start"],
        },
        kronos=KronosProvenance(
            evidence_id=eid,
            case_id=uuid.uuid4(),
            org_id=uuid.uuid4(),
            sha256="a" * 64,
            parser="evtx-rs",
            parser_version="1.0.0",
            record_index=record_index,
            ingest_timestamp=datetime.now(UTC),
        ),
    )
