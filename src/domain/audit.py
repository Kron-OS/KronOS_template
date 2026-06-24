"""AuditEvent domain model and event-type catalogue."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AuditEventType(StrEnum):
    """Exhaustive catalogue of auditable events in the platform."""

    # Evidence lifecycle
    EVIDENCE_UPLOAD_REQUESTED = "evidence.upload_requested"
    EVIDENCE_UPLOAD_FINALIZED = "evidence.upload_finalized"
    EVIDENCE_SCAN_STARTED = "evidence.scan_started"
    EVIDENCE_SCAN_COMPLETED = "evidence.scan_completed"
    EVIDENCE_SCAN_FAILED = "evidence.scan_failed"
    EVIDENCE_HASH_COMPUTED = "evidence.hash_computed"
    EVIDENCE_HASH_MISMATCH = "evidence.hash_mismatch"
    EVIDENCE_PROMOTED = "evidence.promoted"
    EVIDENCE_DELETED = "evidence.deleted"
    EVIDENCE_ERROR = "evidence.error"

    # Parsing
    PARSE_STARTED = "parse.started"
    PARSE_COMPLETED = "parse.completed"
    PARSE_FAILED = "parse.failed"

    # Timeline ingestion
    INGEST_STARTED = "ingest.started"
    INGEST_COMPLETED = "ingest.completed"
    INGEST_FAILED = "ingest.failed"

    # Authentication & authorization
    AUTH_LOGIN = "auth.login"
    AUTH_LOGOUT = "auth.logout"
    AUTH_STEP_UP = "auth.step_up"
    AUTH_FAILED = "auth.failed"
    AUTHZ_DENIED = "authz.denied"

    # Case management
    CASE_CREATED = "case.created"
    CASE_UPDATED = "case.updated"
    CASE_DELETED = "case.deleted"

    # Audit integrity
    AUDIT_HASH_CHAIN_VERIFIED = "audit.hash_chain_verified"
    AUDIT_HASH_CHAIN_TAMPERED = "audit.hash_chain_tampered"

    # Generic
    SYSTEM_ERROR = "system.error"


class AuditEvent(BaseModel):
    """Single immutable audit record; forms a cryptographic chain via row_hash."""

    model_config = {"frozen": True}

    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    event_type: AuditEventType
    actor_user_id: uuid.UUID | None = None
    actor_username: str | None = None
    org_id: uuid.UUID | None = None
    case_id: uuid.UUID | None = None
    evidence_id: uuid.UUID | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    # Hash chain fields — populated by AuditLogService before persistence.
    sequence_number: int = 0
    prev_row_hash: str | None = None
    row_hash: str | None = None
