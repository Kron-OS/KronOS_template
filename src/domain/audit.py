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
    EVIDENCE_DELETE_DENIED = "evidence.delete_denied"
    EVIDENCE_ERROR = "evidence.error"
    EVIDENCE_LEGAL_HOLD_SET = "evidence.legal_hold_set"
    EVIDENCE_LEGAL_HOLD_CLEARED = "evidence.legal_hold_cleared"

    # Parsing
    PARSE_STARTED = "parse.started"
    PARSE_COMPLETED = "parse.completed"
    PARSE_FAILED = "parse.failed"

    # Timeline ingestion
    INGEST_STARTED = "ingest.started"
    INGEST_COMPLETED = "ingest.completed"
    INGEST_FAILED = "ingest.failed"

    # Structured (non-timeline) artifact ingestion -- see
    # reviews/Data_Source_Module_System.md
    ARTIFACT_INGEST_STARTED = "artifact_ingest.started"
    ARTIFACT_INGEST_COMPLETED = "artifact_ingest.completed"
    ARTIFACT_INGEST_FAILED = "artifact_ingest.failed"

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
    AUDIT_MERKLE_ANCHORED = "audit.merkle_anchored"

    # RFC 3161 timestamping
    EVIDENCE_TSA_ANCHORED = "evidence.tsa_anchored"

    # Batch sealing (roadmap M3/D3) -- continuous-stream chain-of-custody;
    # see src/application/batch_sealing.py.
    BATCH_SEALED = "batch.sealed"
    BATCH_SEAL_FAILED = "batch.seal_failed"
    BATCH_SEAL_WATERMARK_GAP_DETECTED = "batch.seal_watermark_gap_detected"

    # Detection / triage (roadmap M2/C4) -- SA findings mirrored into
    # KronOS's own audited Detection entity; see src/domain/detection.py.
    DETECTION_SYNCED = "detection.synced"
    DETECTION_SYNC_FAILED = "detection.sync_failed"
    DETECTION_TRIAGE_TRANSITIONED = "detection.triage_transitioned"
    DETECTION_TRIAGE_TRANSITION_FAILED = "detection.triage_transition_failed"

    # Rule-pack lifecycle (roadmap M2/C3) -- versioned custom-rule packs;
    # see src/application/rule_pack_service.py.
    RULE_PACK_VERSION_CREATED = "rule_pack.version_created"
    RULE_PACK_VERSION_CREATE_FAILED = "rule_pack.version_create_failed"
    RULE_PACK_SIGNATURE_REJECTED = "rule_pack.signature_rejected"
    RULE_PACK_RULE_PUBLISHED = "rule_pack.rule_published"
    RULE_PACK_RULE_PUBLISH_FAILED = "rule_pack.rule_publish_failed"

    # Org administration
    ORG_USER_INVITED = "org.user_invited"
    ORG_USER_ROLE_CHANGED = "org.user_role_changed"
    ORG_USER_REMOVED = "org.user_removed"
    ORG_SETTINGS_UPDATED = "org.settings_updated"

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
