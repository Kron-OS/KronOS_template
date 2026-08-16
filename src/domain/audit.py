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
    # Health signal, not evidence loss -- the pending segment is still fully
    # present and about to be picked up this very cycle; see
    # BatchSealingService._check_sealer_fall_behind's own docstring for why
    # this does NOT raise, unlike the watermark-gap case above.
    SEALER_FALL_BEHIND_DETECTED = "batch.sealer_fall_behind_detected"

    # Stream normalization dead-letter (roadmap M3/D5) -- one event within a
    # sealed batch that failed to normalize; see
    # src/application/stream_normalization.py.
    STREAM_EVENT_DEAD_LETTERED = "stream.event_dead_lettered"

    # Detection / triage (roadmap M2/C4) -- SA findings mirrored into
    # KronOS's own audited Detection entity; see src/domain/detection.py.
    DETECTION_SYNCED = "detection.synced"
    DETECTION_SYNC_FAILED = "detection.sync_failed"
    DETECTION_TRIAGE_TRANSITIONED = "detection.triage_transitioned"
    DETECTION_TRIAGE_TRANSITION_FAILED = "detection.triage_transition_failed"

    # Correlation (roadmap M2/F3) -- SA's native correlation-engine matches
    # mirrored into KronOS's own audited DetectionCorrelation entity; see
    # src/application/correlation_sync.py.
    DETECTION_CORRELATED = "detection.correlated"
    DETECTION_CORRELATION_SYNC_FAILED = "detection.correlation_sync_failed"

    # Rule-pack lifecycle (roadmap M2/C3) -- versioned custom-rule packs;
    # see src/application/rule_pack_service.py.
    RULE_PACK_VERSION_CREATED = "rule_pack.version_created"
    RULE_PACK_VERSION_CREATE_FAILED = "rule_pack.version_create_failed"
    RULE_PACK_SIGNATURE_REJECTED = "rule_pack.signature_rejected"
    RULE_PACK_RULE_PUBLISHED = "rule_pack.rule_published"
    RULE_PACK_RULE_PUBLISH_FAILED = "rule_pack.rule_publish_failed"

    # YARA rule-pack lifecycle (roadmap E4) -- same trust model as C3's Sigma
    # rule packs, applied to YARA rulesets; see
    # src/application/yara_rule_pack_service.py. No RULE_PUBLISHED/
    # RULE_PUBLISH_FAILED analogue: unlike C3 (which pushes each accepted
    # rule to a real external system, OpenSearch), "publishing" a YARA rule
    # pack version only flips this repository's own local pointer -- there
    # is no second external system call that can fail independently of the
    # version-create step.
    YARA_RULE_PACK_VERSION_CREATED = "yara_rule_pack.version_created"
    YARA_RULE_PACK_VERSION_CREATE_FAILED = "yara_rule_pack.version_create_failed"
    YARA_RULE_PACK_SIGNATURE_REJECTED = "yara_rule_pack.signature_rejected"
    YARA_RULE_PACK_VERSION_PUBLISHED = "yara_rule_pack.version_published"
    YARA_RULE_PACK_PUBLISH_FAILED = "yara_rule_pack.publish_failed"

    # Playbook engine (roadmap M7/H1) -- deterministic, fully audited
    # response automation; see src/application/playbook_execution.py. One
    # event per step (never batched) so a single execution's audit rows are
    # sufficient, on their own, to fully reconstruct what happened (action
    # name, params, output/error) without needing anything external --
    # exactly the "explainable" contract G3 already gated for the analytics
    # milestone, applied here to response actions instead.
    PLAYBOOK_EXECUTION_STARTED = "playbook.execution_started"
    PLAYBOOK_STEP_EXECUTED = "playbook.step_executed"
    PLAYBOOK_STEP_FAILED = "playbook.step_failed"
    PLAYBOOK_EXECUTION_COMPLETED = "playbook.execution_completed"

    # Containment / destructive action adapters (roadmap M7/H2) -- the
    # gate's own binding requirement is "every attempt is audited whether
    # or not it succeeded," so ATTEMPTED is logged before the approval gate
    # is even consulted (a bug inside the gate itself must never erase the
    # fact an attempt happened), and DENIED is its own distinct event from
    # FAILED -- "no approval" and "a real backend error" are different
    # facts a court-facing audit trail must not conflate. See
    # src/application/containment_action.py.
    CONTAINMENT_ACTION_ATTEMPTED = "containment.action_attempted"
    CONTAINMENT_ACTION_DENIED = "containment.action_denied"
    CONTAINMENT_ACTION_EXECUTED = "containment.action_executed"
    CONTAINMENT_ACTION_FAILED = "containment.action_failed"

    # Case/ticket integration (roadmap M7/H4) -- mirrors CONTAINMENT_ACTION's
    # own ATTEMPTED-before-the-call / distinct-FAILED discipline exactly:
    # ATTEMPTED is logged before the real outbound TicketingSystem call is
    # even made, so a crash inside that call can never erase the fact an
    # attempt happened; FAILED means "the real backend was unreachable or
    # rejected the call," never silently absorbed. There is no separate
    # DENIED event here -- unlike H2's destructive actions, creating/
    # updating an external ticket has no approval-gate concept in this
    # pass. See src/application/ticket_sync_action.py.
    TICKET_SYNC_ATTEMPTED = "ticket.sync_attempted"
    TICKET_SYNC_EXECUTED = "ticket.sync_executed"
    TICKET_SYNC_FAILED = "ticket.sync_failed"

    # Integration sink pushes (KAFKA_AND_INTEGRATIONS_ROADMAP.md R1 --
    # KronOS -> external SIEM/SOAR) -- mirrors TICKET_SYNC's own
    # ATTEMPTED-before-the-call / distinct-FAILED discipline exactly, one
    # triple per real batch pushed through an IntegrationSink: ATTEMPTED is
    # logged before the real outbound call is even made, so a crash inside
    # it can never erase the fact an attempt happened; EXECUTED records the
    # real SinkAck (including its honest ACKNOWLEDGED/UNACKNOWLEDGED
    # status -- never conflated); FAILED means the real backend was
    # unreachable, rejected the call, or a real SinkAuthenticator failure,
    # never silently absorbed. See src/application/detection_sink_push.py.
    SINK_PUSH_ATTEMPTED = "sink.push_attempted"
    SINK_PUSH_EXECUTED = "sink.push_executed"
    SINK_PUSH_FAILED = "sink.push_failed"

    # Org administration
    ORG_USER_INVITED = "org.user_invited"
    ORG_USER_ROLE_CHANGED = "org.user_role_changed"
    ORG_USER_REMOVED = "org.user_removed"
    ORG_SETTINGS_UPDATED = "org.settings_updated"

    # Tenant storage quota (docs/TENANT_USAGE_QUOTA.md) -- a real, distinct
    # event per mutation/decision point: QUOTA_UPDATED is the admin-facing
    # config change; the other three are the gate's own enforcement
    # decisions, each independently auditable without needing to cross-
    # reference the upload/parse events they accompany.
    QUOTA_UPDATED = "quota.updated"
    QUOTA_UPLOAD_DENIED = "quota.upload_denied"
    QUOTA_INGESTION_HELD = "quota.ingestion_held"
    QUOTA_INGESTION_RESUMED = "quota.ingestion_resumed"

    # Integration sources (roadmap Q1) -- external EDR/SIEM/IDS tools
    # handing KronOS their own real alerts, via the IntegrationSource
    # foundation (src/application/integration_source.py). One audit event
    # per real ingested batch (a whole webhook call, or a whole poll
    # cycle's page of results) -- mirrors the existing collector-ingest
    # idiom of auditing at the durable-batch granularity
    # (BATCH_SEALED/STREAM_EVENT_DEAD_LETTERED above), not per raw event,
    # since raw per-event produces onto the stream are provisional/
    # unsealed until a batch is actually sealed.
    INTEGRATION_SOURCE_PUSH_INGESTED = "integration_source.push_ingested"
    INTEGRATION_SOURCE_POLL_COMPLETED = "integration_source.poll_completed"
    INTEGRATION_SOURCE_POLL_FAILED = "integration_source.poll_failed"

    # Integration source API-key provisioning (Milestone W8, Gap Audit
    # P1-7) -- credential issuance/revocation, at least as sensitive as
    # evidence deletion (both require aal2 step-up, see admin_integration_
    # sources.py), so both get their own real, auditable event distinct
    # from the push/poll ingestion events above. Audit details never
    # include the plaintext key (CLAUDE.md SS B.4: no credentials in logs).
    INTEGRATION_SOURCE_KEY_PROVISIONED = "integration_source.key_provisioned"
    INTEGRATION_SOURCE_KEY_REVOKED = "integration_source.key_revoked"

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
