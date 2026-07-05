"""Evidence domain model with FSM state transitions."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from src.exceptions import EvidenceStateError

# ---------------------------------------------------------------------------
# State machine definition
# ---------------------------------------------------------------------------

# Maps each state to the set of valid next states.
# PURGED is reachable from every other state: an org-admin may delete
# evidence at any point in its lifecycle (Project_Specifications.md §2 —
# the retention/legal-hold purge soft-deletes the row rather than removing
# it, so the custodial record survives indefinitely).
_VALID_TRANSITIONS: dict[str, set[str]] = {
    "UPLOADING": {"SCANNING", "PURGED"},
    "SCANNING": {"HASHING", "ERROR", "PURGED"},
    "HASHING": {"RECEIVED", "ERROR", "PURGED"},
    "RECEIVED": {"PARSING", "ERROR", "PURGED"},
    "PARSING": {"COMPLETE", "ERROR", "PURGED"},
    "COMPLETE": {"PURGED"},
    "ERROR": {"PURGED"},
    "PURGED": set(),
}


class EvidenceState(StrEnum):
    """Lifecycle states for a piece of evidence."""

    UPLOADING = "UPLOADING"
    SCANNING = "SCANNING"
    HASHING = "HASHING"
    RECEIVED = "RECEIVED"
    PARSING = "PARSING"
    COMPLETE = "COMPLETE"
    ERROR = "ERROR"
    PURGED = "PURGED"

    def can_transition_to(self, target: EvidenceState) -> bool:
        return target.value in _VALID_TRANSITIONS.get(self.value, set())

    def transition_to(self, target: EvidenceState) -> EvidenceState:
        if not self.can_transition_to(target):
            raise EvidenceStateError(
                f"Invalid evidence state transition: {self.value} → {target.value}",
                context={"from_state": self.value, "to_state": target.value},
            )
        return target


class EvidenceMetadata(BaseModel):
    """Immutable evidence intake metadata captured at upload time."""

    model_config = {"frozen": True}

    original_filename: str
    content_type: str
    size_bytes: int = Field(ge=0)
    uploader_user_id: uuid.UUID
    case_id: uuid.UUID
    org_id: uuid.UUID
    org_alias: str


class Evidence(BaseModel):
    """Core evidence entity tracking lifecycle and chain-of-custody fingerprints."""

    model_config = {"frozen": True}

    evidence_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    metadata: EvidenceMetadata
    state: EvidenceState = EvidenceState.UPLOADING
    sha256: str | None = None
    md5: str | None = None
    minio_quarantine_key: str | None = None
    minio_evidence_key: str | None = None
    error_reason: str | None = None
    # Legal hold + WORM retention (Project_Specifications.md §2 "evidence" schema).
    legal_hold: bool = False
    object_lock_until: datetime | None = None
    # RFC 3161 TSA-signed timestamp of `sha256`, stored as raw DER TimeStampToken bytes.
    rfc3161_token: bytes | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def with_state(self, target: EvidenceState) -> Evidence:
        """Return a new Evidence in the given state after FSM validation."""
        new_state = self.state.transition_to(target)
        return self.model_copy(update={"state": new_state, "updated_at": datetime.now(UTC)})

    def with_error(self, reason: str) -> Evidence:
        """Transition to ERROR state with a human-readable reason."""
        # ERROR is reachable from any non-terminal state.
        if self.state in (EvidenceState.COMPLETE, EvidenceState.ERROR):
            raise EvidenceStateError(
                f"Cannot set error on terminal state {self.state.value}",
                context={"state": self.state.value},
            )
        return self.model_copy(
            update={
                "state": EvidenceState.ERROR,
                "error_reason": reason,
                "updated_at": datetime.now(UTC),
            }
        )

    def with_hashes(self, sha256: str, md5: str) -> Evidence:
        return self.model_copy(
            update={"sha256": sha256, "md5": md5, "updated_at": datetime.now(UTC)}
        )

    def with_keys(self, quarantine_key: str | None, evidence_key: str | None) -> Evidence:
        return self.model_copy(
            update={
                "minio_quarantine_key": quarantine_key,
                "minio_evidence_key": evidence_key,
                "updated_at": datetime.now(UTC),
            }
        )

    def with_legal_hold(self, hold: bool) -> Evidence:
        """Return a copy with the legal-hold flag set/cleared.

        A legal hold blocks purge/delete regardless of retention expiry
        (SEC 17a-4(f) / ISO A.5.33); it does not itself change FSM state.
        """
        return self.model_copy(update={"legal_hold": hold, "updated_at": datetime.now(UTC)})

    def with_object_lock_until(self, retain_until: datetime) -> Evidence:
        """Return a copy recording the MinIO Object Lock retain-until date."""
        return self.model_copy(
            update={"object_lock_until": retain_until, "updated_at": datetime.now(UTC)}
        )

    def with_rfc3161_token(self, token: bytes) -> Evidence:
        """Return a copy with the RFC 3161 TSA timestamp token attached."""
        return self.model_copy(update={"rfc3161_token": token, "updated_at": datetime.now(UTC)})

    def with_purge(self) -> Evidence:
        """Transition to PURGED — the terminal soft-delete state.

        The row is never removed (Project_Specifications.md §2): only the
        FSM state changes, so the custodial record survives indefinitely.
        """
        return self.with_state(EvidenceState.PURGED)
