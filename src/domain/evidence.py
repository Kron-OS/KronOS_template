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
_VALID_TRANSITIONS: dict[str, set[str]] = {
    "UPLOADING": {"SCANNING"},
    "SCANNING": {"HASHING", "ERROR"},
    "HASHING": {"RECEIVED", "ERROR"},
    "RECEIVED": {"PARSING", "ERROR"},
    "PARSING": {"COMPLETE", "ERROR"},
    "COMPLETE": set(),
    "ERROR": set(),
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
