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
    # SCANNING and PARSING are legitimate re-entry points, not just terminal
    # dead ends: POST /evidence/{id}/retry-intake re-runs process_intake from
    # ERROR for a retryable intake-stage reason (is_retryable_error_reason),
    # and _run_validation's own evidence.with_state(SCANNING) call is what
    # actually performs that transition. POST /evidence/{id}/retry-parse does
    # the analogous thing for a retryable parse-stage reason
    # (is_parse_stage_error_reason) — the object is already promoted to the
    # evidence bucket, so retrying only re-enters parsing, not intake.
    "ERROR": {"SCANNING", "PARSING", "PURGED"},
    "PURGED": set(),
}


# Reasons that reflect a real, unchanging property of the uploaded bytes --
# retrying intake on the exact same quarantined file can never produce a
# different verdict, so no retry is offered for these. Everything else
# (storage/scanner connectivity errors, an object not yet visible in MinIO,
# any other unanticipated exception) is presumed transient and retryable by
# default -- the safer default for reasons this list doesn't name.
_TERMINAL_ERROR_REASONS: frozenset[str] = frozenset(
    {"validation_failed", "size_limit_exceeded", "hash_mismatch", "no_parser_found"}
)
_TERMINAL_ERROR_PREFIXES: tuple[str, ...] = ("infected:",)


def is_retryable_error_reason(reason: str | None) -> bool:
    """Whether ERROR evidence with this reason is worth a client-facing retry."""
    if reason is None:
        return False
    if reason in _TERMINAL_ERROR_REASONS:
        return False
    return not any(reason.startswith(prefix) for prefix in _TERMINAL_ERROR_PREFIXES)


# Reasons set by the parse/index stage (ParsingOrchestrationService /
# parse_artefact_fast|heavy / abort_orphan_parses), as opposed to the intake
# stage (EvidenceIntakeService / process_intake / abort_orphan_intake). The
# two stages recover differently: an intake-stage ERROR re-enters at
# SCANNING (retry-intake, re-validates/re-scans/re-hashes the still-
# quarantined object); a parse-stage ERROR re-enters at PARSING (retry-parse,
# re-parses the already-promoted evidence-bucket object without touching
# intake at all). no_parser_found is deliberately NOT in this set's retryable
# half -- it's parse-stage but listed in _TERMINAL_ERROR_REASONS above, since
# an unsupported format can't change on retry.
_PARSE_STAGE_ERROR_REASONS: frozenset[str] = frozenset(
    {"no_parser_found", "parse_failed", "ingest_failed", "parse_timeout"}
)


def is_parse_stage_error_reason(reason: str | None) -> bool:
    """Whether this ERROR reason originated from the parse/index stage.

    Used to route a retry to retry-parse (re-enter PARSING) rather than
    retry-intake (re-enter SCANNING) -- the two stages recover from
    different objects (quarantine bucket vs. evidence bucket) and re-run
    different work.
    """
    return reason in _PARSE_STAGE_ERROR_REASONS


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
    # The client's declared SHA-256, captured once at intake start (start_intake)
    # so process_intake — and any later retry-intake — can re-verify against
    # it without needing the client to resupply it (they may not still have
    # the original File object, e.g. after a page reload).
    client_declared_sha256: str | None = None
    # Legal hold + WORM retention (Project_Specifications.md §2 "evidence" schema).
    legal_hold: bool = False
    object_lock_until: datetime | None = None
    # RFC 3161 TSA-signed timestamp of `sha256`, stored as raw DER TimeStampToken bytes.
    rfc3161_token: bytes | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def with_state(self, target: EvidenceState) -> Evidence:
        """Return a new Evidence in the given state after FSM validation.

        Clears any stale error_reason from a prior ERROR excursion — this is
        the only place a real forward transition happens (with_error is the
        one that sets it), so any error_reason left over here is always from
        a previous, now-superseded attempt (e.g. a successful retry-intake
        re-entering via ERROR -> SCANNING).
        """
        new_state = self.state.transition_to(target)
        return self.model_copy(
            update={"state": new_state, "error_reason": None, "updated_at": datetime.now(UTC)}
        )

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

    def with_client_declared_sha256(self, client_sha256: str) -> Evidence:
        """Record the client's declared SHA-256 at intake start (no state change)."""
        return self.model_copy(
            update={"client_declared_sha256": client_sha256, "updated_at": datetime.now(UTC)}
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
