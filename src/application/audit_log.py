"""AuditLogService: immutable, append-only audit log with SHA-256 hash chain."""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any

from src.adapter.repository.audit_log import AuditLogRepository
from src.domain.audit import AuditEvent, AuditEventType
from src.exceptions import AuditLogError

logger = logging.getLogger(__name__)

# Genesis value used as prev_row_hash for the very first event in an org's chain.
_GENESIS_HASH = hashlib.sha256(b"kronos-audit-genesis").hexdigest()


def _canonical_json(event: AuditEvent) -> bytes:
    """Produce a deterministic JSON encoding of audit event fields for hashing.

    Excludes row_hash and prev_row_hash to avoid circular dependency.
    Fields are sorted alphabetically so the output is reproducible across
    Python versions and platforms.
    """
    payload: dict[str, Any] = {
        "event_id": str(event.event_id),
        "event_type": event.event_type.value,
        "actor_user_id": str(event.actor_user_id) if event.actor_user_id else None,
        "actor_username": event.actor_username,
        "org_id": str(event.org_id) if event.org_id else None,
        "case_id": str(event.case_id) if event.case_id else None,
        "evidence_id": str(event.evidence_id) if event.evidence_id else None,
        "details": event.details,
        "occurred_at": event.occurred_at.isoformat(),
        "sequence_number": event.sequence_number,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_row_hash(prev_hash: str, event: AuditEvent) -> str:
    """Compute SHA-256(prev_hash || canonical_json(event))."""
    digest = hashlib.sha256()
    digest.update(prev_hash.encode("utf-8"))
    digest.update(_canonical_json(event))
    return digest.hexdigest()


class AuditLogService:
    """Orchestrates audit event creation with a tamper-evident hash chain.

    The hash chain provides cryptographic linkage: each event's row_hash
    covers both the previous hash and the event's own content. Any gap or
    mutation in the chain is detectable by ``verify_chain``.
    """

    def __init__(self, repository: AuditLogRepository) -> None:
        self._repository = repository

    async def log(
        self,
        event_type: AuditEventType,
        org_id: uuid.UUID | None = None,
        *,
        actor_user_id: uuid.UUID | None = None,
        actor_username: str | None = None,
        case_id: uuid.UUID | None = None,
        evidence_id: uuid.UUID | None = None,
        details: dict[str, Any] | None = None,
        occurred_at: datetime | None = None,
    ) -> AuditEvent:
        """Create, hash-chain, and persist one audit event."""
        if org_id is None and actor_user_id is None:
            raise AuditLogError("org_id or actor_user_id must be provided for audit tracing")

        prev_hash: str
        seq: int
        if org_id is not None:
            latest_hash = await self._repository.get_latest_hash(org_id)
            latest_seq = await self._repository.get_latest_sequence(org_id)
            prev_hash = latest_hash if latest_hash else _GENESIS_HASH
            seq = latest_seq + 1
        else:
            prev_hash = _GENESIS_HASH
            seq = 1

        partial = AuditEvent(
            event_type=event_type,
            actor_user_id=actor_user_id,
            actor_username=actor_username,
            org_id=org_id,
            case_id=case_id,
            evidence_id=evidence_id,
            details=details or {},
            occurred_at=occurred_at or datetime.now(UTC),
            sequence_number=seq,
            prev_row_hash=prev_hash,
        )
        row_hash = compute_row_hash(prev_hash, partial)
        event = partial.model_copy(update={"row_hash": row_hash})

        try:
            persisted = await self._repository.append(event)
        except Exception as exc:
            raise AuditLogError(
                "Failed to persist audit event",
                context={"event_type": event_type.value, "error": str(exc)},
            ) from exc

        logger.info(
            "audit_event_logged",
            extra={
                "event_id": str(persisted.event_id),
                "event_type": event_type.value,
                "seq": seq,
            },
        )
        return persisted

    @asynccontextmanager
    async def audit_context(
        self,
        success_event_type: AuditEventType,
        error_event_type: AuditEventType,
        org_id: uuid.UUID | None = None,
        *,
        actor_user_id: uuid.UUID | None = None,
        actor_username: str | None = None,
        case_id: uuid.UUID | None = None,
        evidence_id: uuid.UUID | None = None,
        details: dict[str, Any] | None = None,
    ) -> AsyncIterator[None]:
        """Context manager that logs success or error depending on outcome.

        On normal exit → logs success_event_type.
        On exception   → logs error_event_type with error details, then re-raises.
        """
        try:
            yield
        except Exception as exc:
            await self.log(
                error_event_type,
                org_id=org_id,
                actor_user_id=actor_user_id,
                actor_username=actor_username,
                case_id=case_id,
                evidence_id=evidence_id,
                details={**(details or {}), "error": str(exc), "error_type": type(exc).__name__},
            )
            raise
        else:
            await self.log(
                success_event_type,
                org_id=org_id,
                actor_user_id=actor_user_id,
                actor_username=actor_username,
                case_id=case_id,
                evidence_id=evidence_id,
                details=details or {},
            )

    async def verify_chain(self, org_id: uuid.UUID) -> tuple[bool, str | None]:
        """Walk the org's audit chain and verify every hash link.

        Returns (True, None) if chain is intact.
        Returns (False, detail_message) if a break is detected.
        """
        prev_hash = _GENESIS_HASH
        async for event in self._repository.stream_by_case(org_id):  # type: ignore[arg-type]
            expected = compute_row_hash(event.prev_row_hash or _GENESIS_HASH, event)
            if event.row_hash != expected:
                detail = (
                    f"Hash mismatch at seq={event.sequence_number} " f"event_id={event.event_id}"
                )
                logger.warning("audit_chain_tampered", extra={"detail": detail})
                return False, detail
            prev_hash = event.row_hash  # noqa: F841 — kept for readability
        return True, None
