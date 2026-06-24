"""Unit tests for AuditLogService: hash chain, context manager, error handling."""

from __future__ import annotations

import asyncio
import uuid

import pytest

from src.application.audit_log import _GENESIS_HASH, AuditLogService, compute_row_hash
from src.domain.audit import AuditEventType
from src.exceptions import AuditLogError
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_audit_event


class TestHashChain:
    def test_first_event_uses_genesis_hash(
        self, audit_service: AuditLogService, audit_repo: InMemoryAuditLogRepository
    ) -> None:
        org_id = uuid.uuid4()
        event = await_coro(
            audit_service.log(
                AuditEventType.EVIDENCE_UPLOAD_REQUESTED,
                org_id=org_id,
                actor_user_id=uuid.uuid4(),
                actor_username="user1",
            )
        )
        assert event.prev_row_hash == _GENESIS_HASH

    def test_second_event_links_to_first(
        self, audit_service: AuditLogService, audit_repo: InMemoryAuditLogRepository
    ) -> None:
        org_id = uuid.uuid4()
        ev1 = await_coro(
            audit_service.log(
                AuditEventType.EVIDENCE_UPLOAD_REQUESTED,
                org_id=org_id,
                actor_user_id=uuid.uuid4(),
            )
        )
        ev2 = await_coro(
            audit_service.log(
                AuditEventType.EVIDENCE_UPLOAD_FINALIZED,
                org_id=org_id,
                actor_user_id=uuid.uuid4(),
            )
        )
        assert ev2.prev_row_hash == ev1.row_hash

    def test_row_hash_differs_between_events(self, audit_service: AuditLogService) -> None:
        org_id = uuid.uuid4()
        ev1 = await_coro(audit_service.log(AuditEventType.EVIDENCE_UPLOAD_REQUESTED, org_id=org_id))
        ev2 = await_coro(audit_service.log(AuditEventType.EVIDENCE_SCAN_STARTED, org_id=org_id))
        assert ev1.row_hash != ev2.row_hash

    def test_sequence_numbers_increment(self, audit_service: AuditLogService) -> None:
        org_id = uuid.uuid4()
        ev1 = await_coro(audit_service.log(AuditEventType.PARSE_STARTED, org_id=org_id))
        ev2 = await_coro(audit_service.log(AuditEventType.PARSE_COMPLETED, org_id=org_id))
        assert ev2.sequence_number == ev1.sequence_number + 1

    def test_different_orgs_have_independent_chains(self, audit_service: AuditLogService) -> None:
        org1 = uuid.uuid4()
        org2 = uuid.uuid4()
        ev1 = await_coro(audit_service.log(AuditEventType.CASE_CREATED, org_id=org1))
        ev2 = await_coro(audit_service.log(AuditEventType.CASE_CREATED, org_id=org2))
        # Both start from genesis — they're independent chains.
        assert ev1.prev_row_hash == _GENESIS_HASH
        assert ev2.prev_row_hash == _GENESIS_HASH

    def test_compute_row_hash_is_deterministic(self) -> None:
        event = make_audit_event(sequence_number=1, prev_row_hash=_GENESIS_HASH)
        h1 = compute_row_hash(_GENESIS_HASH, event)
        h2 = compute_row_hash(_GENESIS_HASH, event)
        assert h1 == h2

    def test_row_hash_changes_with_different_prev(self) -> None:
        event = make_audit_event(sequence_number=1, prev_row_hash=_GENESIS_HASH)
        h1 = compute_row_hash(_GENESIS_HASH, event)
        h2 = compute_row_hash("different_prev_hash", event)
        assert h1 != h2

    def test_row_hash_is_hex_string(self, audit_service: AuditLogService) -> None:
        org_id = uuid.uuid4()
        ev = await_coro(audit_service.log(AuditEventType.SYSTEM_ERROR, org_id=org_id))
        assert ev.row_hash is not None
        assert len(ev.row_hash) == 64  # SHA-256 hex digest
        int(ev.row_hash, 16)  # must be valid hex


class TestAuditContext:
    def test_success_logs_success_event(
        self, audit_service: AuditLogService, audit_repo: InMemoryAuditLogRepository
    ) -> None:
        org_id = uuid.uuid4()

        async def run() -> None:
            async with audit_service.audit_context(
                AuditEventType.EVIDENCE_UPLOAD_FINALIZED,
                AuditEventType.EVIDENCE_ERROR,
                org_id=org_id,
            ):
                pass

        await_coro(run())
        events = audit_repo.events
        assert len(events) == 1
        assert events[0].event_type == AuditEventType.EVIDENCE_UPLOAD_FINALIZED

    def test_exception_logs_error_event_and_reraises(
        self, audit_service: AuditLogService, audit_repo: InMemoryAuditLogRepository
    ) -> None:
        org_id = uuid.uuid4()

        async def run() -> None:
            async with audit_service.audit_context(
                AuditEventType.EVIDENCE_UPLOAD_FINALIZED,
                AuditEventType.EVIDENCE_ERROR,
                org_id=org_id,
            ):
                raise ValueError("disk full")

        with pytest.raises(ValueError, match="disk full"):
            await_coro(run())

        events = audit_repo.events
        assert len(events) == 1
        assert events[0].event_type == AuditEventType.EVIDENCE_ERROR
        assert "disk full" in events[0].details.get("error", "")

    def test_context_passes_details(
        self, audit_service: AuditLogService, audit_repo: InMemoryAuditLogRepository
    ) -> None:
        org_id = uuid.uuid4()
        evidence_id = uuid.uuid4()

        async def run() -> None:
            async with audit_service.audit_context(
                AuditEventType.EVIDENCE_HASH_COMPUTED,
                AuditEventType.EVIDENCE_ERROR,
                org_id=org_id,
                evidence_id=evidence_id,
                details={"sha256": "abc"},
            ):
                pass

        await_coro(run())
        events = audit_repo.events
        assert events[0].evidence_id == evidence_id
        assert events[0].details["sha256"] == "abc"


class TestAuditLogErrors:
    def test_missing_org_and_actor_raises(self, audit_service: AuditLogService) -> None:
        with pytest.raises(AuditLogError):
            await_coro(audit_service.log(AuditEventType.SYSTEM_ERROR))


# ---------------------------------------------------------------------------
# Asyncio compatibility helper for synchronous pytest
# ---------------------------------------------------------------------------


def await_coro(coro):  # type: ignore[no-untyped-def]
    """Run a coroutine in a fresh event loop (safe after pytest-asyncio closes its loop)."""
    return asyncio.run(coro)
