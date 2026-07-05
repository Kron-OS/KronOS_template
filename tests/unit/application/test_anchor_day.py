"""Integration-style unit tests for AuditLogService.anchor_day() (AUDIT-03).

Uses the in-memory fake AnchorRepository (tests/conftest.py) to prove the
whole anchor pipeline end-to-end without a real Postgres/TSA: populate a day
with events, anchor it, and assert the root is non-trivial, the TSA token is
persisted, and re-anchoring the same day is idempotent (last-write-wins on
the upsert, same root recomputed).
"""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime

from src.application.audit_log import AuditLogService
from src.domain.audit import AuditEventType
from src.domain.merkle import EMPTY_ROOT
from tests.conftest import InMemoryAuditLogRepository


class _FakeTimestampService:
    """Stub RFC3161TimestampService — returns a deterministic fake token."""

    def __init__(self) -> None:
        self.calls: list[bytes] = []

    async def timestamp(self, digest: bytes) -> bytes:
        self.calls.append(digest)
        return b"FAKE-TSA-TOKEN:" + digest


async def _populate_day(
    repo: InMemoryAuditLogRepository, org_id: uuid.UUID, anchor_date: date, count: int
) -> None:
    svc = AuditLogService(repo)
    for i in range(count):
        await svc.log(
            AuditEventType.EVIDENCE_UPLOAD_FINALIZED,
            org_id=org_id,
            details={"i": i},
            occurred_at=datetime(
                anchor_date.year, anchor_date.month, anchor_date.day, 12, 0, 0, tzinfo=UTC
            ),
        )


async def test_anchor_day_root_is_non_trivial_and_tsa_token_persisted() -> None:
    repo = InMemoryAuditLogRepository()
    org_id = uuid.uuid4()
    today = date(2026, 6, 25)
    await _populate_day(repo, org_id, today, count=5)

    svc = AuditLogService(repo)
    timestamp_service = _FakeTimestampService()
    root = await svc.anchor_day(today, org_id, timestamp_service)

    assert root != EMPTY_ROOT
    assert len(root) == 64  # hex SHA-256
    assert len(timestamp_service.calls) == 1

    stored = await repo.get_anchor(today, org_id=org_id)
    assert stored is not None
    stored_root, tsa_token = stored
    assert stored_root == root
    assert tsa_token == b"FAKE-TSA-TOKEN:" + bytes.fromhex(root)


async def test_anchor_day_with_no_events_returns_empty_root() -> None:
    repo = InMemoryAuditLogRepository()
    org_id = uuid.uuid4()
    today = date(2026, 6, 25)

    svc = AuditLogService(repo)
    root = await svc.anchor_day(today, org_id, _FakeTimestampService())

    assert root == EMPTY_ROOT


async def test_re_anchoring_same_day_is_idempotent_when_events_unchanged() -> None:
    """Re-running the anchor for a day whose events haven't changed must
    recompute the same root (last-write-wins upsert, not a duplicate row)."""
    repo = InMemoryAuditLogRepository()
    org_id = uuid.uuid4()
    today = date(2026, 6, 25)
    await _populate_day(repo, org_id, today, count=3)

    svc = AuditLogService(repo)
    timestamp_service = _FakeTimestampService()

    first_root = await svc.anchor_day(today, org_id, timestamp_service)
    second_root = await svc.anchor_day(today, org_id, timestamp_service)

    assert first_root == second_root
    assert len(timestamp_service.calls) == 2  # TSA is called again each run...
    stored = await repo.get_anchor(today, org_id=org_id)
    assert stored is not None
    # ...but the upsert means exactly one row survives, holding the latest token.
    stored_root, stored_token = stored
    assert stored_root == first_root
    assert stored_token == b"FAKE-TSA-TOKEN:" + bytes.fromhex(first_root)


async def test_tsa_failure_does_not_block_anchoring() -> None:
    """A TSA outage must not prevent the Merkle root from being computed and
    persisted — only the tsa_token is absent (AuditLogService.anchor_day
    logs a warning and continues, per its try/except around the TSA call)."""

    class _FailingTimestampService:
        async def timestamp(self, digest: bytes) -> bytes:
            raise ConnectionError("TSA unreachable")

    repo = InMemoryAuditLogRepository()
    org_id = uuid.uuid4()
    today = date(2026, 6, 25)
    await _populate_day(repo, org_id, today, count=2)

    svc = AuditLogService(repo)
    root = await svc.anchor_day(today, org_id, _FailingTimestampService())

    assert root != EMPTY_ROOT
    stored = await repo.get_anchor(today, org_id=org_id)
    assert stored is not None
    stored_root, tsa_token = stored
    assert stored_root == root
    assert tsa_token is None


async def test_anchor_day_excludes_its_own_bookkeeping_event() -> None:
    """A second anchor_day call must not fold the first call's own
    AUDIT_MERKLE_ANCHORED event into the day's leaf set."""
    repo = InMemoryAuditLogRepository()
    org_id = uuid.uuid4()
    today = date(2026, 6, 25)
    await _populate_day(repo, org_id, today, count=1)

    svc = AuditLogService(repo)
    first_root = await svc.anchor_day(today, org_id, None)
    second_root = await svc.anchor_day(today, org_id, None)

    assert first_root == second_root
