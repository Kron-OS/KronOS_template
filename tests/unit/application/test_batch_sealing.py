"""Unit tests for BatchSealingService (roadmap M3/D3).

Mocks only the real external boundaries this service composes (D1's
StreamIngestAdapter, MinIO-backed SealedBatchStorage, the RFC 3161 TSA
client) per CLAUDE.md SS B.5 -- AuditLogService uses the real class over
tests/conftest.py's InMemoryAuditLogRepository (a legitimate adapter
double, same pattern as InMemoryDetectionRepository elsewhere), and
SealedBatchRepository uses the real InMemorySealedBatchRepository for the
same reason. The real, live-dependency version of every scenario below
(actual Redis/MinIO/openssl-ts-backed TSA/Postgres) is in
poc/batch_sealing/.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from src.adapter.queue.stream_ingest import StreamMessage
from src.adapter.repository.sealed_batch import InMemorySealedBatchRepository
from src.application.audit_log import AuditLogService
from src.application.batch_sealing import BatchSealingService
from src.application.sealing_trigger_policy import SizeBoundTriggerPolicy, TimeBoundTriggerPolicy
from src.domain.audit import AuditEventType
from src.domain.merkle import build_merkle_root, merkle_proof, verify_proof
from src.domain.sealed_batch import SealedBatch
from src.exceptions import BatchSealFailedError, EvidenceLossDetectedError, StorageError
from tests.conftest import InMemoryAuditLogRepository


def _msg(mid: str, payload: bytes) -> StreamMessage:
    return StreamMessage(message_id=mid, payload=payload)


def _stream_adapter(carry_over: list[StreamMessage], fresh: list[StreamMessage]) -> AsyncMock:
    adapter = AsyncMock()
    adapter.reclaim_stale.return_value = carry_over
    adapter.consume.return_value = fresh
    adapter.earliest_message_id.return_value = None
    return adapter


def _storage(bucket: str = "kronos-stream-batches-org", key: str = "src/batch.json") -> AsyncMock:
    storage = AsyncMock()
    storage.put_batch.return_value = (bucket, key)
    return storage


def _tsa(token: bytes = b"\x30\x82fake-tsa-token") -> AsyncMock:
    tsa = AsyncMock()
    tsa.timestamp.return_value = token
    return tsa


def _service(
    stream_adapter: AsyncMock,
    storage: AsyncMock,
    tsa,
    audit_log: AuditLogService,
    repository: InMemorySealedBatchRepository,
    trigger_policy,
) -> BatchSealingService:
    return BatchSealingService(
        stream_adapter, storage, tsa, audit_log, repository, trigger_policy
    )


class TestSealPendingNoWork:
    @pytest.mark.asyncio
    async def test_no_pending_messages_returns_none(self) -> None:
        stream = _stream_adapter([], [])
        storage = _storage()
        repo = InMemorySealedBatchRepository()
        audit_log = AuditLogService(InMemoryAuditLogRepository())
        service = _service(stream, storage, _tsa(), audit_log, repo, SizeBoundTriggerPolicy(1))

        result = await service.seal_pending(uuid.uuid4(), "zeek-conn")

        assert result is None
        storage.put_batch.assert_not_awaited()
        stream.ack.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_trigger_not_met_defers_and_does_not_ack(self) -> None:
        messages = [_msg("1-0", b"a"), _msg("2-0", b"b")]
        stream = _stream_adapter([], messages)
        storage = _storage()
        repo = InMemorySealedBatchRepository()
        audit_log = AuditLogService(InMemoryAuditLogRepository())
        # Requires 100 events -- 2 pending is nowhere near enough.
        service = _service(stream, storage, _tsa(), audit_log, repo, SizeBoundTriggerPolicy(100))

        result = await service.seal_pending(uuid.uuid4(), "zeek-conn")

        assert result is None
        storage.put_batch.assert_not_awaited()
        stream.ack.assert_not_awaited()


class TestSealPendingSuccess:
    @pytest.mark.asyncio
    async def test_full_flow_seals_worm_tsa_audit_and_merkle_root(self) -> None:
        org_id = uuid.uuid4()
        messages = [_msg("1-0", b"event-one"), _msg("2-0", b"event-two"), _msg("3-0", b"event-three")]
        stream = _stream_adapter([], messages)
        storage = _storage()
        tsa = _tsa(b"real-looking-der-token")
        audit_repo = InMemoryAuditLogRepository()
        audit_log = AuditLogService(audit_repo)
        repo = InMemorySealedBatchRepository()
        service = _service(stream, storage, tsa, audit_log, repo, SizeBoundTriggerPolicy(1))

        sealed = await service.seal_pending(org_id, "zeek-conn")

        assert sealed is not None
        assert sealed.event_count == 3
        assert sealed.org_id == org_id
        assert sealed.source_id == "zeek-conn"

        # WORM write happened with the real event payloads, base64-encoded.
        storage.put_batch.assert_awaited_once()
        put_org, put_source, put_batch_id, manifest_bytes = storage.put_batch.await_args[0]
        assert put_org == org_id
        assert put_source == "zeek-conn"
        assert put_batch_id == sealed.batch_id
        manifest = json.loads(manifest_bytes)
        assert manifest["event_count"] == 3
        assert [e["message_id"] for e in manifest["events"]] == ["1-0", "2-0", "3-0"]

        # Merkle root computed the same way AuditLogService.anchor_day() does
        # -- reused, not reimplemented.
        expected_leaves = [hashlib.sha256(m.payload).hexdigest() for m in messages]
        assert sealed.leaf_hashes == tuple(expected_leaves)
        assert sealed.merkle_root == build_merkle_root(expected_leaves)

        # TSA called over the Merkle root's raw digest bytes.
        tsa.timestamp.assert_awaited_once_with(bytes.fromhex(sealed.merkle_root))
        assert sealed.tsa_token == b"real-looking-der-token"

        # Persisted for real.
        assert await repo.get_by_id(sealed.batch_id, org_id) == sealed

        # Exactly one audit event, the success type.
        assert len(audit_repo._events) == 1
        assert audit_repo._events[0].event_type == AuditEventType.BATCH_SEALED
        assert audit_repo._events[0].details["merkle_root"] == sealed.merkle_root

        # Only after everything else succeeded: ack the real source messages.
        stream.ack.assert_awaited_once_with(org_id, "zeek-conn", "kronos-sealer", "1-0", "2-0", "3-0")

    @pytest.mark.asyncio
    async def test_carry_over_and_fresh_messages_combined_in_order(self) -> None:
        carry_over = [_msg("1-0", b"stale-pending")]
        fresh = [_msg("2-0", b"new")]
        stream = _stream_adapter(carry_over, fresh)
        storage = _storage()
        audit_log = AuditLogService(InMemoryAuditLogRepository())
        repo = InMemorySealedBatchRepository()
        service = _service(stream, storage, _tsa(), audit_log, repo, SizeBoundTriggerPolicy(1))

        sealed = await service.seal_pending(uuid.uuid4(), "zeek-conn")

        assert sealed is not None
        assert sealed.message_ids == ("1-0", "2-0")

    @pytest.mark.asyncio
    async def test_no_tsa_configured_seals_with_none_token(self) -> None:
        messages = [_msg("1-0", b"a")]
        stream = _stream_adapter([], messages)
        storage = _storage()
        audit_log = AuditLogService(InMemoryAuditLogRepository())
        repo = InMemorySealedBatchRepository()
        service = _service(stream, storage, None, audit_log, repo, SizeBoundTriggerPolicy(1))

        sealed = await service.seal_pending(uuid.uuid4(), "zeek-conn")

        assert sealed is not None
        assert sealed.tsa_token is None
        stream.ack.assert_awaited_once()


class TestSealPendingFailureNeverAcks:
    @pytest.mark.asyncio
    async def test_worm_write_failure_never_acks_and_raises(self) -> None:
        messages = [_msg("1-0", b"a"), _msg("2-0", b"b")]
        stream = _stream_adapter([], messages)
        storage = _storage()
        storage.put_batch.side_effect = StorageError("MinIO unreachable")
        audit_repo = InMemoryAuditLogRepository()
        audit_log = AuditLogService(audit_repo)
        repo = InMemorySealedBatchRepository()
        service = _service(stream, storage, _tsa(), audit_log, repo, SizeBoundTriggerPolicy(1))
        org_id = uuid.uuid4()

        with pytest.raises(BatchSealFailedError):
            await service.seal_pending(org_id, "zeek-conn")

        stream.ack.assert_not_awaited()
        assert await repo.get_last_sealed(org_id, "zeek-conn") is None
        assert audit_repo._events[-1].event_type == AuditEventType.BATCH_SEAL_FAILED

    @pytest.mark.asyncio
    async def test_tsa_failure_never_acks_and_raises_even_though_worm_write_succeeded(self) -> None:
        """TSA is mandatory here (unlike AuditLogService.anchor_day()'s best-effort
        TSA) -- see BatchSealingService's module docstring point 3."""
        messages = [_msg("1-0", b"a")]
        stream = _stream_adapter([], messages)
        storage = _storage()
        tsa = _tsa()
        tsa.timestamp.side_effect = StorageError("TSA unreachable")
        audit_repo = InMemoryAuditLogRepository()
        audit_log = AuditLogService(audit_repo)
        repo = InMemorySealedBatchRepository()
        service = _service(stream, storage, tsa, audit_log, repo, SizeBoundTriggerPolicy(1))
        org_id = uuid.uuid4()

        with pytest.raises(BatchSealFailedError):
            await service.seal_pending(org_id, "zeek-conn")

        # The WORM object write itself did happen (a documented, acceptable
        # orphan -- see module docstring) but nothing was acked or persisted.
        storage.put_batch.assert_awaited_once()
        stream.ack.assert_not_awaited()
        assert await repo.get_last_sealed(org_id, "zeek-conn") is None


class TestWatermarkGapDetection:
    @pytest.mark.asyncio
    async def test_no_prior_seal_no_gap_check(self) -> None:
        stream = _stream_adapter([], [])
        repo = InMemorySealedBatchRepository()
        audit_log = AuditLogService(InMemoryAuditLogRepository())
        service = _service(stream, _storage(), _tsa(), audit_log, repo, SizeBoundTriggerPolicy(1))

        # Must not raise -- nothing sealed yet for this (org, source).
        result = await service.seal_pending(uuid.uuid4(), "zeek-conn")
        assert result is None

    @pytest.mark.asyncio
    async def test_earliest_at_or_before_watermark_is_not_a_gap(self) -> None:
        org_id = uuid.uuid4()
        repo = InMemorySealedBatchRepository()
        await repo.save(_prior_batch(org_id, last_message_id="10-0"))
        stream = _stream_adapter([], [])
        stream.earliest_message_id.return_value = "5-0"  # older, untrimmed history -- fine
        audit_log = AuditLogService(InMemoryAuditLogRepository())
        service = _service(stream, _storage(), _tsa(), audit_log, repo, SizeBoundTriggerPolicy(1))

        result = await service.seal_pending(org_id, "zeek-conn")
        assert result is None  # no messages pending, but also no gap raised

    @pytest.mark.asyncio
    async def test_gap_detected_pages_and_raises(self) -> None:
        org_id = uuid.uuid4()
        repo = InMemorySealedBatchRepository()
        await repo.save(_prior_batch(org_id, last_message_id="10-0"))
        stream = _stream_adapter([], [])
        # Earliest retained entry is now AFTER our last-sealed watermark --
        # MAXLEN has trimmed past sealed history into never-sealed territory.
        stream.earliest_message_id.return_value = "20-0"
        audit_repo = InMemoryAuditLogRepository()
        audit_log = AuditLogService(audit_repo)
        service = _service(stream, _storage(), _tsa(), audit_log, repo, SizeBoundTriggerPolicy(1))

        with pytest.raises(EvidenceLossDetectedError):
            await service.seal_pending(org_id, "zeek-conn")

        assert audit_repo._events[-1].event_type == AuditEventType.BATCH_SEAL_WATERMARK_GAP_DETECTED
        assert audit_repo._events[-1].details["last_sealed_message_id"] == "10-0"
        assert audit_repo._events[-1].details["earliest_retained_message_id"] == "20-0"


def _msg_with_age(payload: bytes, age_seconds: float) -> StreamMessage:
    """A StreamMessage whose id's real millisecond component makes
    _message_id_ms() compute an oldest_pending_age_seconds of roughly
    age_seconds -- lets a test simulate "this event has been pending for a
    long time" without actually sleeping."""
    old_ms = int(datetime.now(UTC).timestamp() * 1000 - age_seconds * 1000)
    return StreamMessage(message_id=f"{old_ms}-0", payload=payload)


class TestSealerFallBehindAlerting:
    """Distinct from TestWatermarkGapDetection above: this is a liveness
    signal (the sealer isn't keeping up), not evidence loss, so it must page
    (log + audit event) WITHOUT raising or blocking the seal attempt this
    same cycle makes -- see BatchSealingService's module docstring and
    _check_sealer_fall_behind's own docstring for the reasoning."""

    @pytest.mark.asyncio
    async def test_disabled_by_default_never_pages_even_with_very_old_pending_events(self) -> None:
        messages = [_msg_with_age(b"ancient", age_seconds=99_999)]
        stream = _stream_adapter([], messages)
        audit_repo = InMemoryAuditLogRepository()
        audit_log = AuditLogService(audit_repo)
        repo = InMemorySealedBatchRepository()
        # No stall_alert_after_seconds passed -- default None disables the check.
        service = _service(stream, _storage(), _tsa(), audit_log, repo, SizeBoundTriggerPolicy(100))

        result = await service.seal_pending(uuid.uuid4(), "zeek-conn")

        assert result is None  # trigger policy still not met, deferred as normal
        assert all(
            e.event_type != AuditEventType.SEALER_FALL_BEHIND_DETECTED for e in audit_repo._events
        )

    @pytest.mark.asyncio
    async def test_stale_pending_event_pages_but_does_not_raise_and_seal_still_proceeds(self) -> None:
        org_id = uuid.uuid4()
        messages = [_msg_with_age(b"stale-event", age_seconds=3600)]  # 1 hour old
        stream = _stream_adapter([], messages)
        audit_repo = InMemoryAuditLogRepository()
        audit_log = AuditLogService(audit_repo)
        repo = InMemorySealedBatchRepository()
        # Threshold (60s) is well below the trigger policy's own threshold
        # would ever need to be -- distinct knobs, per this item's own design.
        service = BatchSealingService(
            stream, _storage(), _tsa(), audit_log, repo, SizeBoundTriggerPolicy(1),
            stall_alert_after_seconds=60.0,
        )

        sealed = await service.seal_pending(org_id, "zeek-conn")

        # The alert did NOT block sealing -- the very same cycle sealed the
        # stale segment (the mechanism that resolves the staleness).
        assert sealed is not None
        stream.ack.assert_awaited_once()

        alert_events = [
            e for e in audit_repo._events if e.event_type == AuditEventType.SEALER_FALL_BEHIND_DETECTED
        ]
        assert len(alert_events) == 1
        assert alert_events[0].details["pending_event_count"] == 1
        assert alert_events[0].details["oldest_pending_age_seconds"] >= 3600
        assert alert_events[0].details["stall_alert_after_seconds"] == 60.0

        # Both the alert AND the normal success event were recorded -- the
        # alert is additive, not a replacement for the normal BATCH_SEALED flow.
        assert any(e.event_type == AuditEventType.BATCH_SEALED for e in audit_repo._events)

    @pytest.mark.asyncio
    async def test_pending_age_below_threshold_does_not_page(self) -> None:
        messages = [_msg_with_age(b"fresh", age_seconds=5)]
        stream = _stream_adapter([], messages)
        audit_repo = InMemoryAuditLogRepository()
        audit_log = AuditLogService(audit_repo)
        repo = InMemorySealedBatchRepository()
        service = BatchSealingService(
            stream, _storage(), _tsa(), audit_log, repo, SizeBoundTriggerPolicy(100),
            stall_alert_after_seconds=60.0,
        )

        result = await service.seal_pending(uuid.uuid4(), "zeek-conn")

        assert result is None
        assert all(
            e.event_type != AuditEventType.SEALER_FALL_BEHIND_DETECTED for e in audit_repo._events
        )


class TestInclusionProofReconstruction:
    """The literal gate condition: an arbitrary real event's inclusion proof,
    reconstructed from the SealedBatch's own stored leaf_hashes, must verify
    against the SealedBatch's own persisted merkle_root -- and a tampered
    proof/leaf must be rejected. Uses src.domain.merkle directly, exactly as
    the real (Postgres-backed) SealedBatch row would be used in production."""

    @pytest.mark.asyncio
    async def test_arbitrary_event_proof_verifies_true_and_tampered_proof_verifies_false(self) -> None:
        messages = [_msg(f"{i}-0", f"event-{i}".encode()) for i in range(1, 6)]
        stream = _stream_adapter([], messages)
        audit_log = AuditLogService(InMemoryAuditLogRepository())
        repo = InMemorySealedBatchRepository()
        service = _service(stream, _storage(), _tsa(), audit_log, repo, SizeBoundTriggerPolicy(1))

        sealed = await service.seal_pending(uuid.uuid4(), "zeek-conn")
        assert sealed is not None

        for index in range(len(sealed.leaf_hashes)):
            leaf = sealed.leaf_hashes[index]
            proof = merkle_proof(list(sealed.leaf_hashes), index)
            assert verify_proof(leaf, proof, sealed.merkle_root) is True

        # Negative case: tamper the leaf -> proof must fail.
        tampered_leaf = hashlib.sha256(b"not-the-real-event").hexdigest()
        proof = merkle_proof(list(sealed.leaf_hashes), 2)
        assert verify_proof(tampered_leaf, proof, sealed.merkle_root) is False

        # Negative case: tamper the proof itself -> must also fail.
        real_leaf = sealed.leaf_hashes[2]
        tampered_proof = [(hashlib.sha256(b"bogus-sibling").hexdigest(), "right")]
        assert verify_proof(real_leaf, tampered_proof, sealed.merkle_root) is False


def _prior_batch(org_id: uuid.UUID, *, last_message_id: str) -> SealedBatch:
    return SealedBatch(
        org_id=org_id,
        source_id="zeek-conn",
        sealed_at=datetime.now(UTC),
        event_count=1,
        leaf_hashes=("a" * 64,),
        message_ids=(last_message_id,),
        merkle_root="b" * 64,
        worm_bucket="kronos-stream-batches-org",
        worm_object_key="zeek-conn/prior.json",
        first_message_id=last_message_id,
        last_message_id=last_message_id,
    )
