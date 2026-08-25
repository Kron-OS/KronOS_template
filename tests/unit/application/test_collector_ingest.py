"""Unit tests for CollectorIngestService (mocked stream adapter + dedup checker)."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock

import pytest

from src.application.collector_ingest import BackpressureError, CollectorIngestService
from src.domain.collector import CollectorIdentity


def _identity(org_id: uuid.UUID | None = None, source_id: str = "zeek-conn") -> CollectorIdentity:
    return CollectorIdentity(
        org_id=org_id or uuid.uuid4(),
        source_id=source_id,
        cert_subject="CN=test",
        not_after="2026-01-01T00:00:00+00:00",
    )


@pytest.fixture
def stream_adapter() -> AsyncMock:
    adapter = AsyncMock()
    adapter.approximate_length.return_value = 0
    adapter.produce.return_value = "1-0"
    return adapter


@pytest.fixture
def dedup_checker() -> AsyncMock:
    checker = AsyncMock()
    checker.is_duplicate.return_value = False
    return checker


@pytest.fixture
def service(stream_adapter: AsyncMock, dedup_checker: AsyncMock) -> CollectorIngestService:
    return CollectorIngestService(
        stream_adapter, dedup_checker, max_stream_length=100, dedup_ttl_seconds=3600
    )


class TestIngestEvents:
    @pytest.mark.asyncio
    async def test_org_id_and_source_id_always_come_from_identity_not_events(
        self, service: CollectorIngestService, stream_adapter: AsyncMock
    ) -> None:
        identity = _identity()
        # The event tries to claim a different org -- must be ignored.
        await service.ingest_events(identity, [{"org_id": str(uuid.uuid4()), "message": "x"}])

        stream_adapter.produce.assert_awaited_once()
        call_org_id, call_source_id, _payload = stream_adapter.produce.await_args[0]
        assert call_org_id == identity.org_id
        assert call_source_id == identity.source_id

    @pytest.mark.asyncio
    async def test_multiple_events_all_produced(
        self, service: CollectorIngestService, stream_adapter: AsyncMock
    ) -> None:
        identity = _identity()
        outcomes = await service.ingest_events(identity, [{"a": 1}, {"a": 2}, {"a": 3}])

        assert len(outcomes) == 3
        assert all(o.accepted for o in outcomes)
        assert stream_adapter.produce.await_count == 3

    @pytest.mark.asyncio
    async def test_duplicate_event_is_not_produced(
        self, service: CollectorIngestService, stream_adapter: AsyncMock, dedup_checker: AsyncMock
    ) -> None:
        dedup_checker.is_duplicate.return_value = True
        identity = _identity()

        outcomes = await service.ingest_events(identity, [{"a": 1}])

        assert outcomes[0].duplicate is True
        assert outcomes[0].accepted is False
        assert outcomes[0].message_id is None
        stream_adapter.produce.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_identical_events_hash_identically_regardless_of_key_order(
        self, service: CollectorIngestService, dedup_checker: AsyncMock
    ) -> None:
        identity = _identity()
        await service.ingest_events(identity, [{"a": 1, "b": 2}])
        await service.ingest_events(identity, [{"b": 2, "a": 1}])

        hash1 = dedup_checker.is_duplicate.await_args_list[0][0][2]
        hash2 = dedup_checker.is_duplicate.await_args_list[1][0][2]
        assert hash1 == hash2

    @pytest.mark.asyncio
    async def test_backpressure_raised_when_stream_at_capacity(
        self, service: CollectorIngestService, stream_adapter: AsyncMock
    ) -> None:
        stream_adapter.approximate_length.return_value = 100
        identity = _identity()

        with pytest.raises(BackpressureError):
            await service.ingest_events(identity, [{"a": 1}])
        stream_adapter.produce.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_backpressure_check_happens_before_any_event_is_processed(
        self, service: CollectorIngestService, stream_adapter: AsyncMock, dedup_checker: AsyncMock
    ) -> None:
        """A saturated stream rejects the WHOLE batch up front, not partially."""
        stream_adapter.approximate_length.return_value = 100
        identity = _identity()

        with pytest.raises(BackpressureError):
            await service.ingest_events(identity, [{"a": 1}, {"a": 2}, {"a": 3}])
        dedup_checker.is_duplicate.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_two_different_orgs_are_independent(
        self, service: CollectorIngestService, stream_adapter: AsyncMock
    ) -> None:
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        await service.ingest_events(_identity(org_a), [{"a": 1}])
        await service.ingest_events(_identity(org_b), [{"a": 1}])

        orgs_used = {call[0][0] for call in stream_adapter.produce.await_args_list}
        assert orgs_used == {org_a, org_b}
