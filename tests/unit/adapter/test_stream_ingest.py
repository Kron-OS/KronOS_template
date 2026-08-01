"""Unit tests for StreamIngestAdapter implementations.

RedisStreamIngestAdapter's real behavior (consumer groups, at-least-once
redelivery via XAUTOCLAIM, cross-org structural isolation, no shared
bottleneck, MAXLEN retention) is verified for real against the live Redis
7.4.9 cluster in poc/stream_ingest_redis/ (22/22 checks) -- these tests
mock only the redis client itself, covering this class's own call-shape
contract, per CLAUDE.md SS B.5.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock

import pytest
from redis.exceptions import ResponseError

from src.adapter.queue.stream_ingest import (
    ConsumerGroupHealth,
    InMemoryStreamIngestAdapter,
    RedisStreamIngestAdapter,
    StreamMessage,
)


class TestRedisStreamIngestAdapterProduce:
    @pytest.mark.asyncio
    async def test_produce_calls_xadd_with_the_per_org_source_key(self) -> None:
        redis = AsyncMock()
        redis.xadd.return_value = b"123-0"
        adapter = RedisStreamIngestAdapter(redis)
        org = uuid.uuid4()

        message_id = await adapter.produce(org, "zeek-conn", b"payload-bytes")

        redis.xadd.assert_awaited_once_with(f"kronos:stream:{org}:zeek-conn", {b"payload": b"payload-bytes"})
        assert message_id == "123-0"


class TestRedisStreamIngestAdapterEnsureConsumerGroup:
    @pytest.mark.asyncio
    async def test_creates_group_with_mkstream(self) -> None:
        redis = AsyncMock()
        adapter = RedisStreamIngestAdapter(redis)
        org = uuid.uuid4()

        await adapter.ensure_consumer_group(org, "zeek-conn", "ingest-cg", start="0")

        redis.xgroup_create.assert_awaited_once_with(
            f"kronos:stream:{org}:zeek-conn", "ingest-cg", id="0", mkstream=True
        )

    @pytest.mark.asyncio
    async def test_idempotent_swallows_busygroup(self) -> None:
        redis = AsyncMock()
        redis.xgroup_create.side_effect = ResponseError("BUSYGROUP Consumer Group name already exists")
        adapter = RedisStreamIngestAdapter(redis)

        await adapter.ensure_consumer_group(uuid.uuid4(), "zeek-conn", "ingest-cg")  # must not raise

    @pytest.mark.asyncio
    async def test_reraises_non_busygroup_errors(self) -> None:
        redis = AsyncMock()
        redis.xgroup_create.side_effect = ResponseError("some other real error")
        adapter = RedisStreamIngestAdapter(redis)

        with pytest.raises(ResponseError):
            await adapter.ensure_consumer_group(uuid.uuid4(), "zeek-conn", "ingest-cg")


class TestRedisStreamIngestAdapterConsume:
    @pytest.mark.asyncio
    async def test_returns_stream_messages_from_the_real_xreadgroup_shape(self) -> None:
        redis = AsyncMock()
        org = uuid.uuid4()
        key = f"kronos:stream:{org}:zeek-conn".encode()
        redis.xreadgroup.return_value = [
            (key, [(b"1-0", {b"payload": b"a"}), (b"1-1", {b"payload": b"b"})])
        ]
        adapter = RedisStreamIngestAdapter(redis)

        messages = await adapter.consume(org, "zeek-conn", "cg", "consumer-1", count=5, block_ms=100)

        redis.xreadgroup.assert_awaited_once_with(
            "cg", "consumer-1", {f"kronos:stream:{org}:zeek-conn": ">"}, count=5, block=100
        )
        assert messages == [
            StreamMessage(message_id="1-0", payload=b"a"),
            StreamMessage(message_id="1-1", payload=b"b"),
        ]

    @pytest.mark.asyncio
    async def test_empty_response_returns_empty_list(self) -> None:
        redis = AsyncMock()
        redis.xreadgroup.return_value = None
        adapter = RedisStreamIngestAdapter(redis)

        messages = await adapter.consume(uuid.uuid4(), "zeek-conn", "cg", "consumer-1")

        assert messages == []


class TestRedisStreamIngestAdapterAck:
    @pytest.mark.asyncio
    async def test_acks_the_given_ids(self) -> None:
        redis = AsyncMock()
        adapter = RedisStreamIngestAdapter(redis)
        org = uuid.uuid4()

        await adapter.ack(org, "zeek-conn", "cg", "1-0", "1-1")

        redis.xack.assert_awaited_once_with(f"kronos:stream:{org}:zeek-conn", "cg", "1-0", "1-1")

    @pytest.mark.asyncio
    async def test_no_ids_is_a_noop(self) -> None:
        redis = AsyncMock()
        adapter = RedisStreamIngestAdapter(redis)

        await adapter.ack(uuid.uuid4(), "zeek-conn", "cg")

        redis.xack.assert_not_awaited()


class TestRedisStreamIngestAdapterReclaimStale:
    @pytest.mark.asyncio
    async def test_reclaims_via_xautoclaim_and_returns_stream_messages(self) -> None:
        redis = AsyncMock()
        redis.xautoclaim.return_value = ("0-0", [(b"1-0", {b"payload": b"stuck"})], [])
        adapter = RedisStreamIngestAdapter(redis)
        org = uuid.uuid4()

        reclaimed = await adapter.reclaim_stale(org, "zeek-conn", "cg", "consumer-2", min_idle_ms=30000)

        redis.xautoclaim.assert_awaited_once_with(
            f"kronos:stream:{org}:zeek-conn", "cg", "consumer-2", min_idle_time=30000, start_id="0-0"
        )
        assert reclaimed == [StreamMessage(message_id="1-0", payload=b"stuck")]


class TestRedisStreamIngestAdapterEarliestMessageId:
    @pytest.mark.asyncio
    async def test_returns_the_oldest_retained_entry_id(self) -> None:
        redis = AsyncMock()
        org = uuid.uuid4()
        redis.xrange.return_value = [(b"5-0", {b"payload": b"oldest"})]
        adapter = RedisStreamIngestAdapter(redis)

        earliest = await adapter.earliest_message_id(org, "zeek-conn")

        redis.xrange.assert_awaited_once_with(
            f"kronos:stream:{org}:zeek-conn", min="-", max="+", count=1
        )
        assert earliest == "5-0"

    @pytest.mark.asyncio
    async def test_empty_stream_returns_none(self) -> None:
        redis = AsyncMock()
        redis.xrange.return_value = []
        adapter = RedisStreamIngestAdapter(redis)

        assert await adapter.earliest_message_id(uuid.uuid4(), "zeek-conn") is None


class TestRedisStreamIngestAdapterConsumerGroupHealth:
    @pytest.mark.asyncio
    async def test_returns_pending_and_lag_from_the_real_xpending_xinfo_shapes(self) -> None:
        redis = AsyncMock()
        org = uuid.uuid4()
        redis.xpending.return_value = {
            "pending": 3,
            "min": b"1-0",
            "max": b"1-2",
            "consumers": [{"name": b"consumer-1", "pending": 3}],
        }
        redis.xinfo_groups.return_value = [
            {
                "name": "cg",
                "consumers": 1,
                "pending": 3,
                "last-delivered-id": b"1-2",
                "entries-read": 3,
                "lag": 2,
            }
        ]
        adapter = RedisStreamIngestAdapter(redis)

        health = await adapter.consumer_group_health(org, "zeek-conn", "cg")

        redis.xpending.assert_awaited_once_with(f"kronos:stream:{org}:zeek-conn", "cg")
        redis.xinfo_groups.assert_awaited_once_with(f"kronos:stream:{org}:zeek-conn")
        assert health == ConsumerGroupHealth(
            pending_count=3,
            min_pending_id="1-0",
            max_pending_id="1-2",
            consumer_pending_counts={"consumer-1": 3},
            lag=2,
        )

    @pytest.mark.asyncio
    async def test_nogroup_error_returns_none_lag_health_not_raised(self) -> None:
        redis = AsyncMock()
        redis.xpending.side_effect = ResponseError(
            "NOGROUP No such key 'kronos:stream:x:y' or consumer group 'cg'"
        )
        adapter = RedisStreamIngestAdapter(redis)

        health = await adapter.consumer_group_health(uuid.uuid4(), "zeek-conn", "cg")

        assert health == ConsumerGroupHealth(
            pending_count=0, min_pending_id=None, max_pending_id=None,
            consumer_pending_counts={}, lag=None,
        )
        redis.xinfo_groups.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_non_nogroup_xpending_error_is_reraised(self) -> None:
        redis = AsyncMock()
        redis.xpending.side_effect = ResponseError("some other real error")
        adapter = RedisStreamIngestAdapter(redis)

        with pytest.raises(ResponseError):
            await adapter.consumer_group_health(uuid.uuid4(), "zeek-conn", "cg")

    @pytest.mark.asyncio
    async def test_zero_pending_still_reports_real_lag(self) -> None:
        redis = AsyncMock()
        redis.xpending.return_value = {"pending": 0, "min": None, "max": None, "consumers": []}
        redis.xinfo_groups.return_value = [
            {"name": "cg", "consumers": 1, "pending": 0, "last-delivered-id": b"0-0",
             "entries-read": 0, "lag": 5}
        ]
        adapter = RedisStreamIngestAdapter(redis)

        health = await adapter.consumer_group_health(uuid.uuid4(), "zeek-conn", "cg")

        assert health.pending_count == 0
        assert health.lag == 5


class TestInMemoryStreamIngestAdapterContract:
    """The in-memory double must satisfy the same ABC contract callers rely on."""

    @pytest.mark.asyncio
    async def test_produce_then_consume_round_trips(self) -> None:
        adapter = InMemoryStreamIngestAdapter()
        org = uuid.uuid4()
        await adapter.produce(org, "src", b"one")
        await adapter.produce(org, "src", b"two")
        await adapter.ensure_consumer_group(org, "src", "cg", start="0")

        messages = await adapter.consume(org, "src", "cg", "c1")

        assert [m.payload for m in messages] == [b"one", b"two"]

    @pytest.mark.asyncio
    async def test_two_orgs_never_share_data_even_with_the_same_source_id(self) -> None:
        adapter = InMemoryStreamIngestAdapter()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        await adapter.produce(org_a, "same-source", b"org-a-data")
        await adapter.produce(org_b, "same-source", b"org-b-data")
        await adapter.ensure_consumer_group(org_a, "same-source", "cg", start="0")
        await adapter.ensure_consumer_group(org_b, "same-source", "cg", start="0")

        a_messages = await adapter.consume(org_a, "same-source", "cg", "c1")
        b_messages = await adapter.consume(org_b, "same-source", "cg", "c1")

        assert [m.payload for m in a_messages] == [b"org-a-data"]
        assert [m.payload for m in b_messages] == [b"org-b-data"]

    @pytest.mark.asyncio
    async def test_consuming_without_a_group_raises(self) -> None:
        adapter = InMemoryStreamIngestAdapter()
        with pytest.raises(KeyError):
            await adapter.consume(uuid.uuid4(), "src", "never-created", "c1")

    @pytest.mark.asyncio
    async def test_consumer_group_cursor_advances_across_calls(self) -> None:
        adapter = InMemoryStreamIngestAdapter()
        org = uuid.uuid4()
        await adapter.produce(org, "src", b"one")
        await adapter.ensure_consumer_group(org, "src", "cg", start="0")
        await adapter.consume(org, "src", "cg", "c1", count=1)
        await adapter.produce(org, "src", b"two")

        messages = await adapter.consume(org, "src", "cg", "c1", count=10)

        assert [m.payload for m in messages] == [b"two"]

    @pytest.mark.asyncio
    async def test_earliest_message_id_returns_oldest_and_none_when_empty(self) -> None:
        adapter = InMemoryStreamIngestAdapter()
        org = uuid.uuid4()

        assert await adapter.earliest_message_id(org, "src") is None

        await adapter.produce(org, "src", b"one")
        await adapter.produce(org, "src", b"two")

        earliest = await adapter.earliest_message_id(org, "src")
        assert earliest == "1-0"

    @pytest.mark.asyncio
    async def test_consumer_group_health_reports_lag_via_the_shared_cursor(self) -> None:
        adapter = InMemoryStreamIngestAdapter()
        org = uuid.uuid4()

        # No group ever created for this (org, source) -> lag=None, not 0.
        never = await adapter.consumer_group_health(org, "src", "cg")
        assert never == ConsumerGroupHealth(
            pending_count=0, min_pending_id=None, max_pending_id=None,
            consumer_pending_counts={}, lag=None,
        )

        await adapter.produce(org, "src", b"one")
        await adapter.produce(org, "src", b"two")
        await adapter.produce(org, "src", b"three")
        await adapter.ensure_consumer_group(org, "src", "cg", start="0")
        await adapter.consume(org, "src", "cg", "c1", count=1)  # reads only "one"

        health = await adapter.consumer_group_health(org, "src", "cg")

        # This double never simulates a pending-entries-list (documented
        # gap, matches ack()/reclaim_stale()) -- pending_count stays 0 --
        # but lag is real: 2 entries ("two", "three") never delivered yet.
        assert health.pending_count == 0
        assert health.lag == 2
