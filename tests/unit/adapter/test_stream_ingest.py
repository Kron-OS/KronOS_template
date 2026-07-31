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
