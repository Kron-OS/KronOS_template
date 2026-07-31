"""Unit tests for EventDedupChecker implementations."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock

import pytest

from src.adapter.queue.event_dedup import InMemoryEventDedupChecker, RedisEventDedupChecker


class TestRedisEventDedupChecker:
    @pytest.mark.asyncio
    async def test_first_occurrence_is_not_a_duplicate_and_records_it(self) -> None:
        redis = AsyncMock()
        redis.set.return_value = True  # NX succeeded -- newly set
        checker = RedisEventDedupChecker(redis)
        org = uuid.uuid4()

        is_dup = await checker.is_duplicate(org, "src", "hash123", ttl_seconds=60)

        assert is_dup is False
        redis.set.assert_awaited_once_with(f"kronos:dedup:{org}:src:hash123", "1", nx=True, ex=60)

    @pytest.mark.asyncio
    async def test_second_occurrence_within_ttl_is_a_duplicate(self) -> None:
        redis = AsyncMock()
        redis.set.return_value = None  # NX failed -- already exists
        checker = RedisEventDedupChecker(redis)

        is_dup = await checker.is_duplicate(uuid.uuid4(), "src", "hash123", ttl_seconds=60)

        assert is_dup is True

    @pytest.mark.asyncio
    async def test_different_orgs_have_independent_dedup_keys(self) -> None:
        redis = AsyncMock()
        redis.set.return_value = True
        checker = RedisEventDedupChecker(redis)
        org_a, org_b = uuid.uuid4(), uuid.uuid4()

        await checker.is_duplicate(org_a, "src", "same-hash", ttl_seconds=60)
        await checker.is_duplicate(org_b, "src", "same-hash", ttl_seconds=60)

        keys_used = {call.args[0] for call in redis.set.await_args_list}
        assert keys_used == {f"kronos:dedup:{org_a}:src:same-hash", f"kronos:dedup:{org_b}:src:same-hash"}


class TestInMemoryEventDedupChecker:
    @pytest.mark.asyncio
    async def test_first_occurrence_is_not_a_duplicate(self) -> None:
        checker = InMemoryEventDedupChecker()
        assert await checker.is_duplicate(uuid.uuid4(), "src", "hash1", ttl_seconds=60) is False

    @pytest.mark.asyncio
    async def test_second_occurrence_is_a_duplicate(self) -> None:
        checker = InMemoryEventDedupChecker()
        org = uuid.uuid4()
        await checker.is_duplicate(org, "src", "hash1", ttl_seconds=60)
        assert await checker.is_duplicate(org, "src", "hash1", ttl_seconds=60) is True

    @pytest.mark.asyncio
    async def test_different_source_ids_are_independent(self) -> None:
        checker = InMemoryEventDedupChecker()
        org = uuid.uuid4()
        await checker.is_duplicate(org, "src-a", "hash1", ttl_seconds=60)
        assert await checker.is_duplicate(org, "src-b", "hash1", ttl_seconds=60) is False
