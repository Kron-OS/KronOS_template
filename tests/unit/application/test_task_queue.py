"""Unit tests for InMemoryTaskQueue."""

from __future__ import annotations

import uuid

import pytest

from src.adapter.queue.task_queue import InMemoryTaskQueue
from tests.fixtures.factories import make_tenant_context


class TestInMemoryTaskQueue:
    @pytest.mark.asyncio
    async def test_enqueue_fast_records_task(self) -> None:
        queue = InMemoryTaskQueue()
        tenant = make_tenant_context()
        eid = uuid.uuid4()
        await queue.enqueue_parse_fast(eid, tenant)
        assert len(queue.enqueued) == 1
        assert queue.enqueued[0][0] == "fast"
        assert queue.enqueued[0][1] == eid

    @pytest.mark.asyncio
    async def test_enqueue_heavy_records_task(self) -> None:
        queue = InMemoryTaskQueue()
        tenant = make_tenant_context()
        eid = uuid.uuid4()
        await queue.enqueue_parse_heavy(eid, tenant)
        assert len(queue.enqueued) == 1
        assert queue.enqueued[0][0] == "heavy"
        assert queue.enqueued[0][1] == eid

    @pytest.mark.asyncio
    async def test_returns_task_id_string(self) -> None:
        queue = InMemoryTaskQueue()
        tenant = make_tenant_context()
        task_id = await queue.enqueue_parse_fast(uuid.uuid4(), tenant)
        assert isinstance(task_id, str)
        # Should be a valid UUID string.
        uuid.UUID(task_id)  # raises if not valid

    @pytest.mark.asyncio
    async def test_multiple_enqueues_all_recorded(self) -> None:
        queue = InMemoryTaskQueue()
        tenant = make_tenant_context()
        for _ in range(5):
            await queue.enqueue_parse_fast(uuid.uuid4(), tenant)
        assert len(queue.enqueued) == 5
        assert all(entry[0] == "fast" for entry in queue.enqueued)
