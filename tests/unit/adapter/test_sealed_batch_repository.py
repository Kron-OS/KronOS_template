"""Unit tests for InMemorySealedBatchRepository (roadmap M3/D3)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from src.adapter.repository.sealed_batch import InMemorySealedBatchRepository
from src.domain.sealed_batch import SealedBatch


def _batch(org_id: uuid.UUID, source_id: str, sealed_at: datetime, last_message_id: str) -> SealedBatch:
    return SealedBatch(
        org_id=org_id,
        source_id=source_id,
        sealed_at=sealed_at,
        event_count=1,
        leaf_hashes=("a" * 64,),
        message_ids=(last_message_id,),
        merkle_root="b" * 64,
        worm_bucket="bucket",
        worm_object_key="key.json",
        first_message_id=last_message_id,
        last_message_id=last_message_id,
    )


class TestInMemorySealedBatchRepository:
    @pytest.mark.asyncio
    async def test_save_then_get_by_id(self) -> None:
        repo = InMemorySealedBatchRepository()
        org_id = uuid.uuid4()
        batch = _batch(org_id, "src", datetime.now(UTC), "1-0")

        await repo.save(batch)

        assert await repo.get_by_id(batch.batch_id, org_id) == batch

    @pytest.mark.asyncio
    async def test_get_by_id_scoped_to_org(self) -> None:
        repo = InMemorySealedBatchRepository()
        batch = _batch(uuid.uuid4(), "src", datetime.now(UTC), "1-0")
        await repo.save(batch)

        assert await repo.get_by_id(batch.batch_id, uuid.uuid4()) is None

    @pytest.mark.asyncio
    async def test_get_last_sealed_returns_none_when_nothing_sealed(self) -> None:
        repo = InMemorySealedBatchRepository()
        assert await repo.get_last_sealed(uuid.uuid4(), "src") is None

    @pytest.mark.asyncio
    async def test_get_last_sealed_returns_most_recent_by_sealed_at(self) -> None:
        repo = InMemorySealedBatchRepository()
        org_id = uuid.uuid4()
        now = datetime.now(UTC)
        older = _batch(org_id, "src", now - timedelta(minutes=5), "1-0")
        newer = _batch(org_id, "src", now, "2-0")
        await repo.save(older)
        await repo.save(newer)

        result = await repo.get_last_sealed(org_id, "src")
        assert result == newer

    @pytest.mark.asyncio
    async def test_get_last_sealed_scoped_by_source_id(self) -> None:
        repo = InMemorySealedBatchRepository()
        org_id = uuid.uuid4()
        await repo.save(_batch(org_id, "zeek-conn", datetime.now(UTC), "1-0"))

        assert await repo.get_last_sealed(org_id, "other-source") is None
