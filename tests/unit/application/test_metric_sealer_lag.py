"""Unit tests for SealerLagCalculator (roadmap M8/I2)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from src.adapter.queue.stream_ingest import InMemoryStreamIngestAdapter
from src.adapter.repository.sealed_batch import InMemorySealedBatchRepository
from src.application.metric_sealer_lag import SealerLagCalculator
from src.domain.sealed_batch import SealedBatch
from tests.fixtures.factories import make_tenant_context


def _batch(org_id: uuid.UUID, source_id: str) -> SealedBatch:
    return SealedBatch(
        org_id=org_id,
        source_id=source_id,
        sealed_at=datetime.now(UTC),
        event_count=1,
        leaf_hashes=("a" * 64,),
        message_ids=("1-0",),
        merkle_root="b" * 64,
        worm_bucket="bucket",
        worm_object_key="key.json",
        first_message_id="1-0",
        last_message_id="1-0",
    )


class TestSealerLagCalculator:
    @pytest.mark.asyncio
    async def test_org_with_no_sealed_batches_reports_unavailable(self) -> None:
        calc = SealerLagCalculator(InMemorySealedBatchRepository(), InMemoryStreamIngestAdapter())
        result = await calc.compute(make_tenant_context())

        assert result.value is None
        assert "never sealed a batch" in result.unavailable_reason

    @pytest.mark.asyncio
    async def test_no_live_consumer_group_reports_unavailable_with_staleness_detail(self) -> None:
        tenant = make_tenant_context()
        sealed_batches = InMemorySealedBatchRepository()
        await sealed_batches.save(_batch(tenant.org_id, "zeek-conn"))
        stream = InMemoryStreamIngestAdapter()  # never produced/consumed -- no live group

        result = await SealerLagCalculator(sealed_batches, stream).compute(tenant)

        assert result.value is None
        assert "No live Redis consumer group" in result.unavailable_reason
        assert result.detail["per_source"]["zeek-conn"]["live_group_found"] is False

    @pytest.mark.asyncio
    async def test_live_group_with_undelivered_lag_is_surfaced_not_hidden(self) -> None:
        """Regression test for a real bug caught while building this: an
        earlier draft summed only pending_count (delivered-but-unacked) and
        would report 0.0 here even though 3 real messages are sitting
        unconsumed in the stream (the "lag" failure mode -- no sealer
        running at all -- see ConsumerGroupHealth's own docstring)."""
        tenant = make_tenant_context()
        sealed_batches = InMemorySealedBatchRepository()
        await sealed_batches.save(_batch(tenant.org_id, "zeek-conn"))
        stream = InMemoryStreamIngestAdapter()
        await stream.ensure_consumer_group(tenant.org_id, "zeek-conn", "kronos-sealer", start="0")
        for i in range(3):
            await stream.produce(tenant.org_id, "zeek-conn", f"event-{i}".encode())
        # Deliberately never call consume() -- these 3 messages were never
        # delivered to any consumer of the group at all.

        result = await SealerLagCalculator(sealed_batches, stream).compute(tenant)

        assert result.value == 3.0
        assert result.detail["per_source"]["zeek-conn"]["lag"] == 3
        assert result.detail["per_source"]["zeek-conn"]["backlog"] == 3

    @pytest.mark.asyncio
    async def test_scoped_to_tenant_org_never_leaks_other_org_data(self) -> None:
        tenant_a = make_tenant_context()
        tenant_b = make_tenant_context()
        sealed_batches = InMemorySealedBatchRepository()
        await sealed_batches.save(_batch(tenant_b.org_id, "zeek-conn"))

        result = await SealerLagCalculator(sealed_batches, InMemoryStreamIngestAdapter()).compute(
            tenant_a
        )

        assert result.value is None
        assert "never sealed a batch" in result.unavailable_reason
