"""Unit tests for StreamNormalizationService (roadmap M3/D4).

Mocks only the real external boundaries (SealedBatchStorage/MinIO) --
SealedBatchRepository uses the real InMemorySealedBatchRepository and
TimelineIngestionService uses the real InMemoryOpenSearchClient, same
"mock only external dependencies" precedent as test_batch_sealing.py. The
real, live-dependency version (real Postgres/MinIO/OpenSearch) is in
poc/stream_normalization/.
"""

from __future__ import annotations

import base64
import json
import uuid
from unittest.mock import AsyncMock

import pytest

from src.adapter.opensearch.client import InMemoryOpenSearchClient
from src.adapter.repository.sealed_batch import InMemorySealedBatchRepository
from src.application.audit_log import AuditLogService
from src.application.stream_normalization import StreamNormalizationService
from src.application.stream_source_registry import get_default_stream_normalizer_registry
from src.application.timeline_ingest import TimelineIngestionService
from src.domain.sealed_batch import SealedBatch
from src.domain.stream import StreamProvenance
from src.exceptions import ParsingError, ValidationError
from tests.conftest import InMemoryAuditLogRepository


def _zeek_event(seq: int) -> bytes:
    return json.dumps(
        {
            "ts": 1735689600.0 + seq,
            "id.orig_h": "10.0.0.5",
            "id.orig_p": 50000 + seq,
            "id.resp_h": "93.184.216.34",
            "id.resp_p": 443,
            "proto": "tcp",
        }
    ).encode()


def _manifest_bytes(batch_id: uuid.UUID, org_id: uuid.UUID, source_id: str, events: list[bytes]) -> bytes:
    import hashlib

    doc = {
        "batch_id": str(batch_id),
        "org_id": str(org_id),
        "source_id": source_id,
        "event_count": len(events),
        "events": [
            {
                "message_id": f"{i}-0",
                "leaf_hash": hashlib.sha256(e).hexdigest(),
                "payload_base64": base64.b64encode(e).decode("ascii"),
            }
            for i, e in enumerate(events)
        ],
    }
    return json.dumps(doc).encode()


def _sealed_batch(org_id: uuid.UUID, source_id: str, event_count: int) -> SealedBatch:
    return SealedBatch(
        org_id=org_id,
        source_id=source_id,
        sealed_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
        event_count=event_count,
        leaf_hashes=tuple("a" * 64 for _ in range(event_count)),
        message_ids=tuple(f"{i}-0" for i in range(event_count)),
        merkle_root="b" * 64,
        worm_bucket="kronos-stream-batches-org",
        worm_object_key=f"{source_id}/batch.json",
        first_message_id="0-0",
        last_message_id=f"{event_count - 1}-0",
    )


class TestStreamNormalizationService:
    def _service(self, storage: AsyncMock) -> tuple[StreamNormalizationService, InMemorySealedBatchRepository, InMemoryOpenSearchClient]:
        repo = InMemorySealedBatchRepository()
        os_client = InMemoryOpenSearchClient()
        audit = AuditLogService(InMemoryAuditLogRepository())
        ingestion = TimelineIngestionService(opensearch=os_client, audit_log=audit)
        registry = get_default_stream_normalizer_registry()
        service = StreamNormalizationService(repo, storage, ingestion, registry)
        return service, repo, os_client

    @pytest.mark.asyncio
    async def test_normalizes_and_indexes_every_event_in_a_sealed_batch(self) -> None:
        org_id = uuid.uuid4()
        batch = _sealed_batch(org_id, "zeek-conn-log", event_count=3)
        events = [_zeek_event(i) for i in range(3)]
        storage = AsyncMock()
        storage.get_batch.return_value = _manifest_bytes(batch.batch_id, org_id, "zeek-conn-log", events)

        service, repo, os_client = self._service(storage)
        await repo.save(batch)

        count = await service.normalize_batch(org_id, batch.batch_id, org_alias="acme")

        assert count == 3
        storage.get_batch.assert_awaited_once_with(batch.worm_bucket, batch.worm_object_key)
        all_docs = {
            doc_id: body
            for index in os_client.all_indices()
            for doc_id, body in os_client.get_documents(index).items()
        }
        assert len(all_docs) == 3
        # Real ECS + kronos.* StreamProvenance fields landed in the document.
        sample = next(iter(all_docs.values()))
        assert sample["kronos"]["source_id"] == "zeek-conn-log"
        assert sample["kronos"]["batch_id"] == str(batch.batch_id)
        assert sample["kronos"]["org_id"] == str(org_id)
        assert "source" in sample or "network" in sample  # ECS extra fields present

    @pytest.mark.asyncio
    async def test_event_offset_matches_position_within_batch(self) -> None:
        org_id = uuid.uuid4()
        batch = _sealed_batch(org_id, "zeek-conn-log", event_count=2)
        events = [_zeek_event(i) for i in range(2)]
        storage = AsyncMock()
        storage.get_batch.return_value = _manifest_bytes(batch.batch_id, org_id, "zeek-conn-log", events)
        service, repo, os_client = self._service(storage)
        await repo.save(batch)

        await service.normalize_batch(org_id, batch.batch_id, org_alias="acme")

        offsets = sorted(
            body["kronos"]["event_offset"]
            for index in os_client.all_indices()
            for body in os_client.get_documents(index).values()
        )
        assert offsets == [0, 1]

    @pytest.mark.asyncio
    async def test_unknown_batch_raises_validation_error(self) -> None:
        storage = AsyncMock()
        service, _repo, _os = self._service(storage)

        with pytest.raises(ValidationError):
            await service.normalize_batch(uuid.uuid4(), uuid.uuid4(), org_alias="acme")

    @pytest.mark.asyncio
    async def test_no_normalizer_for_source_raises_parsing_error(self) -> None:
        org_id = uuid.uuid4()
        batch = _sealed_batch(org_id, "unregistered-source", event_count=1)
        storage = AsyncMock()
        service, repo, _os = self._service(storage)
        await repo.save(batch)

        with pytest.raises(ParsingError, match="No stream normalizer registered"):
            await service.normalize_batch(org_id, batch.batch_id, org_alias="acme")
        storage.get_batch.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_malformed_manifest_raises_parsing_error(self) -> None:
        org_id = uuid.uuid4()
        batch = _sealed_batch(org_id, "zeek-conn-log", event_count=1)
        storage = AsyncMock()
        storage.get_batch.return_value = b"not json"
        service, repo, _os = self._service(storage)
        await repo.save(batch)

        with pytest.raises(ParsingError, match="malformed"):
            await service.normalize_batch(org_id, batch.batch_id, org_alias="acme")

    @pytest.mark.asyncio
    async def test_produced_records_carry_stream_provenance(self) -> None:
        org_id = uuid.uuid4()
        batch = _sealed_batch(org_id, "zeek-conn-log", event_count=1)
        events = [_zeek_event(0)]
        storage = AsyncMock()
        storage.get_batch.return_value = _manifest_bytes(batch.batch_id, org_id, "zeek-conn-log", events)

        captured: list = []
        service, repo, os_client = self._service(storage)
        await repo.save(batch)

        # Patch ingest_stream_records to inspect the actual TimelineRecord.kronos type
        original = service._ingestion.ingest_stream_records

        async def _spy(records, **kwargs):  # type: ignore[no-untyped-def]
            async def _tap():
                async for r in records:
                    captured.append(r)
                    yield r

            return await original(_tap(), **kwargs)

        service._ingestion.ingest_stream_records = _spy  # type: ignore[method-assign]

        await service.normalize_batch(org_id, batch.batch_id, org_alias="acme")

        assert len(captured) == 1
        assert isinstance(captured[0].kronos, StreamProvenance)
        assert captured[0].kronos.batch_id == batch.batch_id
        assert captured[0].kronos.event_offset == 0
