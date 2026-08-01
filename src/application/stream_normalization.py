"""StreamNormalizationService: normalizes one sealed stream batch's raw
events into ECS ``TimelineRecord``s and indexes them into OpenSearch
(roadmap M3/D4).

Real input is a ``SealedBatch`` (D3), never the raw pre-seal stream:
``StreamProvenance.batch_id`` (``src/domain/stream.py``) is a required field
with no default, so a ``TimelineRecord`` tagged with stream provenance
cannot be constructed until that event's batch has actually been sealed.
This service's whole job is therefore: fetch an already-sealed batch's WORM
manifest (``SealedBatchStorage.get_batch``), decode each event's raw
payload, run it through the ``StreamSourceNormalizer`` registered for that
batch's ``source_id`` (``src/application/stream_source_registry.py``), build
one ``TimelineRecord`` per event with ``StreamProvenance(batch_id=<this
batch>, event_offset=<its index in the batch>)``, and bulk-index all of them
via ``TimelineIngestionService.ingest_stream_records`` -- no bulk-indexing,
ISM-attachment, or partial-failure-checking logic is reimplemented here (see
that method's own docstring for why it is a sibling of ``ingest_records``,
not a rewrite).

Deliberately does not schedule itself: no Celery beat task, no
trigger-on-seal wiring, mirroring D3's own explicit scope note (sealing
itself isn't scheduled yet either). Proving the mechanism produces correct
ECS documents when invoked is this item's job; automatic invocation is
D5/D6's.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

from src.adapter.repository.sealed_batch import SealedBatchRepository
from src.adapter.storage.sealed_batch_storage import SealedBatchStorage
from src.application.stream_source_registry import StreamSourceNormalizerRegistry
from src.application.timeline_ingest import TimelineIngestionService
from src.domain.stream import StreamProvenance
from src.domain.timeline import TimelineRecord
from src.exceptions import ParsingError, ValidationError

logger = logging.getLogger(__name__)


class StreamNormalizationService:
    """Normalizes and indexes every event of one sealed batch into OpenSearch."""

    def __init__(
        self,
        sealed_batch_repository: SealedBatchRepository,
        sealed_batch_storage: SealedBatchStorage,
        ingestion: TimelineIngestionService,
        normalizer_registry: StreamSourceNormalizerRegistry,
    ) -> None:
        self._repository = sealed_batch_repository
        self._storage = sealed_batch_storage
        self._ingestion = ingestion
        self._registry = normalizer_registry

    async def normalize_batch(self, org_id: uuid.UUID, batch_id: uuid.UUID, org_alias: str) -> int:
        """Normalize and index every event in one sealed batch.

        Returns the number of records indexed.

        Raises:
            ValidationError: if no ``SealedBatch`` with this id exists for org_id.
            ParsingError: if no normalizer is registered for the batch's
                source_id, or the batch's WORM manifest is malformed.
        """
        batch = await self._repository.get_by_id(batch_id, org_id)
        if batch is None:
            raise ValidationError(
                "No sealed batch found for this org_id/batch_id",
                context={"org_id": str(org_id), "batch_id": str(batch_id)},
            )

        normalizer = self._registry.for_source(batch.source_id)
        if normalizer is None:
            raise ParsingError(
                f"No stream normalizer registered for source_id={batch.source_id!r}",
                context={"batch_id": str(batch_id), "source_id": batch.source_id},
            )

        manifest_bytes = await self._storage.get_batch(batch.worm_bucket, batch.worm_object_key)
        try:
            manifest = json.loads(manifest_bytes)
            events = manifest["events"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ParsingError(
                "Sealed batch WORM manifest is malformed",
                context={"batch_id": str(batch_id), "error": str(exc)},
            ) from exc

        logger.info(
            "stream_normalization_started",
            extra={
                "org_id": str(org_id),
                "batch_id": str(batch_id),
                "source_id": batch.source_id,
                "event_count": len(events),
            },
        )

        async def _records() -> AsyncIterator[TimelineRecord]:
            ingest_ts = datetime.now(UTC)
            for offset, event in enumerate(events):
                payload = base64.b64decode(event["payload_base64"])
                normalized = normalizer.normalize(payload)
                yield TimelineRecord(
                    document_id=_stream_document_id(batch_id, offset),
                    timestamp=normalized.timestamp,
                    message=normalized.message,
                    event_kind=normalized.event_kind,
                    event_category=normalized.event_category,
                    event_type=normalized.event_type,
                    event_outcome=normalized.event_outcome,
                    event_original=normalized.event_original,
                    host_name=normalized.host_name,
                    host_os_name=normalized.host_os_name,
                    user_name=normalized.user_name,
                    user_id=normalized.user_id,
                    process_pid=normalized.process_pid,
                    process_name=normalized.process_name,
                    extra=normalized.extra,
                    kronos=StreamProvenance(
                        org_id=org_id,
                        org_alias=org_alias,
                        parser=normalizer.source_id,
                        parser_version=normalizer.normalizer_version,
                        ingest_timestamp=ingest_ts,
                        source_id=batch.source_id,
                        batch_id=batch_id,
                        event_offset=offset,
                    ),
                )

        return await self._ingestion.ingest_stream_records(
            _records(),
            org_id=org_id,
            org_alias=org_alias,
            source_id=batch.source_id,
            batch_id=batch_id,
        )


def _stream_document_id(batch_id: uuid.UUID, event_offset: int) -> str:
    """Deterministic OpenSearch ``_id`` for idempotent re-normalization.

    A sealed batch is immutable (roadmap invariant #5) -- ``batch_id:offset``
    is therefore a stable key for the lifetime of the batch, so re-running
    ``normalize_batch`` on the same batch (e.g. after a partial failure)
    always produces the exact same document ids: true idempotent
    re-indexing, not just "probably won't collide." Computed eagerly here,
    same SHA1-of-a-stable-key convention as
    ``TimelineIngestionService._fallback_id``/``_fallback_stream_id``, rather
    than left to that service's own fallback.
    """
    key = f"{batch_id}:{event_offset}"
    return hashlib.sha1(key.encode()).hexdigest()  # noqa: S324
