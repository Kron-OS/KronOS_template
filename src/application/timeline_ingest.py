"""TimelineIngestionService: batches TimelineRecords and bulk-indexes to OpenSearch."""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterable
from typing import Any

from src.adapter.opensearch.client import AbstractTimelineIndex
from src.application.audit_log import AuditLogService
from src.application.timeline_normalization import ECSNormalizer, build_index_name
from src.domain.audit import AuditEventType
from src.domain.timeline import TimelineRecord
from src.domain.user import TenantContext
from src.exceptions import StorageError

logger = logging.getLogger(__name__)

_DEFAULT_BATCH_SIZE = 500


class TimelineIngestionService:
    """Batches parsed timeline records and writes them to OpenSearch in bulk.

    Collects records into batches of *batch_size*, grouping each by its target
    index before issuing a single bulk request per flush.  The final (possibly
    partial) batch is always flushed after the iterator is exhausted.
    """

    def __init__(
        self,
        opensearch: AbstractTimelineIndex,
        audit_log: AuditLogService,
        *,
        batch_size: int = _DEFAULT_BATCH_SIZE,
    ) -> None:
        self._opensearch = opensearch
        self._audit = audit_log
        self._batch_size = batch_size
        self._normalizer = ECSNormalizer()

    async def ingest_records(
        self,
        records: AsyncIterable[TimelineRecord],
        tenant: TenantContext,
        evidence_id: uuid.UUID,
    ) -> int:
        """Ingest all records from *records* into OpenSearch.

        Logs INGEST_STARTED before processing and INGEST_COMPLETED (or
        INGEST_FAILED) after.  Returns the total number of indexed records.

        Raises:
            StorageError: if the underlying bulk request fails.
        """
        await self._audit.log(
            AuditEventType.INGEST_STARTED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            actor_username=tenant.username,
            evidence_id=evidence_id,
            details={},
        )

        batch: list[tuple[str, str, dict[str, Any]]] = []
        total = 0

        try:
            async for record in records:
                index = build_index_name(
                    tenant.org_alias,
                    str(record.kronos.case_id),
                    record.timestamp,
                )
                doc_id = record.document_id or _fallback_id(record)
                body = self._normalizer.to_document(record)
                batch.append((index, doc_id, body))

                if len(batch) >= self._batch_size:
                    total += await self._flush(batch)
                    batch = []

            if batch:
                total += await self._flush(batch)

        except Exception as exc:
            await self._audit.log(
                AuditEventType.INGEST_FAILED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                evidence_id=evidence_id,
                details={"error": str(exc), "error_type": type(exc).__name__},
            )
            if not isinstance(exc, StorageError):
                raise StorageError(
                    f"Timeline ingestion failed: {exc}",
                    context={"evidence_id": str(evidence_id)},
                ) from exc
            raise

        await self._audit.log(
            AuditEventType.INGEST_COMPLETED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            evidence_id=evidence_id,
            details={"record_count": total},
        )
        logger.info(
            "ingest_completed",
            extra={"evidence_id": str(evidence_id), "record_count": total},
        )
        return total

    async def _flush(self, batch: list[tuple[str, str, dict[str, Any]]]) -> int:
        count = await self._opensearch.bulk_index(batch)
        logger.debug("ingest_flush", extra={"flushed": count})
        return count


def _fallback_id(record: TimelineRecord) -> str:
    """Generate a deterministic fallback doc ID when document_id is not set."""
    key = f"{record.kronos.evidence_id}:{record.kronos.parser}:{record.kronos.record_index}"
    import hashlib  # noqa: PLC0415

    return hashlib.sha1(key.encode()).hexdigest()  # noqa: S324
