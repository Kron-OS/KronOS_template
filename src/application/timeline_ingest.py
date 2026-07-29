"""TimelineIngestionService: batches TimelineRecords and bulk-indexes to OpenSearch."""

from __future__ import annotations

import logging
import time
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
_FLUSH_INTERVAL_SECONDS = 30


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
        security_enabled: bool = False,
    ) -> None:
        self._opensearch = opensearch
        self._audit = audit_log
        self._batch_size = batch_size
        self._normalizer = ECSNormalizer()
        self._ism_applied = False
        self._template_applied = False
        self._tenant_role_applied = False
        self._security_enabled = security_enabled
        self._security_warned = False

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
        batch: list[tuple[str, str, dict[str, Any]]] = []
        total = 0
        last_flush = time.monotonic()

        try:
            if not self._template_applied:
                # Verified against a real OpenSearch cluster (poc/full_pipeline/):
                # without this, nothing ever calls ensure_index_template(), so
                # every kronos-* index is created by dynamic mapping instead of
                # the ECS template's explicit field types. String fields (e.g.
                # kronos.evidence_id, kronos.org_id) then become "text" +
                # ".keyword" multi-fields instead of pure "keyword", and a term
                # query against the un-suffixed field name (exactly what
                # OpenSearchQueryBuilder.org_id_filter builds) silently matches
                # nothing — not a data leak, but a real, silent functionality
                # break for any exact-match filter, tested and confirmed here.
                await self._opensearch.ensure_index_template()
                self._template_applied = True

            if not self._ism_applied:
                await self._opensearch.ensure_ism_policy()
                self._ism_applied = True

            if not self._tenant_role_applied:
                # Verified in poc/keycloak_opensearch_dls/ (steps 3-4): ONE
                # generic, org-agnostic DLS role + static mapping, created once
                # ever -- not per-org. New orgs/members need zero further calls
                # here; DLS is templated from each caller's own JWT at query time.
                if self._security_enabled:
                    await self._opensearch.ensure_generic_tenant_role()
                elif not self._security_warned:
                    logger.warning("opensearch_security_disabled_skipping_tenant_role")
                    self._security_warned = True
                self._tenant_role_applied = True

            await self._audit.log(
                AuditEventType.INGEST_STARTED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                evidence_id=evidence_id,
                details={},
            )

            async for record in records:
                index = build_index_name(
                    tenant.org_alias,
                    str(record.kronos.case_id),
                    record.timestamp,
                )
                doc_id = record.document_id or _fallback_id(record)
                body = self._normalizer.to_document(record)
                batch.append((index, doc_id, body))

                elapsed = time.monotonic() - last_flush
                if len(batch) >= self._batch_size or elapsed >= _FLUSH_INTERVAL_SECONDS:
                    total += await self._flush(batch)
                    batch = []
                    last_flush = time.monotonic()

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
