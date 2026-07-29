"""ArtifactIngestService: persists StructuredArtifacts, batching writes to Postgres."""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterable

from src.adapter.repository.artifact_repository import ArtifactRepository
from src.application.audit_log import AuditLogService
from src.domain.artifact import StructuredArtifact
from src.domain.audit import AuditEventType
from src.domain.user import TenantContext
from src.exceptions import StorageError, ValidationError

logger = logging.getLogger(__name__)

# A compromised or buggy module could stuff excessive data into the
# intentionally-opaque `content` field; cap it the same way
# ZipArchiveParser caps a single zip member's decompressed size --
# real, enforced, not deferred. Measured on the JSON-serialized size, which
# is what actually lands in Postgres.
_MAX_CONTENT_BYTES = 8 * 1024 * 1024  # 8 MiB per artifact


class ArtifactIngestService:
    """Persists a stream of StructuredArtifact objects, one evidence file at a time."""

    def __init__(self, repository: ArtifactRepository, audit_log: AuditLogService) -> None:
        self._repository = repository
        self._audit = audit_log

    async def ingest_artifacts(
        self,
        artifacts: AsyncIterable[StructuredArtifact],
        tenant: TenantContext,
        evidence_id: uuid.UUID,
    ) -> int:
        """Persist every artifact from *artifacts*. Returns the count saved.

        Emits ARTIFACT_INGEST_STARTED before processing and
        ARTIFACT_INGEST_COMPLETED (or _FAILED) after -- mirrors
        TimelineIngestionService.ingest_records's audit contract. A no-op
        (zero audit events) when the stream is empty, since every existing
        ForensicParser's extract_artifacts() default yields nothing and
        this must not add audit noise to every single parse.
        """
        total = 0
        started_logged = False
        try:
            async for artifact in artifacts:
                if not started_logged:
                    await self._audit.log(
                        AuditEventType.ARTIFACT_INGEST_STARTED,
                        org_id=tenant.org_id,
                        actor_user_id=tenant.user_id,
                        actor_username=tenant.username,
                        evidence_id=evidence_id,
                        details={},
                    )
                    started_logged = True

                _assert_content_size(artifact)
                await self._repository.save(artifact)
                total += 1

        except Exception as exc:
            if started_logged:
                await self._audit.log(
                    AuditEventType.ARTIFACT_INGEST_FAILED,
                    org_id=tenant.org_id,
                    actor_user_id=tenant.user_id,
                    evidence_id=evidence_id,
                    details={"error": str(exc), "error_type": type(exc).__name__},
                )
            if isinstance(exc, StorageError | ValidationError):
                raise
            raise StorageError(
                f"Structured artifact ingestion failed: {exc}",
                context={"evidence_id": str(evidence_id)},
            ) from exc

        if started_logged:
            await self._audit.log(
                AuditEventType.ARTIFACT_INGEST_COMPLETED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                evidence_id=evidence_id,
                details={"artifact_count": total},
            )
            logger.info(
                "artifact_ingest_completed",
                extra={"evidence_id": str(evidence_id), "artifact_count": total},
            )
        return total


def _assert_content_size(artifact: StructuredArtifact) -> None:
    import json  # noqa: PLC0415

    size = len(json.dumps(artifact.content, default=str).encode("utf-8"))
    if size > _MAX_CONTENT_BYTES:
        raise ValidationError(
            "Structured artifact content exceeds maximum size",
            context={
                "artifact_id": str(artifact.artifact_id),
                "kind": artifact.kind,
                "size_bytes": size,
                "limit_bytes": _MAX_CONTENT_BYTES,
            },
        )
