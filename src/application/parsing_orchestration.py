"""ParsingOrchestrationService: selects parser, queues task, executes parse."""

from __future__ import annotations

import hashlib
import logging
import uuid

from src.adapter.queue.task_queue import TaskQueue
from src.adapter.repository.evidence import EvidenceRepository
from src.adapter.storage.storage import EvidenceStorage
from src.application.audit_log import AuditLogService
from src.application.parser_registry import ParserRegistry
from src.application.parsing import ForensicParser, ParserType
from src.domain.audit import AuditEventType
from src.domain.evidence import Evidence, EvidenceState
from src.domain.user import TenantContext
from src.exceptions import ParsingError, ValidationError

logger = logging.getLogger(__name__)

# Bytes read from evidence object for parser detection.
_HEADER_BYTES = 8192


def _make_document_id(evidence_id: uuid.UUID, parser_name: str, record_index: int) -> str:
    """Deterministic SHA-1 id for idempotent OpenSearch ingestion (Phase 4)."""
    key = f"{evidence_id}:{parser_name}:{record_index}"
    return hashlib.sha1(key.encode()).hexdigest()  # noqa: S324


class ParsingOrchestrationService:
    """Selects the right parser, queues the Celery task, and executes parsing."""

    def __init__(
        self,
        evidence_repository: EvidenceRepository,
        storage: EvidenceStorage,
        audit_log: AuditLogService,
        parser_registry: ParserRegistry,
        task_queue: TaskQueue,
    ) -> None:
        self._repo = evidence_repository
        self._storage = storage
        self._audit = audit_log
        self._registry = parser_registry
        self._task_queue = task_queue

    async def start_parsing(
        self,
        evidence_id: uuid.UUID,
        tenant: TenantContext,
    ) -> Evidence:
        """Transition RECEIVED evidence to PARSING and enqueue the parse task.

        Steps:
          1. Load evidence; assert state == RECEIVED.
          2. Read first 8 KB from storage for parser detection.
          3. Identify parser via registry; raise ParsingError if none found.
          4. Transition evidence → PARSING; persist.
          5. Log PARSE_STARTED.
          6. Enqueue task (FAST or HEAVY queue).
          7. Return updated evidence.
        """
        evidence = await self._repo.get_by_id(evidence_id, tenant.org_id)
        if evidence is None:
            raise ValidationError(
                "Evidence not found",
                context={"evidence_id": str(evidence_id), "org_id": str(tenant.org_id)},
            )
        if evidence.state != EvidenceState.RECEIVED:
            raise ValidationError(
                f"Evidence is in state {evidence.state.value}, expected RECEIVED",
                context={"evidence_id": str(evidence_id), "state": evidence.state.value},
            )

        evidence_key = evidence.minio_evidence_key
        if not evidence_key:
            raise ParsingError(
                "Evidence has no storage key",
                context={"evidence_id": str(evidence_id)},
            )

        parser = await self._detect_parser(evidence, evidence_key)

        evidence = evidence.with_state(EvidenceState.PARSING)
        await self._repo.update(evidence)
        await self._audit.log(
            AuditEventType.PARSE_STARTED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            actor_username=tenant.username,
            evidence_id=evidence.evidence_id,
            details={"parser": parser.parser_name, "parser_type": parser.parser_type.value},
        )

        if parser.parser_type == ParserType.FAST:
            await self._task_queue.enqueue_parse_fast(evidence_id, tenant)
        else:
            await self._task_queue.enqueue_parse_heavy(evidence_id, tenant)

        logger.info(
            "parse_queued",
            extra={
                "evidence_id": str(evidence_id),
                "parser": parser.parser_name,
                "queue": parser.parser_type.value,
            },
        )
        return evidence

    async def execute_parse(
        self,
        evidence_id: uuid.UUID,
        tenant: TenantContext,
    ) -> int:
        """Run the full parse; called by the Celery worker.

        Steps:
          1. Load evidence; assert state == PARSING.
          2. Detect parser from storage header.
          3. Stream object and feed to parser.parse().
          4. Assign deterministic document_id to each record.
          5. On success: transition → COMPLETE; log PARSE_COMPLETED with record_count.
          6. On exception: transition → ERROR; log PARSE_FAILED; re-raise.
          7. Return total record count.

        Note: records are counted but not forwarded to OpenSearch yet (Phase 4).
        """
        evidence = await self._repo.get_by_id(evidence_id, tenant.org_id)
        if evidence is None:
            raise ParsingError(
                "Evidence not found",
                context={"evidence_id": str(evidence_id)},
            )
        if evidence.state != EvidenceState.PARSING:
            raise ParsingError(
                f"Evidence is in state {evidence.state.value}, expected PARSING",
                context={"evidence_id": str(evidence_id), "state": evidence.state.value},
            )

        evidence_key = evidence.minio_evidence_key
        if not evidence_key:
            raise ParsingError(
                "Evidence has no storage key",
                context={"evidence_id": str(evidence_id)},
            )

        try:
            parser = await self._detect_parser(evidence, evidence_key)
            stream = await self._storage.stream_object(evidence_key)

            count = 0
            async for record in parser.parse(stream, evidence, tenant):
                # Attach deterministic document_id for Phase 4 OpenSearch ingestion.
                doc_id = _make_document_id(evidence_id, parser.parser_name, count)
                record.model_copy(update={"document_id": doc_id})
                count += 1

            evidence = evidence.with_state(EvidenceState.COMPLETE)
            await self._repo.update(evidence)
            await self._audit.log(
                AuditEventType.PARSE_COMPLETED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                evidence_id=evidence.evidence_id,
                details={"parser": parser.parser_name, "record_count": count},
            )
            logger.info(
                "parse_completed",
                extra={"evidence_id": str(evidence_id), "record_count": count},
            )
            return count

        except (ParsingError, ValidationError):
            raise
        except Exception as exc:
            evidence = evidence.with_error("parse_failed")
            await self._repo.update(evidence)
            await self._audit.log(
                AuditEventType.PARSE_FAILED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                evidence_id=evidence.evidence_id,
                details={"error": str(exc), "error_type": type(exc).__name__},
            )
            raise ParsingError(
                f"Parse failed: {exc}",
                context={"evidence_id": str(evidence_id)},
            ) from exc

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _detect_parser(self, evidence: Evidence, evidence_key: str) -> ForensicParser:
        """Read the first 8 KB and return the matching parser."""
        header = b""
        async for chunk in await self._storage.stream_object(evidence_key):
            header += chunk
            if len(header) >= _HEADER_BYTES:
                break
        header = header[:_HEADER_BYTES]

        parser = self._registry.get_parser(
            evidence.metadata.original_filename,
            evidence.metadata.content_type,
            header,
        )
        if parser is None:
            raise ParsingError(
                "No parser found for this evidence file",
                context={
                    "evidence_id": str(evidence.evidence_id),
                    "filename": evidence.metadata.original_filename,
                },
            )
        return parser
