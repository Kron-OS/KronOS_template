"""ParsingOrchestrationService: selects parser, queues task, executes parse."""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections.abc import AsyncGenerator, AsyncIterator
from typing import TYPE_CHECKING

from src.adapter.queue.task_queue import TaskQueue
from src.adapter.repository.evidence import EvidenceRepository
from src.adapter.storage.storage import EvidenceStorage
from src.application.audit_log import AuditLogService
from src.application.parser_registry import ParserRegistry
from src.application.parsing import ForensicParser, ParserType
from src.domain.audit import AuditEventType
from src.domain.evidence import Evidence, EvidenceState
from src.domain.timeline import TimelineRecord
from src.domain.user import TenantContext
from src.exceptions import (
    EvidenceStateConflictError,
    ParsingError,
    StorageError,
    ValidationError,
)

if TYPE_CHECKING:
    from src.application.timeline_ingest import TimelineIngestionService

logger = logging.getLogger(__name__)

# Bytes read from evidence object for parser detection.
_HEADER_BYTES = 8192


def _make_document_id(evidence_id: uuid.UUID, parser_name: str, record_index: int) -> str:
    """Deterministic SHA-1 id for idempotent OpenSearch ingestion."""
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
        timeline_ingest: TimelineIngestionService | None = None,
    ) -> None:
        self._repo = evidence_repository
        self._storage = storage
        self._audit = audit_log
        self._registry = parser_registry
        self._task_queue = task_queue
        self._timeline_ingest = timeline_ingest

    async def start_parsing(
        self,
        evidence_id: uuid.UUID,
        tenant: TenantContext,
    ) -> Evidence:
        """Transition RECEIVED evidence to PARSING and enqueue the parse task.

        Steps:
          1. Load evidence; assert state == RECEIVED.
          2. Read first 8 KB from storage for parser detection.
          3. Identify parser via registry; on failure (including "no parser
             found"), transition evidence -> ERROR, log PARSE_FAILED, re-raise.
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
            raise EvidenceStateConflictError(
                f"Evidence is in state {evidence.state.value}, expected RECEIVED",
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
        except ParsingError as exc:
            # dispatch_parse (celery_app.py) has no exception handling of its
            # own — without this, a detection failure (unsupported format,
            # content that doesn't match any registered parser) left the
            # evidence stuck in RECEIVED forever: the Celery task crashed and
            # got logged, but nothing ever recorded the failure against the
            # evidence itself, so the UI just showed it "processing" with no
            # indication anything went wrong.
            evidence = evidence.with_error("no_parser_found")
            await self._repo.update(evidence)
            await self._audit.log(
                AuditEventType.PARSE_FAILED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                evidence_id=evidence.evidence_id,
                details={"error": str(exc), "error_type": "ParsingError"},
            )
            raise

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
        *,
        is_final_attempt: bool = True,
    ) -> int:
        """Run the full parse; called by the Celery worker.

        Steps:
          1. Load evidence; assert state == PARSING.
          2. Detect parser from storage header.
          3. Stream object; feed annotated records to timeline ingest (if wired).
          4. On success: transition → COMPLETE; log PARSE_COMPLETED with record_count.
          5. On exception: if is_final_attempt, transition → ERROR and log
             PARSE_FAILED; otherwise leave evidence in PARSING so a Celery
             retry's own PARSING-state precondition still holds. Re-raise either way.
          6. Return total record count.

        is_final_attempt defaults to True so direct/manual callers (tests, the
        admin recovery route) keep the original fail-fast-to-ERROR behaviour.
        parse_artefact_fast/heavy (celery_app.py) pass whether this is the
        last retry the task will get, computed from Celery's own retry
        counters — see their docstring-adjacent comment for why this matters.
        """
        evidence = await self._repo.get_by_id(evidence_id, tenant.org_id)
        if evidence is None:
            raise ParsingError(
                "Evidence not found",
                context={"evidence_id": str(evidence_id)},
            )
        if evidence.state != EvidenceState.PARSING:
            raise EvidenceStateConflictError(
                f"Evidence is in state {evidence.state.value}, expected PARSING",
                context={"evidence_id": str(evidence_id), "state": evidence.state.value},
            )

        tenant = self._reconcile_tenant_alias(tenant, evidence)

        evidence_key = evidence.minio_evidence_key
        if not evidence_key:
            raise ParsingError(
                "Evidence has no storage key",
                context={"evidence_id": str(evidence_id)},
            )

        try:
            parser = await self._detect_parser(evidence, evidence_key)
            stream = await self._storage.stream_object(evidence_key, bucket="evidence")
            annotated = _annotate_records(
                parser.parse(stream, evidence, tenant),
                evidence_id,
                parser.parser_name,
                tenant.org_alias,
            )

            if self._timeline_ingest is not None:
                count = await self._timeline_ingest.ingest_records(annotated, tenant, evidence_id)
            else:
                count = 0
                async for _ in annotated:
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

        except StorageError as exc:
            # Ingest failure: INGEST_FAILED already logged by TimelineIngestionService.
            if is_final_attempt:
                # Transition evidence to ERROR and log at orchestration level, then
                # re-raise as StorageError (not ParsingError) to preserve the
                # correct error category.
                evidence = evidence.with_error("ingest_failed")
                await self._repo.update(evidence)
                await self._audit.log(
                    AuditEventType.PARSE_FAILED,
                    org_id=tenant.org_id,
                    actor_user_id=tenant.user_id,
                    evidence_id=evidence.evidence_id,
                    details={"error": str(exc), "error_type": "StorageError"},
                )
            else:
                # A Celery retry is coming: marking ERROR here (a terminal FSM
                # state) would make that retry's own PARSING-state precondition
                # fail immediately with a confusing EvidenceStateConflictError,
                # masking whatever transient condition (e.g. a not-yet-ready
                # OpenSearch cluster returning 503 right after stack startup)
                # actually caused this attempt to fail. Leave evidence in
                # PARSING and let the retry try again.
                logger.warning(
                    "parse_failed_will_retry",
                    extra={"evidence_id": str(evidence_id), "error": str(exc)},
                )
            raise
        except (ParsingError, ValidationError):
            raise
        except Exception as exc:
            if is_final_attempt:
                evidence = evidence.with_error("parse_failed")
                await self._repo.update(evidence)
                await self._audit.log(
                    AuditEventType.PARSE_FAILED,
                    org_id=tenant.org_id,
                    actor_user_id=tenant.user_id,
                    evidence_id=evidence.evidence_id,
                    details={"error": str(exc), "error_type": type(exc).__name__},
                )
            else:
                logger.warning(
                    "parse_failed_will_retry",
                    extra={
                        "evidence_id": str(evidence_id),
                        "error": str(exc),
                        "error_type": type(exc).__name__,
                    },
                )
            raise ParsingError(
                f"Parse failed: {exc}",
                context={"evidence_id": str(evidence_id)},
            ) from exc

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _reconcile_tenant_alias(tenant: TenantContext, evidence: Evidence) -> TenantContext:
        """Return a tenant whose org_alias matches the evidence's own metadata.

        The Celery parse tasks rebuild a minimal TenantContext from the task
        payload, which only carries org_id + user_id, so they fill org_alias
        with a placeholder ("system"). But org_alias is what routes every
        timeline record to its per-tenant index (kronos-<org>-case-...) and
        names the per-tenant OpenSearch DLS role — using the placeholder made
        *all* parsed evidence, for every org, land in a single
        kronos-system-case-* index and provisioned a "system" role the real
        tenant's index pattern (kronos-<org>-*) would never match.

        The authoritative alias is the immutable one captured on the evidence
        at upload time from the uploader's organization. get_by_id() already
        loaded this evidence scoped to tenant.org_id, so the org matches and
        this reconciliation cannot cross a tenant boundary — it only repairs
        the human-readable alias the task couldn't carry.
        """
        if tenant.org_alias == evidence.metadata.org_alias:
            return tenant
        return tenant.model_copy(update={"org_alias": evidence.metadata.org_alias})

    async def _detect_parser(self, evidence: Evidence, evidence_key: str) -> ForensicParser:
        """Read the first 8 KB and return the matching parser."""
        header = b""
        async for chunk in await self._storage.stream_object(evidence_key, bucket="evidence"):
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


async def _annotate_records(
    source: AsyncIterator[TimelineRecord],
    evidence_id: uuid.UUID,
    parser_name: str,
    org_alias: str,
) -> AsyncGenerator[TimelineRecord, None]:
    """Wrap a parser's output stream, assigning deterministic document_id and org_alias."""
    count = 0
    async for record in source:
        doc_id = _make_document_id(evidence_id, parser_name, count)
        updated_kronos = record.kronos.model_copy(update={"org_alias": org_alias})
        yield record.model_copy(update={"document_id": doc_id, "kronos": updated_kronos})
        count += 1
