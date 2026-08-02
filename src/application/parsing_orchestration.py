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
from src.application.enrichment import EnrichmentPipeline
from src.application.parser_registry import ParserRegistry
from src.application.parsing import ForensicParser, ParserType
from src.application.yara_rules import yara_scan_org_var
from src.domain.artifact import StructuredArtifact
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
    from src.application.artifact_ingest import ArtifactIngestService
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
        artifact_ingest: ArtifactIngestService | None = None,
        enrichment_pipeline: EnrichmentPipeline | None = None,
    ) -> None:
        self._repo = evidence_repository
        self._storage = storage
        self._audit = audit_log
        self._registry = parser_registry
        self._task_queue = task_queue
        self._timeline_ingest = timeline_ingest
        self._artifact_ingest = artifact_ingest
        # Honestly disabled (roadmap F1) when unset -- no enrichers configured
        # is a valid, real state (matches every other optional collaborator
        # in this codebase), never a fake pass-through pipeline.
        self._enrichment_pipeline = enrichment_pipeline

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

    async def retry_parse(
        self,
        evidence_id: uuid.UUID,
        tenant: TenantContext,
    ) -> Evidence:
        """Re-enter PARSING for ERROR evidence with a retryable parse-stage reason.

        Unlike retry-intake (which re-enters SCANNING and re-validates/
        re-scans/re-hashes the quarantined object), this re-enters PARSING
        directly against the object already promoted to the evidence
        bucket -- no re-upload, no re-scan, since intake already succeeded
        and only parsing/indexing failed. Callers (the route) must already
        have checked is_parse_stage_error_reason + is_retryable_error_reason;
        this method re-derives the parser itself so a stale/incorrect prior
        detection can't wedge a retry loop.
        """
        evidence = await self._repo.get_by_id(evidence_id, tenant.org_id)
        if evidence is None:
            raise ValidationError(
                "Evidence not found",
                context={"evidence_id": str(evidence_id), "org_id": str(tenant.org_id)},
            )
        if evidence.state != EvidenceState.ERROR:
            raise EvidenceStateConflictError(
                f"Evidence is in state {evidence.state.value}, expected ERROR",
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
        await self._repo.update(evidence, expected_state=EvidenceState.ERROR)
        await self._audit.log(
            AuditEventType.PARSE_STARTED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            actor_username=tenant.username,
            evidence_id=evidence.evidence_id,
            details={
                "parser": parser.parser_name,
                "parser_type": parser.parser_type.value,
                "retry": True,
            },
        )

        if parser.parser_type == ParserType.FAST:
            await self._task_queue.enqueue_parse_fast(evidence_id, tenant)
        else:
            await self._task_queue.enqueue_parse_heavy(evidence_id, tenant)

        logger.info(
            "parse_retry_queued",
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
            if self._enrichment_pipeline is not None:
                annotated = _apply_enrichment(annotated, self._enrichment_pipeline, tenant.org_id)

            if self._timeline_ingest is not None:
                count = await self._timeline_ingest.ingest_records(annotated, tenant, evidence_id)
            else:
                count = 0
                async for _ in annotated:
                    count += 1

            # Independent second pass -- a fresh stream fetch, same pattern
            # _detect_parser's own separate header-peek fetch already uses.
            # Default extract_artifacts() yields nothing, so this is a
            # true no-op for every parser that hasn't opted in (known,
            # documented v1 tradeoff: two stream_object() calls for a
            # parser that implements both -- see
            # reviews/Data_Source_Module_System.md §5/§9).
            #
            # yara_scan_org_var is bound here, around the whole
            # extract_artifacts()-consuming block, not inside
            # ZipArchiveParser/TarArchiveParser themselves (roadmap E4 --
            # see src/application/yara_rules.py's module docstring for why
            # a ContextVar is how org scoping reaches
            # SignedYaraRulePackProvider.get_rule_source() without those two
            # parsers' zero-argument call site ever needing to change). This
            # is the ONE place every ForensicParser's extract_artifacts() is
            # invoked from, so binding it here covers every current and
            # future parser, not just the container ones.
            org_context_token = yara_scan_org_var.set(tenant.org_id)
            try:
                artifact_stream = await self._storage.stream_object(evidence_key, bucket="evidence")
                annotated_artifacts = _annotate_artifacts(
                    parser.extract_artifacts(artifact_stream, evidence, tenant),
                    tenant.org_alias,
                )
                if self._artifact_ingest is not None:
                    artifact_count = await self._artifact_ingest.ingest_artifacts(
                        annotated_artifacts, tenant, evidence_id
                    )
                else:
                    artifact_count = 0
                    async for _ in annotated_artifacts:
                        artifact_count += 1
            finally:
                yara_scan_org_var.reset(org_context_token)

            evidence = evidence.with_state(EvidenceState.COMPLETE)
            await self._repo.update(evidence)
            await self._audit.log(
                AuditEventType.PARSE_COMPLETED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                evidence_id=evidence.evidence_id,
                details={
                    "parser": parser.parser_name,
                    "record_count": count,
                    "artifact_count": artifact_count,
                },
            )
            logger.info(
                "parse_completed",
                extra={
                    "evidence_id": str(evidence_id),
                    "record_count": count,
                    "artifact_count": artifact_count,
                },
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
        except (ParsingError, ValidationError) as exc:
            # Previously just re-raised with no state mutation at all -- a
            # corrupt file/unsupported format hitting this branch (e.g. via
            # _detect_parser's second, execute_parse-local call) was left
            # stuck in PARSING even on the true final attempt, relying
            # entirely on the 3h abort_orphan_parses beat sweep. Mirror the
            # generic except Exception branch below: only mutate state on
            # the final attempt, so a pending Celery retry's own
            # PARSING-state precondition still holds in between.
            if is_final_attempt:
                # Not "no_parser_found" here even for a ParsingError -- that
                # reason is reserved for _detect_parser's own dedicated path
                # in start_parsing (before PARSING is ever entered). A
                # ParsingError surfacing inside execute_parse's try means the
                # parser itself failed against real content (corrupt file,
                # truncated stream, etc.), which is the same "parse_failed"
                # category the generic Exception branch below already uses.
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


async def _apply_enrichment(
    source: AsyncIterator[TimelineRecord],
    pipeline: EnrichmentPipeline,
    org_id: uuid.UUID,
) -> AsyncGenerator[TimelineRecord, None]:
    """Wrap a record stream, applying every configured Enricher (roadmap F1).

    Runs after ``_annotate_records`` (document_id/org_alias already set) and
    before indexing, so enrichment becomes part of the same immutable,
    indexed record as any other derived field -- see
    ``src/application/enrichment.py``'s own module docstring for why.
    """
    async for record in source:
        yield await pipeline.enrich(record, org_id)


async def _annotate_artifacts(
    source: AsyncIterator[StructuredArtifact],
    org_alias: str,
) -> AsyncGenerator[StructuredArtifact, None]:
    """Wrap a module's artifact stream, correcting org_alias the same way
    _annotate_records does (Celery-rebuilt TenantContext carries a
    placeholder org_alias -- see _reconcile_tenant_alias's own docstring
    for why the authoritative value must come from the evidence's own
    metadata, not the task payload)."""
    async for artifact in source:
        updated_kronos = artifact.kronos.model_copy(update={"org_alias": org_alias})
        yield artifact.model_copy(update={"kronos": updated_kronos})
