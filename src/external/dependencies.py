"""Dependency injection container for FastAPI.

Repositories, services, and scanners are registered here.  Tests override
bindings via FastAPI's ``app.dependency_overrides`` or by calling
``configure_dependencies()`` with test doubles.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from src.adapter.opensearch.client import AbstractTimelineIndex, InMemoryOpenSearchClient
from src.adapter.queue.task_queue import InMemoryTaskQueue, TaskQueue
from src.adapter.repository.audit_log import AuditLogRepository
from src.adapter.repository.case_repository import CaseRepository, InMemoryCaseRepository
from src.adapter.repository.evidence import EvidenceRepository
from src.adapter.storage.storage import EvidenceStorage
from src.application.audit_log import AuditLogService
from src.application.evidence_intake import EvidenceIntakeService
from src.application.hashing import HashService
from src.application.parser_registry import ParserRegistry
from src.application.parsing_orchestration import ParsingOrchestrationService
from src.application.scanning import AntivirusScanner, NoOpScanner
from src.application.timeline_ingest import TimelineIngestionService
from src.application.validation import EvidenceValidator, default_validator_chain
from src.domain.user import Role, TenantContext
from src.external.middleware.step_up_auth import StepUpAuth as _StepUpAuth
from src.external.middleware.tenant_context import get_tenant_context as get_tenant_context

# ---------------------------------------------------------------------------
# Singleton configuration store — only one instance, set at startup.
# ---------------------------------------------------------------------------

_audit_log_repository: AuditLogRepository | None = None
_evidence_repository: EvidenceRepository | None = None
_case_repository: CaseRepository = InMemoryCaseRepository()
_evidence_storage: EvidenceStorage | None = None
_scanner: AntivirusScanner = NoOpScanner()
_task_queue: TaskQueue = InMemoryTaskQueue()
_parser_registry: ParserRegistry | None = None
_opensearch_client: AbstractTimelineIndex = InMemoryOpenSearchClient()
_max_upload_bytes: int = 1_073_741_824
_presigned_expiry: int = 3600
_opensearch_dashboards_url: str | None = None


# ---------------------------------------------------------------------------
# Repository / storage providers
# ---------------------------------------------------------------------------


def get_audit_log_repository() -> AuditLogRepository:
    if _audit_log_repository is None:
        raise RuntimeError(
            "AuditLogRepository is not configured. "
            "Call configure_dependencies() at application startup."
        )
    return _audit_log_repository


def get_evidence_repository() -> EvidenceRepository:
    if _evidence_repository is None:
        raise RuntimeError(
            "EvidenceRepository is not configured. "
            "Call configure_dependencies() at application startup."
        )
    return _evidence_repository


def get_case_repository() -> CaseRepository:
    return _case_repository


def get_opensearch_dashboards_url() -> str | None:
    return _opensearch_dashboards_url


def get_evidence_storage() -> EvidenceStorage:
    if _evidence_storage is None:
        raise RuntimeError(
            "EvidenceStorage is not configured. "
            "Call configure_dependencies() at application startup."
        )
    return _evidence_storage


def get_scanner() -> AntivirusScanner:
    return _scanner


def configure_clamav_from_settings() -> None:
    """Wire ClamAVScanner using CLAMD_HOST / CLAMD_PORT from Settings.

    Call at application startup after configure_dependencies() if ClamAV
    is available.  Falls back to the existing NoOpScanner if Settings
    cannot be instantiated (e.g., in unit tests).
    """
    global _scanner
    try:
        from src.config import Settings  # noqa: PLC0415
        from src.application.scanning import ClamAVScanner  # noqa: PLC0415

        s = Settings()
        _scanner = ClamAVScanner(host=s.clamd_host, port=s.clamd_port)
    except Exception:
        pass  # keep NoOpScanner in test/dev environments without ClamAV


def get_task_queue() -> TaskQueue:
    return _task_queue


def get_parser_registry() -> ParserRegistry:
    """Return the global parser registry, building it on first call."""
    global _parser_registry
    if _parser_registry is None:
        from src.external.parsers.cloudtrail import CloudTrailParser  # noqa: PLC0415
        from src.external.parsers.nginx import NginxParser  # noqa: PLC0415

        registry = ParserRegistry()
        registry.register(CloudTrailParser())
        registry.register(NginxParser())
        try:
            from src.external.parsers.evtx import FastEvtxParser  # noqa: PLC0415

            registry.register(FastEvtxParser())
        except ImportError:
            pass
        _parser_registry = registry
    return _parser_registry


# ---------------------------------------------------------------------------
# Service providers (constructed fresh per-request — cheap, stateless)
# ---------------------------------------------------------------------------


def get_audit_log_service(
    repository: Annotated[AuditLogRepository, Depends(get_audit_log_repository)],
) -> AuditLogService:
    return AuditLogService(repository)


def get_validator() -> EvidenceValidator:
    return default_validator_chain(_max_upload_bytes)


def get_intake_service(
    evidence_repository: Annotated[EvidenceRepository, Depends(get_evidence_repository)],
    storage: Annotated[EvidenceStorage, Depends(get_evidence_storage)],
    audit_log: Annotated[AuditLogService, Depends(get_audit_log_service)],
    validator: Annotated[EvidenceValidator, Depends(get_validator)],
    scanner: Annotated[AntivirusScanner, Depends(get_scanner)],
) -> EvidenceIntakeService:
    return EvidenceIntakeService(
        evidence_repository=evidence_repository,
        storage=storage,
        audit_log=audit_log,
        validator=validator,
        scanner=scanner,
        hash_service=HashService(),
        max_upload_bytes=_max_upload_bytes,
        presigned_url_expiry_seconds=_presigned_expiry,
    )


def get_opensearch_client() -> AbstractTimelineIndex:
    return _opensearch_client


def get_timeline_ingest_service(
    audit_log: Annotated[AuditLogService, Depends(get_audit_log_service)],
) -> TimelineIngestionService:
    return TimelineIngestionService(
        opensearch=_opensearch_client,
        audit_log=audit_log,
    )


def get_parsing_orchestration_service(
    evidence_repository: Annotated[EvidenceRepository, Depends(get_evidence_repository)],
    storage: Annotated[EvidenceStorage, Depends(get_evidence_storage)],
    audit_log: Annotated[AuditLogService, Depends(get_audit_log_service)],
    timeline_ingest: Annotated[TimelineIngestionService, Depends(get_timeline_ingest_service)],
) -> ParsingOrchestrationService:
    """FastAPI dependency for ParsingOrchestrationService."""
    return ParsingOrchestrationService(
        evidence_repository=evidence_repository,
        storage=storage,
        audit_log=audit_log,
        parser_registry=get_parser_registry(),
        task_queue=get_task_queue(),
        timeline_ingest=timeline_ingest,
    )


def _build_tenant_from_task(org_id: str, user_id: str) -> TenantContext:
    """Build a minimal TenantContext for Celery task execution (no HTTP request)."""
    import uuid as _uuid  # noqa: PLC0415

    return TenantContext(
        org_id=_uuid.UUID(org_id),
        org_alias="system",
        user_id=_uuid.UUID(user_id),
        username="celery-worker",
        roles=frozenset({Role.ANALYST}),
        correlation_id=str(_uuid.uuid4()),
    )


def _build_orchestration_service() -> ParsingOrchestrationService:
    """Build ParsingOrchestrationService for Celery workers (no FastAPI context)."""
    audit_log = get_audit_log_service(get_audit_log_repository())
    timeline_ingest = TimelineIngestionService(
        opensearch=_opensearch_client,
        audit_log=audit_log,
    )
    return ParsingOrchestrationService(
        evidence_repository=get_evidence_repository(),
        storage=get_evidence_storage(),
        audit_log=audit_log,
        parser_registry=get_parser_registry(),
        task_queue=get_task_queue(),
        timeline_ingest=timeline_ingest,
    )


# ---------------------------------------------------------------------------
# Auth dependency — JWT-based TenantContext extraction (Phase 5).
# Re-exported here so routes continue to import from this module unchanged.
# ---------------------------------------------------------------------------

_step_up_auth = _StepUpAuth()


def get_step_up_auth() -> _StepUpAuth:
    """Return the shared StepUpAuth instance."""
    return _step_up_auth


# ---------------------------------------------------------------------------
# Runtime configuration — called once at application startup.
# ---------------------------------------------------------------------------


def configure_dependencies(
    audit_log_repository: AuditLogRepository,
    evidence_repository: EvidenceRepository,
    evidence_storage: EvidenceStorage,
    scanner: AntivirusScanner | None = None,
    task_queue: TaskQueue | None = None,
    parser_registry: ParserRegistry | None = None,
    opensearch_client: AbstractTimelineIndex | None = None,
    case_repository: CaseRepository | None = None,
    max_upload_bytes: int = 1_073_741_824,
    presigned_expiry_seconds: int = 3600,
) -> None:
    """Wire concrete implementations into the container."""
    global _audit_log_repository, _evidence_repository, _evidence_storage
    global _scanner, _task_queue, _parser_registry, _opensearch_client
    global _max_upload_bytes, _presigned_expiry, _case_repository
    _audit_log_repository = audit_log_repository
    _evidence_repository = evidence_repository
    _evidence_storage = evidence_storage
    if scanner is not None:
        _scanner = scanner
    if task_queue is not None:
        _task_queue = task_queue
    if parser_registry is not None:
        _parser_registry = parser_registry
    if opensearch_client is not None:
        _opensearch_client = opensearch_client
    if case_repository is not None:
        _case_repository = case_repository
    _max_upload_bytes = max_upload_bytes
    _presigned_expiry = presigned_expiry_seconds


def reset_dependencies() -> None:
    """Reset all dependency bindings — used only in tests."""
    global _audit_log_repository, _evidence_repository, _evidence_storage, _scanner
    global _task_queue, _parser_registry, _opensearch_client, _max_upload_bytes, _presigned_expiry
    global _case_repository
    _audit_log_repository = None
    _evidence_repository = None
    _evidence_storage = None
    _case_repository = InMemoryCaseRepository()
    _scanner = NoOpScanner()
    _task_queue = InMemoryTaskQueue()
    _parser_registry = None
    _opensearch_client = InMemoryOpenSearchClient()
    _max_upload_bytes = 1_073_741_824
    _presigned_expiry = 3600
