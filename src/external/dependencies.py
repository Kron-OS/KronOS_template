"""Dependency injection container for FastAPI.

Repositories, services, and scanners are registered here.  Tests override
bindings via FastAPI's ``app.dependency_overrides`` or by calling
``configure_dependencies()`` with test doubles.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

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
from src.application.timestamping import RFC3161TimestampService
from src.application.validation import EvidenceValidator, default_validator_chain
from src.domain.user import Role, TenantContext
from src.external.middleware.step_up_auth import StepUpAuth as _StepUpAuth
from src.external.middleware.step_up_store import (
    InMemoryTicketStore,
    RedisTicketStore,
    TicketStore,
)
from src.external.middleware.tenant_context import get_tenant_context as get_tenant_context

logger = logging.getLogger(__name__)

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
_presigned_expiry: int = 900
_opensearch_dashboards_url: str | None = None
_timestamp_service: RFC3161TimestampService | None = None
_default_retention_days: int = 365


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

    Call at application startup after configure_dependencies().  Falls back
    to the existing NoOpScanner if Settings cannot be instantiated (e.g., in
    unit tests, which never call this at all).

    In production (``settings.environment == "production"``), an unreachable
    clamd is a hard startup failure — EVID-6: a misconfigured AV scanner must
    never silently downgrade to the permissive NoOpScanner in a deployment
    that is supposed to be malware-scanning every upload.  Dev/test keep the
    previous permissive fallback so a local clamd-less setup still boots.
    """
    global _scanner
    import socket  # noqa: PLC0415

    from src.application.scanning import ClamAVScanner  # noqa: PLC0415
    from src.config import Settings  # noqa: PLC0415
    from src.exceptions import StorageError  # noqa: PLC0415

    try:
        s = Settings()
    except Exception:
        return  # keep NoOpScanner in test/dev environments without full Settings

    try:
        with socket.create_connection((s.clamd_host, s.clamd_port), timeout=3):
            pass
    except OSError as exc:
        if s.environment == "production":
            raise StorageError(
                "ClamAV is unreachable at startup; refusing to start in production "
                "with malware scanning silently disabled",
                context={
                    "clamd_host": s.clamd_host,
                    "clamd_port": s.clamd_port,
                    "error": str(exc),
                },
            ) from exc
        logger.warning(
            "clamav_unreachable_dev_fallback",
            extra={
                "clamd_host": s.clamd_host,
                "clamd_port": s.clamd_port,
                "environment": s.environment,
            },
        )
        return  # keep NoOpScanner in dev/test

    _scanner = ClamAVScanner(host=s.clamd_host, port=s.clamd_port)


def get_task_queue() -> TaskQueue:
    return _task_queue


def get_timestamp_service() -> RFC3161TimestampService | None:
    """Return the configured RFC 3161 TSA client, or None if no tsa_url is set.

    None is a valid, honest configuration (dev/test without a TSA); callers
    must treat it as "timestamping disabled", never substitute a fake result.
    """
    return _timestamp_service


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
        task_queue=_task_queue,
        timestamp_service=_timestamp_service,
        default_retention_days=_default_retention_days,
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


# NOTE: the former _build_orchestration_service() (which assembled the parsing
# orchestration service from the process-wide singletons) was removed: Celery
# workers must NOT reuse the loop-bound singleton engine/OpenSearch client
# across their per-task asyncio.run() loops. Per-task, loop-scoped construction
# now lives in src/external/celery_runtime.py::run_evidence_coro instead.


# ---------------------------------------------------------------------------
# Auth dependency — JWT-based TenantContext extraction (Phase 5).
# Re-exported here so routes continue to import from this module unchanged.
# ---------------------------------------------------------------------------

_step_up_auth = _StepUpAuth()


def get_step_up_auth() -> _StepUpAuth:
    """Return the shared StepUpAuth instance."""
    return _step_up_auth


def configure_step_up_auth(store: TicketStore) -> None:
    """Replace the process StepUpAuth with one backed by *store*.

    Call at startup with a ``RedisTicketStore`` to make step-up tickets work
    across multiple backend workers/replicas (audit M-4).
    """
    global _step_up_auth
    _step_up_auth = _StepUpAuth(store=store)


def build_step_up_ticket_store(settings: Any) -> TicketStore:
    """Build a TicketStore from settings: Redis when configured, else in-memory.

    ``settings.step_up_ticket_store == "redis"`` selects the shared Redis store
    using ``settings.redis_url``; any other value yields the process-local store.
    """
    if getattr(settings, "step_up_ticket_store", "memory") == "redis":
        import redis  # noqa: PLC0415

        url = settings.redis_url
        # redis_url may be a pydantic SecretStr.
        url = url.get_secret_value() if hasattr(url, "get_secret_value") else str(url)
        client = redis.Redis.from_url(url, decode_responses=True)
        return RedisTicketStore(client)
    return InMemoryTicketStore()


# ---------------------------------------------------------------------------
# Runtime configuration — called once at application startup.
# ---------------------------------------------------------------------------


def configure_dependencies(
    audit_log_repository: AuditLogRepository | None,
    evidence_repository: EvidenceRepository | None,
    evidence_storage: EvidenceStorage,
    scanner: AntivirusScanner | None = None,
    task_queue: TaskQueue | None = None,
    parser_registry: ParserRegistry | None = None,
    opensearch_client: AbstractTimelineIndex | None = None,
    case_repository: CaseRepository | None = None,
    max_upload_bytes: int = 1_073_741_824,
    presigned_expiry_seconds: int = 3600,
    opensearch_dashboards_url: str | None = None,
    timestamp_service: RFC3161TimestampService | None = None,
    default_retention_days: int = 365,
) -> None:
    """Wire concrete implementations into the container."""
    global _audit_log_repository, _evidence_repository, _evidence_storage
    global _scanner, _task_queue, _parser_registry, _opensearch_client
    global _max_upload_bytes, _presigned_expiry, _case_repository
    global _opensearch_dashboards_url, _timestamp_service, _default_retention_days
    if audit_log_repository is not None:
        _audit_log_repository = audit_log_repository
    if evidence_repository is not None:
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
    _opensearch_dashboards_url = opensearch_dashboards_url
    _timestamp_service = timestamp_service
    _default_retention_days = default_retention_days


def reset_dependencies() -> None:
    """Reset all dependency bindings — used only in tests."""
    global _audit_log_repository, _evidence_repository, _evidence_storage, _scanner
    global _task_queue, _parser_registry, _opensearch_client, _max_upload_bytes, _presigned_expiry
    global _case_repository, _step_up_auth, _opensearch_dashboards_url
    global _timestamp_service, _default_retention_days
    _step_up_auth = _StepUpAuth()
    _audit_log_repository = None
    _evidence_repository = None
    _evidence_storage = None
    _case_repository = InMemoryCaseRepository()
    _scanner = NoOpScanner()
    _task_queue = InMemoryTaskQueue()
    _parser_registry = None
    _opensearch_client = InMemoryOpenSearchClient()
    _max_upload_bytes = 1_073_741_824
    _presigned_expiry = 900
    _opensearch_dashboards_url = None
    _timestamp_service = None
    _default_retention_days = 365
