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
from src.adapter.opensearch.custom_rule_client import CustomRuleClient
from src.adapter.opensearch.custom_rule_detector_provisioner import CustomRuleDetectorBinder
from src.adapter.opensearch.dashboards_client import DashboardsIndexPatternProvisioner
from src.adapter.opensearch.detector_provisioner import DetectorProvisioner
from src.adapter.opensearch.findings_client import FindingsClient
from src.adapter.opensearch.ism_manager import IsmLifecycleManager
from src.adapter.queue.event_dedup import EventDedupChecker, InMemoryEventDedupChecker
from src.adapter.queue.stream_ingest import InMemoryStreamIngestAdapter, StreamIngestAdapter
from src.adapter.queue.task_queue import InMemoryTaskQueue, TaskQueue
from src.adapter.repository.artifact_repository import (
    ArtifactRepository,
    InMemoryArtifactRepository,
)
from src.adapter.repository.audit_log import AuditLogRepository
from src.adapter.repository.case_repository import CaseRepository, InMemoryCaseRepository
from src.adapter.repository.dead_letter import DeadLetterSink, InMemoryDeadLetterSink
from src.adapter.repository.detection import DetectionRepository, InMemoryDetectionRepository
from src.adapter.repository.evidence import EvidenceRepository
from src.adapter.repository.rule_pack import InMemoryRulePackRepository, RulePackRepository
from src.adapter.repository.sealed_batch import (
    InMemorySealedBatchRepository,
    SealedBatchRepository,
)
from src.adapter.storage.sealed_batch_storage import SealedBatchStorage
from src.adapter.storage.storage import EvidenceStorage
from src.application.artifact_ingest import ArtifactIngestService
from src.application.audit_log import AuditLogService
from src.application.batch_sealing import BatchSealingService
from src.application.collector_ingest import CollectorIngestService
from src.application.cost_gate import RuleCostGate
from src.application.detection_sync import DetectionSyncService
from src.application.detection_triage import DetectionTriageService
from src.application.evidence_intake import EvidenceIntakeService
from src.application.hashing import HashService
from src.application.ism_tiering import DefaultIsmTierResolver, IsmTierResolver
from src.application.pack_signing import PackSignatureVerifier
from src.application.parser_registry import ParserRegistry
from src.application.parsing_orchestration import ParsingOrchestrationService
from src.application.rule_pack_publisher import RulePackPublisher
from src.application.rule_pack_service import RulePackService
from src.application.scanning import AntivirusScanner, NoOpScanner
from src.application.sealing_trigger_policy import SealingTriggerPolicy
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
_artifact_repository: ArtifactRepository = InMemoryArtifactRepository()
_evidence_storage: EvidenceStorage | None = None
_scanner: AntivirusScanner = NoOpScanner()
_task_queue: TaskQueue = InMemoryTaskQueue()
_parser_registry: ParserRegistry | None = None
_opensearch_client: AbstractTimelineIndex = InMemoryOpenSearchClient()
_max_upload_bytes: int = 1_073_741_824
_presigned_expiry: int = 900
_opensearch_dashboards_url: str | None = None
_dashboards_index_pattern_provisioner: DashboardsIndexPatternProvisioner | None = None
_detector_provisioner: DetectorProvisioner | None = None
_ism_manager: IsmLifecycleManager | None = None
_ism_tier_resolver: IsmTierResolver = DefaultIsmTierResolver()
_stream_ingest_adapter: StreamIngestAdapter = InMemoryStreamIngestAdapter()
_event_dedup_checker: EventDedupChecker = InMemoryEventDedupChecker()
_collector_ingest_service: CollectorIngestService | None = None
_findings_client: FindingsClient | None = None
_detection_repository: DetectionRepository = InMemoryDetectionRepository()
_timestamp_service: RFC3161TimestampService | None = None
_default_retention_days: int = 365
_opensearch_security_enabled: bool = False
_rule_pack_repository: RulePackRepository = InMemoryRulePackRepository()
_pack_signature_verifier: PackSignatureVerifier | None = None
_custom_rule_client: CustomRuleClient | None = None
_custom_rule_detector_binder: CustomRuleDetectorBinder | None = None
_sealed_batch_repository: SealedBatchRepository = InMemorySealedBatchRepository()
_batch_sealing_service: BatchSealingService | None = None
_dead_letter_sink: DeadLetterSink = InMemoryDeadLetterSink()


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


def get_artifact_repository() -> ArtifactRepository:
    return _artifact_repository


def get_opensearch_dashboards_url() -> str | None:
    return _opensearch_dashboards_url


def get_dashboards_index_pattern_provisioner() -> DashboardsIndexPatternProvisioner | None:
    return _dashboards_index_pattern_provisioner


def get_detector_provisioner() -> DetectorProvisioner | None:
    return _detector_provisioner


def get_ism_manager() -> IsmLifecycleManager | None:
    return _ism_manager


def get_ism_tier_resolver() -> IsmTierResolver:
    return _ism_tier_resolver


def get_stream_ingest_adapter() -> StreamIngestAdapter:
    return _stream_ingest_adapter


def get_collector_ingest_service() -> CollectorIngestService:
    """FastAPI dependency for CollectorIngestService (roadmap M3/D2).

    Configured independently of the large ``configure_dependencies()``
    monolith via :func:`configure_collector_ingest_service` -- the mTLS
    collector listener (``src/external/run_dual_listener.py``) is a
    deliberately minimal standalone ASGI app (``src/external/collector_app.py``)
    with no Postgres/MinIO/OpenSearch dependencies at all, so it has no
    reason to call the full app's startup wiring.
    """
    if _collector_ingest_service is None:
        raise RuntimeError(
            "CollectorIngestService is not configured. "
            "Call configure_collector_ingest_service() at startup."
        )
    return _collector_ingest_service


def configure_collector_ingest_service(
    stream_ingest_adapter: StreamIngestAdapter,
    dedup_checker: EventDedupChecker,
    *,
    max_stream_length: int,
    dedup_ttl_seconds: int,
) -> None:
    global _collector_ingest_service, _stream_ingest_adapter, _event_dedup_checker
    _stream_ingest_adapter = stream_ingest_adapter
    _event_dedup_checker = dedup_checker
    _collector_ingest_service = CollectorIngestService(
        stream_ingest_adapter,
        dedup_checker,
        max_stream_length=max_stream_length,
        dedup_ttl_seconds=dedup_ttl_seconds,
    )


def get_sealed_batch_repository() -> SealedBatchRepository:
    return _sealed_batch_repository


def get_dead_letter_sink() -> DeadLetterSink:
    """FastAPI/beat-task dependency for DeadLetterSink (roadmap M3/D5).

    Mirrors :func:`get_sealed_batch_repository`'s own pattern: a
    module-level singleton defaulting to the in-memory double so DI never
    hard-fails before Postgres is configured, swapped for
    ``PostgresDeadLetterSink`` in :func:`configure_dead_letter_sink` at real
    startup. ``StreamNormalizationService`` itself is not wired into this
    container yet (mirrors D4's own precedent -- it is constructed directly
    by its callers/tests/PoC); this getter exists so a future caller (an
    admin route listing dead-lettered events for a batch, a beat task) has
    a real hook point without needing that larger wiring done first.
    """
    return _dead_letter_sink


def configure_dead_letter_sink(sink: DeadLetterSink) -> None:
    global _dead_letter_sink
    _dead_letter_sink = sink


def get_batch_sealing_service() -> BatchSealingService:
    """FastAPI/beat-task dependency for BatchSealingService (roadmap M3/D3).

    Configured independently via :func:`configure_batch_sealing_service` --
    mirrors :func:`configure_collector_ingest_service`'s own pattern, since
    both are standalone consumers of D1's ``StreamIngestAdapter`` rather
    than part of the large ``configure_dependencies()`` monolith. Real
    scheduled invocation (a beat task calling ``seal_pending()`` per
    registered (org, source) on an interval) is deliberately not wired here
    -- flagged as follow-up, matching D2's own precedent for
    ``run_dual_listener.py`` not yet being added to
    ``docker-compose.dev.yml``.
    """
    if _batch_sealing_service is None:
        raise RuntimeError(
            "BatchSealingService is not configured. "
            "Call configure_batch_sealing_service() at startup."
        )
    return _batch_sealing_service


def configure_batch_sealing_service(
    stream_adapter: StreamIngestAdapter,
    storage: SealedBatchStorage,
    timestamp_service: RFC3161TimestampService | None,
    audit_log: AuditLogService,
    repository: SealedBatchRepository,
    trigger_policy: SealingTriggerPolicy,
    **kwargs: Any,
) -> None:
    global _batch_sealing_service, _sealed_batch_repository
    _sealed_batch_repository = repository
    _batch_sealing_service = BatchSealingService(
        stream_adapter,
        storage,
        timestamp_service,
        audit_log,
        repository,
        trigger_policy,
        **kwargs,
    )


def get_findings_client() -> FindingsClient | None:
    return _findings_client


def get_detection_repository() -> DetectionRepository:
    return _detection_repository


def get_rule_pack_repository() -> RulePackRepository:
    return _rule_pack_repository


def get_pack_signature_verifier() -> PackSignatureVerifier | None:
    return _pack_signature_verifier


def get_custom_rule_client() -> CustomRuleClient | None:
    return _custom_rule_client


def get_custom_rule_detector_binder() -> CustomRuleDetectorBinder | None:
    return _custom_rule_detector_binder


def get_max_upload_bytes() -> int:
    return _max_upload_bytes


def get_default_retention_days() -> int:
    return _default_retention_days


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
        s = Settings()  # type: ignore[call-arg]  # BaseSettings: real values come from env vars
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
        from src.external.parsers.archive import ZipArchiveParser  # noqa: PLC0415
        from src.external.parsers.chrome_history import ChromeHistoryParser  # noqa: PLC0415
        from src.external.parsers.cloudtrail import CloudTrailParser  # noqa: PLC0415
        from src.external.parsers.nginx import NginxParser  # noqa: PLC0415
        from src.external.parsers.suricata import SuricataEveParser  # noqa: PLC0415

        registry = ParserRegistry()
        # Must be registered FIRST: claims the ZIP magic before any other
        # parser, and its own recursive get_parser() calls (zip-in-zip) rely
        # on finding itself in this same registry -- see archive.py's
        # docstring for the full extraction/re-dispatch design.
        registry.register(ZipArchiveParser(registry))
        registry.register(CloudTrailParser())
        registry.register(NginxParser())
        # SuricataEveParser keys on EVE JSON's own "event_type"+"flow_id"
        # fields, which never appear in CloudTrail's "Records"/
        # "CloudTrailEvent" envelope or Nginx's line-oriented text format --
        # no overlap with either parser's supports() in either registration
        # order (verified by reading both side by side); placed here simply
        # to sit alongside the other FAST JSON/text parsers.
        registry.register(SuricataEveParser())
        # ChromeHistoryParser must precede PlasoParser: both match the SQLite
        # magic, but the native parser handles Chrome/Chromium 'History' DBs
        # (fast, in-process, real browsing-timeline data) while every other
        # SQLite artifact still falls through to the heavy Plaso path.
        registry.register(ChromeHistoryParser())
        try:
            from src.external.parsers.evtx import FastEvtxParser  # noqa: PLC0415

            registry.register(FastEvtxParser())
        except ImportError:
            pass
        try:
            from src.external.parsers.plaso import PlasoParser  # noqa: PLC0415

            registry.register(PlasoParser())
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
        ism_manager=_ism_manager,
    )


def get_opensearch_client() -> AbstractTimelineIndex:
    return _opensearch_client


def get_timeline_ingest_service(
    audit_log: Annotated[AuditLogService, Depends(get_audit_log_service)],
) -> TimelineIngestionService:
    return TimelineIngestionService(
        opensearch=_opensearch_client,
        audit_log=audit_log,
        security_enabled=_opensearch_security_enabled,
        ism_manager=_ism_manager,
        ism_tier_resolver=_ism_tier_resolver,
    )


def get_artifact_ingest_service(
    audit_log: Annotated[AuditLogService, Depends(get_audit_log_service)],
) -> ArtifactIngestService:
    return ArtifactIngestService(repository=_artifact_repository, audit_log=audit_log)


def get_parsing_orchestration_service(
    evidence_repository: Annotated[EvidenceRepository, Depends(get_evidence_repository)],
    storage: Annotated[EvidenceStorage, Depends(get_evidence_storage)],
    audit_log: Annotated[AuditLogService, Depends(get_audit_log_service)],
    timeline_ingest: Annotated[TimelineIngestionService, Depends(get_timeline_ingest_service)],
    artifact_ingest: Annotated[ArtifactIngestService, Depends(get_artifact_ingest_service)],
) -> ParsingOrchestrationService:
    """FastAPI dependency for ParsingOrchestrationService."""
    return ParsingOrchestrationService(
        evidence_repository=evidence_repository,
        storage=storage,
        audit_log=audit_log,
        parser_registry=get_parser_registry(),
        task_queue=get_task_queue(),
        timeline_ingest=timeline_ingest,
        artifact_ingest=artifact_ingest,
    )


def get_detection_sync_service(
    detection_repository: Annotated[DetectionRepository, Depends(get_detection_repository)],
    audit_log: Annotated[AuditLogService, Depends(get_audit_log_service)],
) -> DetectionSyncService | None:
    """FastAPI dependency for DetectionSyncService.

    None (no-op) when no FindingsClient is configured -- the same "honestly
    disabled" pattern as get_timestamp_service/get_dashboards_index_pattern_
    provisioner: callers must treat None as "sync disabled", never fabricate
    a result.
    """
    findings_client = get_findings_client()
    if findings_client is None:
        return None
    return DetectionSyncService(
        findings_client=findings_client,
        detection_repository=detection_repository,
        audit_log=audit_log,
    )


def get_detection_triage_service(
    detection_repository: Annotated[DetectionRepository, Depends(get_detection_repository)],
    audit_log: Annotated[AuditLogService, Depends(get_audit_log_service)],
) -> DetectionTriageService:
    """FastAPI dependency for DetectionTriageService."""
    return DetectionTriageService(detection_repository=detection_repository, audit_log=audit_log)


def get_rule_pack_service(
    audit_log: Annotated[AuditLogService, Depends(get_audit_log_service)],
) -> RulePackService:
    """FastAPI dependency for RulePackService (roadmap M2/C3).

    Requires no OpenSearch connectivity at all -- pure CRUD/versioning/cost-
    gate/signature-verification bookkeeping (see RulePackService's module
    docstring for why publishing is a separate class).
    """
    signature_verifier = get_pack_signature_verifier()
    if signature_verifier is None:
        from src.adapter.signing.cosign_verifier import (  # noqa: PLC0415
            CosignPackSignatureVerifier,
        )

        signature_verifier = CosignPackSignatureVerifier()
    return RulePackService(
        repository=get_rule_pack_repository(),
        cost_gate=RuleCostGate(),
        signature_verifier=signature_verifier,
        audit_log=audit_log,
    )


def get_rule_pack_publisher(
    audit_log: Annotated[AuditLogService, Depends(get_audit_log_service)],
) -> RulePackPublisher | None:
    """FastAPI dependency for RulePackPublisher.

    None (no-op) when no CustomRuleClient/CustomRuleDetectorBinder is
    configured -- the same "honestly disabled" pattern as
    get_detection_sync_service/get_dashboards_index_pattern_provisioner:
    callers must treat None as "publish disabled", never fabricate a result.
    """
    custom_rule_client = get_custom_rule_client()
    detector_binder = get_custom_rule_detector_binder()
    if custom_rule_client is None or detector_binder is None:
        return None
    return RulePackPublisher(
        repository=get_rule_pack_repository(),
        custom_rule_client=custom_rule_client,
        detector_binder=detector_binder,
        audit_log=audit_log,
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
    artifact_repository: ArtifactRepository | None = None,
    max_upload_bytes: int = 1_073_741_824,
    presigned_expiry_seconds: int = 3600,
    opensearch_dashboards_url: str | None = None,
    dashboards_index_pattern_provisioner: DashboardsIndexPatternProvisioner | None = None,
    detector_provisioner: DetectorProvisioner | None = None,
    ism_manager: IsmLifecycleManager | None = None,
    ism_tier_resolver: IsmTierResolver | None = None,
    stream_ingest_adapter: StreamIngestAdapter | None = None,
    findings_client: FindingsClient | None = None,
    detection_repository: DetectionRepository | None = None,
    timestamp_service: RFC3161TimestampService | None = None,
    default_retention_days: int = 365,
    opensearch_security_enabled: bool = False,
    rule_pack_repository: RulePackRepository | None = None,
    pack_signature_verifier: PackSignatureVerifier | None = None,
    custom_rule_client: CustomRuleClient | None = None,
    custom_rule_detector_binder: CustomRuleDetectorBinder | None = None,
) -> None:
    """Wire concrete implementations into the container."""
    global _audit_log_repository, _evidence_repository, _evidence_storage
    global _scanner, _task_queue, _parser_registry, _opensearch_client
    global _max_upload_bytes, _presigned_expiry, _case_repository
    global _opensearch_dashboards_url, _timestamp_service, _default_retention_days
    global _opensearch_security_enabled, _artifact_repository
    global _dashboards_index_pattern_provisioner, _detector_provisioner
    global _ism_manager, _ism_tier_resolver, _stream_ingest_adapter
    global _findings_client, _detection_repository
    global _rule_pack_repository, _pack_signature_verifier
    global _custom_rule_client, _custom_rule_detector_binder
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
    if artifact_repository is not None:
        _artifact_repository = artifact_repository
    if detection_repository is not None:
        _detection_repository = detection_repository
    _max_upload_bytes = max_upload_bytes
    _presigned_expiry = presigned_expiry_seconds
    _opensearch_dashboards_url = opensearch_dashboards_url
    _dashboards_index_pattern_provisioner = dashboards_index_pattern_provisioner
    _detector_provisioner = detector_provisioner
    _ism_manager = ism_manager
    if ism_tier_resolver is not None:
        _ism_tier_resolver = ism_tier_resolver
    if stream_ingest_adapter is not None:
        _stream_ingest_adapter = stream_ingest_adapter
    _findings_client = findings_client
    _timestamp_service = timestamp_service
    _default_retention_days = default_retention_days
    _opensearch_security_enabled = opensearch_security_enabled
    if rule_pack_repository is not None:
        _rule_pack_repository = rule_pack_repository
    _pack_signature_verifier = pack_signature_verifier
    _custom_rule_client = custom_rule_client
    _custom_rule_detector_binder = custom_rule_detector_binder


def reset_dependencies() -> None:
    """Reset all dependency bindings — used only in tests."""
    global _audit_log_repository, _evidence_repository, _evidence_storage, _scanner
    global _task_queue, _parser_registry, _opensearch_client, _max_upload_bytes, _presigned_expiry
    global _case_repository, _step_up_auth, _opensearch_dashboards_url
    global _timestamp_service, _default_retention_days, _opensearch_security_enabled
    global _artifact_repository, _dashboards_index_pattern_provisioner, _detector_provisioner
    global _ism_manager, _ism_tier_resolver, _stream_ingest_adapter
    global _event_dedup_checker, _collector_ingest_service
    global _findings_client, _detection_repository
    global _rule_pack_repository, _pack_signature_verifier
    global _custom_rule_client, _custom_rule_detector_binder
    global _sealed_batch_repository, _batch_sealing_service
    _step_up_auth = _StepUpAuth()
    _audit_log_repository = None
    _evidence_repository = None
    _evidence_storage = None
    _case_repository = InMemoryCaseRepository()
    _artifact_repository = InMemoryArtifactRepository()
    _detection_repository = InMemoryDetectionRepository()
    _findings_client = None
    _scanner = NoOpScanner()
    _task_queue = InMemoryTaskQueue()
    _parser_registry = None
    _opensearch_client = InMemoryOpenSearchClient()
    _max_upload_bytes = 1_073_741_824
    _presigned_expiry = 900
    _opensearch_dashboards_url = None
    _dashboards_index_pattern_provisioner = None
    _detector_provisioner = None
    _ism_manager = None
    _ism_tier_resolver = DefaultIsmTierResolver()
    _stream_ingest_adapter = InMemoryStreamIngestAdapter()
    _event_dedup_checker = InMemoryEventDedupChecker()
    _collector_ingest_service = None
    _timestamp_service = None
    _default_retention_days = 365
    _opensearch_security_enabled = False
    _rule_pack_repository = InMemoryRulePackRepository()
    _pack_signature_verifier = None
    _custom_rule_client = None
    _custom_rule_detector_binder = None
    _sealed_batch_repository = InMemorySealedBatchRepository()
    _batch_sealing_service = None
