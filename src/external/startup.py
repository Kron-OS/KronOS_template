"""Concrete dependency wiring from environment / Settings.

Called once at process startup — both from the FastAPI lifespan and from the
Celery worker_init signal.  Keeps configure_dependencies() calls in one place.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def _resolve_minio_public_endpoint_url(
    public_endpoint: str | None, internal_scheme: str
) -> str | None:
    """Build the presigned-URL client's endpoint_url from MINIO_PUBLIC_ENDPOINT.

    Historically reused the internal connection's scheme (minio_use_tls) for
    both endpoints -- wrong whenever the browser reaches MinIO's presigned
    URLs via a TLS-terminating reverse proxy in front of it while the
    internal backend->MinIO hop stays plain HTTP (there is no MinIO-native
    way to serve HTTP internally and HTTPS externally from one listener).
    A bare "host:port" value still falls back to internal_scheme, unchanged
    from the original behavior; a full "scheme://host:port" value is used
    as-is, letting the public scheme differ from the internal one.
    """
    if not public_endpoint:
        return None
    if "://" in public_endpoint:
        return public_endpoint
    return f"{internal_scheme}://{public_endpoint}"


async def wire_dependencies_async() -> None:
    """Async variant — used by FastAPI lifespan (already in async context)."""
    from sqlalchemy.ext.asyncio import create_async_engine  # noqa: PLC0415

    from src.adapter.opensearch.client import (
        OpenSearchClient as OpenSearchTimelineIndex,  # noqa: PLC0415
    )
    from src.adapter.queue.celery_queue import CeleryTaskQueue  # noqa: PLC0415
    from src.adapter.repository.postgres_artifact import (  # noqa: PLC0415
        PostgresArtifactRepository,
    )
    from src.adapter.repository.postgres_asset import PostgresAssetRepository  # noqa: PLC0415
    from src.adapter.repository.postgres_audit_log import (  # noqa: PLC0415
        PostgresAuditLogRepository,
    )
    from src.adapter.repository.postgres_case import PostgresCaseRepository  # noqa: PLC0415
    from src.adapter.repository.postgres_dead_letter import (  # noqa: PLC0415
        PostgresDeadLetterSink,
    )
    from src.adapter.repository.postgres_detection import (  # noqa: PLC0415
        PostgresDetectionRepository,
    )
    from src.adapter.repository.postgres_detection_correlation import (  # noqa: PLC0415
        PostgresDetectionCorrelationRepository,
    )
    from src.adapter.repository.postgres_evidence import (  # noqa: PLC0415
        PostgresEvidenceRepository,
    )
    from src.adapter.repository.postgres_ioc_feed import (  # noqa: PLC0415
        PostgresIOCFeedRepository,
    )
    from src.adapter.repository.postgres_quota import (  # noqa: PLC0415
        PostgresOrgQuotaRepository,
    )
    from src.adapter.repository.postgres_rule_pack import (  # noqa: PLC0415
        PostgresRulePackRepository,
    )
    from src.adapter.repository.postgres_sealed_batch import (  # noqa: PLC0415
        PostgresSealedBatchRepository,
    )
    from src.adapter.repository.postgres_yara_rule_pack import (  # noqa: PLC0415
        PostgresYaraRulePackRepository,
    )
    from src.adapter.storage.s3 import S3EvidenceStorage  # noqa: PLC0415
    from src.application.asset_enrichment import AssetContextEnricher  # noqa: PLC0415
    from src.application.enrichment import EnrichmentPipeline  # noqa: PLC0415
    from src.application.ioc_enrichment import IOCMatchEnricher  # noqa: PLC0415
    from src.config import Settings  # noqa: PLC0415
    from src.external.dependencies import (  # noqa: PLC0415
        build_step_up_ticket_store,
        configure_cef_syslog_sink_from_settings,
        configure_clamav_from_settings,
        configure_dependencies,
        configure_splunk_hec_sink_from_settings,
        configure_step_up_auth,
    )

    settings = Settings()  # type: ignore[call-arg]  # BaseSettings: real values come from env vars

    engine = create_async_engine(
        settings.database_url.get_secret_value(),
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
    )

    audit_repo = PostgresAuditLogRepository(engine)
    evidence_repo = PostgresEvidenceRepository(engine)
    case_repo = PostgresCaseRepository(engine)
    artifact_repo = PostgresArtifactRepository(engine)
    detection_repo = PostgresDetectionRepository(engine)
    correlation_repo = PostgresDetectionCorrelationRepository(engine)
    rule_pack_repo = PostgresRulePackRepository(engine)
    yara_rule_pack_repo = PostgresYaraRulePackRepository(engine)
    asset_repo = PostgresAssetRepository(engine)
    ioc_feed_repo = PostgresIOCFeedRepository(engine)
    org_quota_repo = PostgresOrgQuotaRepository(engine)

    await PostgresAuditLogRepository.create_tables(engine)
    await PostgresEvidenceRepository.create_tables(engine)
    await PostgresCaseRepository.create_tables(engine)
    await PostgresArtifactRepository.create_tables(engine)
    await PostgresDetectionRepository.create_tables(engine)
    await PostgresDetectionCorrelationRepository.create_tables(engine)
    await PostgresRulePackRepository.create_tables(engine)
    await PostgresYaraRulePackRepository.create_tables(engine)
    await PostgresAssetRepository.create_tables(engine)
    await PostgresIOCFeedRepository.create_tables(engine)
    await PostgresSealedBatchRepository.create_tables(engine)
    # Tenant storage quota (docs/TENANT_USAGE_QUOTA.md) -- create_tables()
    # called here at real startup, not just at DI-container-configure time,
    # deliberately repeating the pattern the DeadLetterSink comment above
    # already documents to avoid D3's real, since-fixed gap (a new
    # repository's table never created because create_tables() was missing
    # from this exact list).
    await PostgresOrgQuotaRepository.create_tables(engine)
    # DeadLetterSink (roadmap M3/D5): create_tables() runs even though
    # nothing configures a Postgres-backed sink into the DI container below
    # yet (StreamNormalizationService itself isn't wired into
    # configure_dependencies() either, mirroring D4's own precedent) --
    # deliberately NOT repeating D3's real, since-fixed gap where
    # PostgresSealedBatchRepository.create_tables() was originally missing
    # from this exact list and the table would not have existed for the
    # first real production save.
    await PostgresDeadLetterSink.create_tables(engine)

    _minio_scheme = "https" if settings.minio_use_tls else "http"
    storage = S3EvidenceStorage(
        endpoint_url=f"{_minio_scheme}://{settings.minio_endpoint}",
        presign_endpoint_url=_resolve_minio_public_endpoint_url(
            settings.minio_public_endpoint, _minio_scheme
        ),
        access_key=settings.minio_access_key.get_secret_value(),
        secret_key=settings.minio_secret_key.get_secret_value(),
        quarantine_bucket_prefix=settings.minio_quarantine_bucket_prefix,
        evidence_bucket_prefix=settings.minio_evidence_bucket_prefix,
        retention_days=settings.minio_default_retention_days,
        use_tls=settings.minio_use_tls,
    )

    from urllib.parse import urlparse  # noqa: PLC0415

    _parsed = urlparse(settings.opensearch_url)
    _os_use_ssl = _parsed.scheme == "https"
    opensearch = OpenSearchTimelineIndex(
        hosts=[{"host": _parsed.hostname, "port": _parsed.port or (443 if _os_use_ssl else 9200)}],
        http_auth=(
            settings.opensearch_username.get_secret_value(),
            settings.opensearch_password.get_secret_value(),
        ),
        use_ssl=_os_use_ssl,
        verify_certs=False,
    )

    task_queue = CeleryTaskQueue()

    step_up_store = build_step_up_ticket_store(settings)
    configure_step_up_auth(step_up_store)

    # RFC 3161 TSA client (EVID-3 / AUDIT-06) — None when tsa_url is unset,
    # which honestly disables timestamping rather than fabricating tokens.
    from src.application.timestamping import RFC3161TimestampService  # noqa: PLC0415

    timestamp_service = RFC3161TimestampService(settings.tsa_url) if settings.tsa_url else None

    # Auto-provisions each case's OpenSearch Dashboards index pattern on
    # creation (DashboardsIndexPatternProvisioner) — None (no-op) when the
    # internal Dashboards URL isn't configured, same "honestly disabled"
    # pattern as timestamp_service above.
    from src.adapter.opensearch.dashboards_client import (  # noqa: PLC0415
        DashboardsIndexPatternProvisioner,
    )

    dashboards_provisioner = (
        DashboardsIndexPatternProvisioner(
            base_url=settings.opensearch_dashboards_internal_url,
            admin_username=settings.opensearch_username.get_secret_value(),
            admin_password=settings.opensearch_password.get_secret_value(),
        )
        if settings.opensearch_dashboards_internal_url
        else None
    )

    # Auto-provisions per-org Security Analytics detectors (roadmap M2/C2).
    # Same "honestly disabled" pattern: None (no-op) is a valid, explicit
    # configuration, not a fabricated fallback. Uses the same admin
    # credentials as the main OpenSearch client -- per the A3 gate
    # (poc/security_analytics_tenant_isolation/), Security Analytics is
    # never touched with anything but admin credentials, and never exposed
    # directly to a tenant session.
    from src.adapter.opensearch.detector_provisioner import (  # noqa: PLC0415
        SecurityAnalyticsDetectorProvisioner,
    )

    detector_provisioner = SecurityAnalyticsDetectorProvisioner(
        base_url=settings.opensearch_url,
        admin_username=settings.opensearch_username.get_secret_value(),
        admin_password=settings.opensearch_password.get_secret_value(),
    )

    # Roadmap M1/B3 (poc/ism_tiering_legal_hold/): explicit self-healing ISM
    # attachment + legal-hold control -- ism_template's implicit auto-attach
    # alone was found, against the real live cluster, to leave indices
    # stuck with management disabled with no automatic recovery.
    from src.adapter.opensearch.ism_manager import (  # noqa: PLC0415
        OpenSearchIsmLifecycleManager,
    )

    ism_manager = OpenSearchIsmLifecycleManager(
        base_url=settings.opensearch_url,
        admin_username=settings.opensearch_username.get_secret_value(),
        admin_password=settings.opensearch_password.get_secret_value(),
    )

    # Continuous ingestion transport (roadmap M3/D1, poc/stream_ingest_redis/):
    # real Redis Streams, on a dedicated DB number (settings.stream_redis_db,
    # default 3) so a stream's own real burst/backpressure characteristics
    # never contend with the Celery broker/backend (DB 1/2) or step-up
    # tickets (DB 0) sharing this same real Redis instance.
    # decode_responses=False (the default) -- this adapter is deliberately
    # payload-agnostic, transporting raw bytes; D4 owns interpreting them.
    from urllib.parse import urlsplit, urlunsplit  # noqa: PLC0415

    from redis.asyncio import Redis as AsyncRedis  # noqa: PLC0415

    from src.adapter.queue.stream_ingest import RedisStreamIngestAdapter  # noqa: PLC0415

    _redis_url = settings.redis_url.get_secret_value()
    _parsed_redis = urlsplit(_redis_url)
    _stream_redis_url = urlunsplit(_parsed_redis._replace(path=f"/{settings.stream_redis_db}"))
    stream_ingest_adapter = RedisStreamIngestAdapter(AsyncRedis.from_url(_stream_redis_url))

    # Read-only real SA findings reader (roadmap M2/C4) -- mirrors the
    # detector_provisioner's own unconditional construction above:
    # opensearch_url/username/password are always-required Settings
    # fields, so (unlike dashboards_provisioner) there is no "URL not
    # configured" honest-disable case to handle here.
    from src.adapter.opensearch.findings_client import (  # noqa: PLC0415
        SecurityAnalyticsFindingsClient,
    )

    findings_client = SecurityAnalyticsFindingsClient(
        base_url=settings.opensearch_url,
        admin_username=settings.opensearch_username.get_secret_value(),
        admin_password=settings.opensearch_password.get_secret_value(),
    )

    # Correlation (roadmap M2/F3, poc/security_analytics_correlation/):
    # evaluated SA's native correlation engine (real, live on the pinned
    # 2.11.1 cluster -- 20/20 real checks passed) before considering a
    # bespoke entity graph. Same always-required opensearch_url/username/
    # password construction as findings_client/detector_provisioner above --
    # no "not configured" honest-disable case here either.
    from src.adapter.opensearch.correlation_client import (  # noqa: PLC0415
        SecurityAnalyticsCorrelationClient,
    )
    from src.adapter.opensearch.correlation_rule_provisioner import (  # noqa: PLC0415
        SecurityAnalyticsCorrelationRuleProvisioner,
    )

    correlation_client = SecurityAnalyticsCorrelationClient(
        base_url=settings.opensearch_url,
        admin_username=settings.opensearch_username.get_secret_value(),
        admin_password=settings.opensearch_password.get_secret_value(),
    )
    correlation_rule_provisioner = SecurityAnalyticsCorrelationRuleProvisioner(
        base_url=settings.opensearch_url,
        admin_username=settings.opensearch_username.get_secret_value(),
        admin_password=settings.opensearch_password.get_secret_value(),
    )

    # Rule-pack lifecycle (roadmap M2/C3, poc/rule_pack_lifecycle/): custom
    # rule publish + detector wiring, admin-only per the A3 gate exactly like
    # detector_provisioner/findings_client above. CosignPackSignatureVerifier
    # needs no OpenSearch connection at all -- it shells out to the pinned
    # `cosign` binary only when a signed pack is actually imported.
    from src.adapter.opensearch.custom_rule_client import (  # noqa: PLC0415
        SecurityAnalyticsCustomRuleClient,
    )
    from src.adapter.opensearch.custom_rule_detector_provisioner import (  # noqa: PLC0415
        SecurityAnalyticsCustomRuleDetectorProvisioner,
    )
    from src.adapter.signing.cosign_verifier import CosignPackSignatureVerifier  # noqa: PLC0415

    custom_rule_client = SecurityAnalyticsCustomRuleClient(
        base_url=settings.opensearch_url,
        admin_username=settings.opensearch_username.get_secret_value(),
        admin_password=settings.opensearch_password.get_secret_value(),
    )
    custom_rule_detector_binder = SecurityAnalyticsCustomRuleDetectorProvisioner(
        base_url=settings.opensearch_url,
        admin_username=settings.opensearch_username.get_secret_value(),
        admin_password=settings.opensearch_password.get_secret_value(),
    )
    pack_signature_verifier = CosignPackSignatureVerifier(cosign_binary=settings.cosign_binary_path)

    configure_dependencies(
        audit_log_repository=audit_repo,
        evidence_repository=evidence_repo,
        case_repository=case_repo,
        artifact_repository=artifact_repo,
        detection_repository=detection_repo,
        correlation_repository=correlation_repo,
        correlation_client=correlation_client,
        correlation_rule_provisioner=correlation_rule_provisioner,
        evidence_storage=storage,
        task_queue=task_queue,
        opensearch_client=opensearch,
        max_upload_bytes=settings.max_upload_bytes,
        presigned_expiry_seconds=settings.presigned_url_expiry_seconds,
        opensearch_dashboards_url=settings.opensearch_dashboards_url,
        dashboards_index_pattern_provisioner=dashboards_provisioner,
        detector_provisioner=detector_provisioner,
        ism_manager=ism_manager,
        stream_ingest_adapter=stream_ingest_adapter,
        findings_client=findings_client,
        timestamp_service=timestamp_service,
        default_retention_days=settings.minio_default_retention_days,
        opensearch_security_enabled=settings.opensearch_security_enabled,
        rule_pack_repository=rule_pack_repo,
        pack_signature_verifier=pack_signature_verifier,
        custom_rule_client=custom_rule_client,
        custom_rule_detector_binder=custom_rule_detector_binder,
        # YARA rule-pack lifecycle (roadmap E4): persistence wiring only.
        # Deliberately NOT wiring yara_runner/yara_rule_provider here yet --
        # a real, concrete gap was found while checking whether to: neither
        # docker/Dockerfile nor docker/Dockerfile.plaso-worker COPYs
        # docker/yara/kronos-yarax-worker.py into the built image (unlike
        # docker/plaso/kronos-plaso-worker.py, which Dockerfile.plaso-worker
        # explicitly COPYs in) -- YaraXSandboxRunner's default worker path
        # would not resolve inside a real deployed container today. Wiring
        # scanning on by default here, unverified against the real built
        # image, would violate CLAUDE.md §F ("plausible code without a
        # captured real run is an automatic fail"). Flagged as a follow-up
        # for whoever completes E2/E3's own production activation, not
        # silently worked around here.
        yara_rule_pack_repository=yara_rule_pack_repo,
        # Enrichment (roadmap F1): wired ON by default, unlike yara_runner
        # above -- AssetContextEnricher is a pure Postgres lookup with no
        # subprocess/Dockerfile-activation concern (nothing to verify against
        # a built container image the way E2/E3's sandboxed tool wrapping
        # does), so there is no "unverified in production" gap here.
        asset_repository=asset_repo,
        # Threat-intel IOC matching (roadmap F2): a pure Postgres lookup,
        # same "no unverified subprocess/container-activation gap" reasoning
        # as asset_repository above -- wired on by default.
        ioc_feed_repository=ioc_feed_repo,
        enrichment_pipeline=EnrichmentPipeline(
            [AssetContextEnricher(asset_repo), IOCMatchEnricher(ioc_feed_repo)]
        ),
        org_quota_repository=org_quota_repo,
    )
    configure_clamav_from_settings()
    configure_splunk_hec_sink_from_settings()
    configure_cef_syslog_sink_from_settings()

    logger.info("startup: dependencies wired (async)")


def wire_dependencies_sync() -> None:
    """Sync variant — used by Celery worker_init signal (sync context).

    Wires only the NON-loop-bound singletons (S3 storage via boto3+thread
    executor, CeleryTaskQueue, step-up ticket store, RFC3161 timestamp
    client, ClamAV scanner) into the DI container, and runs create_tables()
    once via a throwaway NullPool engine + throwaway loop that is fully
    disposed before this function returns.

    Deliberately does NOT configure a pooled asyncpg engine, Postgres
    repositories, or an AsyncOpenSearch client as process-wide singletons
    here: those are loop-bound, and Celery tasks each run in their own
    short-lived event loop via asyncio.run(). Reusing a loop-bound
    engine/client across those separate loops is exactly what caused
    "Future attached to a different loop" / "Event loop is closed" — see
    src/external/celery_runtime.py, which builds fresh instances inside
    each task's own loop instead.
    """
    import asyncio  # noqa: PLC0415

    from src.adapter.queue.celery_queue import CeleryTaskQueue  # noqa: PLC0415
    from src.adapter.repository.postgres_artifact import (  # noqa: PLC0415
        PostgresArtifactRepository,
    )
    from src.adapter.repository.postgres_audit_log import (  # noqa: PLC0415
        PostgresAuditLogRepository,
    )
    from src.adapter.repository.postgres_evidence import (  # noqa: PLC0415
        PostgresEvidenceRepository,
    )
    from src.adapter.repository.postgres_quota import (  # noqa: PLC0415
        PostgresOrgQuotaRepository,
    )
    from src.adapter.storage.s3 import S3EvidenceStorage  # noqa: PLC0415
    from src.application.timestamping import RFC3161TimestampService  # noqa: PLC0415
    from src.config import Settings  # noqa: PLC0415
    from src.external.dependencies import (  # noqa: PLC0415
        build_step_up_ticket_store,
        configure_clamav_from_settings,
        configure_dependencies,
        configure_step_up_auth,
    )

    settings = Settings()  # type: ignore[call-arg]  # BaseSettings: real values come from env vars

    async def _create_tables() -> None:
        from sqlalchemy.ext.asyncio import create_async_engine  # noqa: PLC0415
        from sqlalchemy.pool import NullPool  # noqa: PLC0415

        engine = create_async_engine(settings.database_url.get_secret_value(), poolclass=NullPool)
        try:
            await PostgresAuditLogRepository.create_tables(engine)
            await PostgresEvidenceRepository.create_tables(engine)
            await PostgresArtifactRepository.create_tables(engine)
            await PostgresOrgQuotaRepository.create_tables(engine)
        finally:
            await engine.dispose()

    asyncio.run(_create_tables())

    _minio_scheme = "https" if settings.minio_use_tls else "http"
    storage = S3EvidenceStorage(
        endpoint_url=f"{_minio_scheme}://{settings.minio_endpoint}",
        presign_endpoint_url=_resolve_minio_public_endpoint_url(
            settings.minio_public_endpoint, _minio_scheme
        ),
        access_key=settings.minio_access_key.get_secret_value(),
        secret_key=settings.minio_secret_key.get_secret_value(),
        quarantine_bucket_prefix=settings.minio_quarantine_bucket_prefix,
        evidence_bucket_prefix=settings.minio_evidence_bucket_prefix,
        retention_days=settings.minio_default_retention_days,
        use_tls=settings.minio_use_tls,
    )

    task_queue = CeleryTaskQueue()
    step_up_store = build_step_up_ticket_store(settings)
    configure_step_up_auth(step_up_store)

    timestamp_service = RFC3161TimestampService(settings.tsa_url) if settings.tsa_url else None

    configure_dependencies(
        audit_log_repository=None,
        evidence_repository=None,
        evidence_storage=storage,
        task_queue=task_queue,
        max_upload_bytes=settings.max_upload_bytes,
        presigned_expiry_seconds=settings.presigned_url_expiry_seconds,
        opensearch_dashboards_url=settings.opensearch_dashboards_url,
        timestamp_service=timestamp_service,
        default_retention_days=settings.minio_default_retention_days,
        opensearch_security_enabled=settings.opensearch_security_enabled,
    )
    configure_clamav_from_settings()

    logger.info("startup: dependencies wired (sync/celery)")
