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
    from src.adapter.repository.postgres_source_cursor import (  # noqa: PLC0415
        PostgresSourceCursorRepository,
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
        configure_defender_poll_source_from_settings,
        configure_dependencies,
        configure_sentinel_sink_from_settings,
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
    # Poll-source cursor persistence (Gap Audit P1-8): real Postgres
    # wiring is safe here (unlike the Celery/sync path -- see
    # wire_dependencies_sync()'s own docstring) because this whole
    # function already runs inside the one long-lived event loop FastAPI's
    # own lifespan owns; this engine and every repository built from it
    # live exactly as long as that loop does. Only the FastAPI PUSH route
    # (get_integration_source_ingest_service) resolves this via
    # get_source_cursor_repository() today -- the Defender POLL beat task
    # (celery_app.py's poll_defender_alerts) is loop-bound per-task instead
    # and builds its own throwaway PostgresSourceCursorRepository, exactly
    # mirroring org_quota_repo's own split between this process-wide
    # instance and celery_runtime.py's per-task one.
    source_cursor_repo = PostgresSourceCursorRepository(engine)

    # Schema creation/evolution (Gap Audit P1-12 / Milestone V4): this used
    # to call every repository's own `create_tables()` classmethod here, at
    # every real FastAPI boot. That is now Alembic's job instead --
    # `alembic upgrade head` runs once, to completion, in a dedicated
    # `db-migrate` init step (docker-compose.{dev,test,prod}.yml) BEFORE
    # this process ever starts, mirroring this repo's existing keycloak-
    # init/opensearch-init one-shot-container pattern rather than having
    # N independently-booting app/worker processes race each other via
    # `_schema_lock.py`'s advisory lock. Deliberately NOT calling
    # `create_tables()` here anymore: doing so alongside a real migration
    # tool would reintroduce the exact "two sources of truth for schema"
    # ambiguity adopting Alembic exists to remove (`create_all(checkfirst=
    # True)` only ever ADDS missing tables -- it can silently paper over a
    # `db-migrate` step that was skipped, rather than failing loudly the
    # way a missing/failed migration should). The 14 repositories' own
    # `create_tables()` classmethods are NOT deleted -- they still exist
    # and are still used directly by tests/integration/conftest.py for
    # lightweight per-test schema setup against a throwaway testcontainer.
    # See docs/DATABASE_MIGRATIONS.md for the full reasoning and workflow.

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
        source_cursor_repository=source_cursor_repo,
    )
    configure_clamav_from_settings()
    configure_splunk_hec_sink_from_settings()
    configure_cef_syslog_sink_from_settings()
    configure_sentinel_sink_from_settings()
    configure_defender_poll_source_from_settings()

    logger.info("startup: dependencies wired (async)")


def wire_dependencies_sync() -> None:
    """Sync variant — used by Celery worker_init signal (sync context).

    Wires only the NON-loop-bound singletons (S3 storage via boto3+thread
    executor, CeleryTaskQueue, step-up ticket store, RFC3161 timestamp
    client, ClamAV scanner) into the DI container.

    Deliberately does NOT configure a pooled asyncpg engine, Postgres
    repositories, or an AsyncOpenSearch client as process-wide singletons
    here: those are loop-bound, and Celery tasks each run in their own
    short-lived event loop via asyncio.run(). Reusing a loop-bound
    engine/client across those separate loops is exactly what caused
    "Future attached to a different loop" / "Event loop is closed" — see
    src/external/celery_runtime.py, which builds fresh instances inside
    each task's own loop instead.

    Schema creation/evolution (Gap Audit P1-12 / Milestone V4): this used
    to also run every repository's own `create_tables()` classmethod here,
    via a throwaway NullPool engine + throwaway loop, at every real Celery
    worker boot. That is now Alembic's job instead -- see
    wire_dependencies_async()'s identical comment and
    docs/DATABASE_MIGRATIONS.md for the full reasoning. The `db-migrate`
    init step (docker-compose.{dev,test,prod}.yml) runs `alembic upgrade
    head` to completion before either this worker or the FastAPI backend
    ever starts, so there is no remaining caller here that needs its own
    schema-creation safety net.
    """
    from src.adapter.queue.celery_queue import CeleryTaskQueue  # noqa: PLC0415
    from src.adapter.storage.s3 import S3EvidenceStorage  # noqa: PLC0415
    from src.application.timestamping import RFC3161TimestampService  # noqa: PLC0415
    from src.config import Settings  # noqa: PLC0415
    from src.external.dependencies import (  # noqa: PLC0415
        build_step_up_ticket_store,
        configure_cef_syslog_sink_from_settings,
        configure_clamav_from_settings,
        configure_dependencies,
        configure_sentinel_sink_from_settings,
        configure_splunk_hec_sink_from_settings,
        configure_step_up_auth,
    )

    settings = Settings()  # type: ignore[call-arg]  # BaseSettings: real values come from env vars

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
    # Real, previously-undiscovered gap found and fixed 2026-08-09
    # (Milestone S): wire_dependencies_async() (the FastAPI path) has always
    # called all four of configure_splunk_hec_sink_from_settings()/
    # configure_cef_syslog_sink_from_settings()/
    # configure_sentinel_sink_from_settings()/
    # configure_defender_poll_source_from_settings(), but this sync/Celery
    # path never called any of them -- meaning get_splunk_hec_sink()/
    # get_cef_syslog_sink()/get_sentinel_sink() would all resolve to None
    # inside a Celery task (e.g. a future SOAR playbook action pushing a
    # Detection to an external SIEM) even with real splunk_hec_url/
    # cef_syslog_host/sentinel_* env vars set on the worker. Not an active
    # bug today (no route/playbook-action currently calls
    # DetectionSinkPushService from anywhere, confirmed via a direct
    # grep -- R2/R3/R4's own "Not built here" scope notes), but a real,
    # latent one given the SOAR playbook engine (Milestone M7/H1) that just
    # landed is exactly the kind of caller that would run inside a Celery
    # task. Splunk/CEF/Sentinel are safe to add here: SplunkHecSink,
    # CefDetectionMapper/SyslogIntegrationSink, and SentinelHttpSink all
    # construct their own httpx.AsyncClient fresh, per-call, inside
    # push_events() (`async with httpx.AsyncClient(...)`) rather than
    # holding one open at configure time -- so they don't reintroduce the
    # cross-event-loop sharing bug this function's own docstring documents
    # Postgres/OpenSearch having to avoid. configure_defender_poll_source_
    # from_settings() is deliberately STILL NOT added here: its own
    # docstring states it constructs and keeps alive a single
    # process-lifetime httpx.AsyncClient specifically so DefenderPollSource's
    # OAuth2 token cache persists across poll cycles -- reusing that one
    # client from inside Celery's own per-task fresh-event-loop model (see
    # this function's own docstring above) would risk exactly the "Future
    # attached to a different loop" failure class this sync path was built
    # to avoid. Gap Audit P1-2/Milestone V2 closed the "wiring Defender
    # polling into Celery correctly" follow-up flagged here on 2026-08-09 --
    # see src/external/celery_defender.py's own module docstring and
    # celery_app.py's poll_defender_alerts task: a celery_runtime.py-style
    # per-task client, built and disposed fresh every 10-minute beat
    # invocation, rather than a copy-paste of this function's own
    # process-lifetime call.
    configure_splunk_hec_sink_from_settings()
    configure_cef_syslog_sink_from_settings()
    configure_sentinel_sink_from_settings()

    logger.info("startup: dependencies wired (sync/celery)")
