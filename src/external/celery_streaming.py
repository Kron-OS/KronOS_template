"""Per-Celery-task, loop-scoped resource construction for the autonomous
continuous-telemetry -> Detection pipeline (roadmap Milestone W/W1).

**Why this is its own module, not an addition to ``celery_runtime.py`` or
``celery_defender.py``.** Same reasoning ``celery_defender.py`` already
gives for itself: ``celery_runtime.py``'s ``TaskResources`` is scoped to the
evidence-parsing DAG's own collaborators; bolting sealing/normalization/
detection-sync resources onto it would make every future evidence-DAG task
pay for imports/fields it never uses. This module needs a genuinely
different, non-overlapping resource set (``StreamIngestAdapter``,
``SealedBatchStorage``, ``RFC3161TimestampService``, ``FindingsClient``,
``HttpxKeycloakAdminClient``) that has nothing to do with evidence parsing
*or* Defender polling, so it gets its own module, following the exact same
"build every loop-bound resource fresh inside this task's own
``asyncio.run()`` loop, dispose everything before the loop closes" pattern
``celery_defender.py``'s own module docstring already documents in full --
nothing new invented here, just applied to a third resource set.

**The four real, sequenced pieces this module builds task bodies for**
(``docs/ASSESSMENT_SYNTHESIS_2026-08.md`` P0-W1, the incident-response
walkthrough's F1/F2/F3):

  ``run_seal_pending_cycle()``
      Discovers every real (org_id, source_id) pair with a stream key via
      ``StreamIngestAdapter.list_active_streams()`` (see that method's own
      docstring for why this, not a Postgres-backed registry, is the
      correct discovery source -- no such registry exists anywhere in this
      codebase for push/mTLS-authenticated sources) and calls
      ``BatchSealingService.seal_pending()`` once per pair. Returns a
      descriptor per NEWLY sealed batch so the calling Celery task
      (``celery_app.py``'s ``seal_pending_streams``) can chain
      ``normalize_stream_batch`` onto each one.

  ``run_normalize_batch(org_id, batch_id)``
      Normalizes and indexes exactly one already-sealed batch. Deliberately
      event-driven, not polled: ``SealedBatch`` (``src/domain/sealed_batch.py``)
      has no persisted "normalized yet" field to poll on (confirmed by
      direct read -- it is a ``frozen=True`` model with no such column), so
      the only real, non-invented way to discover "which batches need
      normalizing" is to be told exactly which one, right after it was
      sealed -- exactly the shape ``parse_artefact_fast``/``_heavy`` already
      use for ``finalize_evidence.apply_async(...)`` (celery_app.py), a
      well-established chaining idiom in this codebase, not a new one.

  ``run_sync_org_findings_cycle()``
      Discovers every real org via Keycloak's own Organizations Admin API
      (``KeycloakAdminClient.list_organizations()``) -- chosen over
      ``anchor_audit_log``'s "which orgs had audit-log activity yesterday"
      idiom because that idiom would incorrectly skip a genuinely new
      tenant with a freshly-provisioned SA detector but zero audit-log
      writes yet; Keycloak Organizations is this platform's own explicit
      tenant-identity source of truth (CLAUDE.md "Key Decisions"), so
      asking it directly for "every real org" is the more correct answer to
      the actual question this task needs answered ("which orgs might have
      real SA findings"), not merely a substitute for anchor_audit_log's
      answer to a different question. Calls
      ``DetectionSyncService.sync_org_findings()`` once per org.

**Why a Celery task needs ``KeycloakAdminClient`` at all (org_alias
resolution).** ``TenantContext.org_alias``/``StreamProvenance.org_alias``
are not cosmetic -- ``build_stream_index_name(org_alias, ...)`` embeds
``org_alias`` directly into the target OpenSearch index name
(``src/application/timeline_normalization.py``), and
``DetectionSyncService.sync_org_findings`` uses ``tenant.org_alias`` to
select which org's SA findings to query
(``findings_client.fetch_org_findings(tenant.org_alias, ...)``). The
evidence-parsing DAG's own placeholder (``_build_tenant_from_task``'s
``org_alias="system"``) is only ever safe there because
``parsing_orchestration.py``'s ``_reconcile_tenant_alias`` immediately
corrects it from the real, already-persisted ``Evidence.metadata.org_alias``
-- there is no equivalent already-persisted-org_alias record anywhere in
the streaming/detection path for a Celery task to read (confirmed by
direct grep: ``IntegrationSourceIdentity``/``StaticApiKeyProvisioning``
carry only ``org_id``, never ``org_alias``). Reusing the "system" placeholder
here would silently collapse every real org's continuous-telemetry data
into the same ``kronos-system-stream-*`` OpenSearch index and query the
wrong (or a nonexistent) SA finding index per org -- a real, serious
multi-tenancy regression, not a cosmetic gap. ``KeycloakAdminClient.
get_organization_alias()``/``list_organizations()`` (added alongside this
module) are the fix: verified live against Keycloak 26.2 (see
``poc/autonomous_detection_pipeline/README.md``) using the exact same
``kronos-backend`` service-account credential path ``is_org_member`` already
uses in production.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import TYPE_CHECKING
from urllib.parse import urlparse, urlsplit, urlunsplit

if TYPE_CHECKING:
    from src.adapter.keycloak.admin_client import HttpxKeycloakAdminClient
    from src.adapter.opensearch.client import OpenSearchClient
    from src.config import Settings

logger = logging.getLogger(__name__)

# SealingTriggerPolicy thresholds (roadmap Milestone W/W1). No concrete
# default exists anywhere else in this codebase to reuse (confirmed:
# CompositeTriggerPolicy/SizeBoundTriggerPolicy/TimeBoundTriggerPolicy are
# never instantiated with real numbers in src/ before this module --
# configure_batch_sealing_service() is never called in production either).
# Chosen fresh here: 500 events is a real, bounded WORM-object/Merkle-tree
# size that keeps one seal well under a second of hashing; 60 seconds is a
# real "continuous telemetry cannot wait a day for custody" ceiling (this
# module's own docstring already states the design goal) that stays well
# clear of SealingTriggerPolicy's own event-count trigger for any
# reasonably active source. The beat task's own schedule (celery_app.py)
# runs every 60 seconds to match -- running much less often than the time
# trigger would leave real telemetry waiting past its own stated bound
# before the trigger is even evaluated.
_SEAL_MAX_EVENTS = 500
_SEAL_MAX_AGE_SECONDS = 60.0
# Real liveness signal (BatchSealingService's own opt-in mechanism -- see
# that class's module docstring): 10x the trigger's own time bound, so a
# healthy sealer running on its normal 60s schedule never trips this, but a
# sealer that has stopped running (crashed worker, broker outage) pages
# after 10 minutes of real backlog growth rather than never.
_SEAL_STALL_ALERT_AFTER_SECONDS = 600.0

# Placeholder actor identity for TenantContext objects this module builds
# for a pure system/beat-task caller with no natural per-request user --
# mirrors src.external.dependencies._build_tenant_from_task's identical
# "system"/placeholder idiom. DetectionSyncService.sync_org_findings never
# reads tenant.user_id/tenant.username (confirmed by direct read of
# src/application/detection_sync.py -- only org_id/org_alias are used), so
# this value is structural only, never surfaced in any real audit trail
# this task produces.
_SYSTEM_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000000")


class OrgAliasNotFoundError(RuntimeError):
    """A sealed batch (or other real, already-persisted row) references an
    ``org_id`` that no longer resolves to a real Keycloak organization.

    Unlike ``DefenderPollNotConfiguredError`` (an honest, expected
    pre-production "nothing to do yet" state), this is a genuine data
    inconsistency -- something real was already persisted for this org_id,
    so its Keycloak organization disappearing is unexpected and must fail
    loudly (CLAUDE.md invariant #8), not be silently skipped.
    """


def _minio_endpoint_url(settings: Settings) -> str:
    scheme = "https" if settings.minio_use_tls else "http"
    return f"{scheme}://{settings.minio_endpoint}"


def _stream_redis_url(settings: Settings) -> str:
    redis_url = settings.redis_url.get_secret_value()
    parsed = urlsplit(redis_url)
    return urlunsplit(parsed._replace(path=f"/{settings.stream_redis_db}"))


def _build_keycloak_admin_client(settings: Settings) -> HttpxKeycloakAdminClient:
    from src.adapter.keycloak.admin_client import HttpxKeycloakAdminClient  # noqa: PLC0415

    return HttpxKeycloakAdminClient(
        settings.keycloak_url,
        settings.keycloak_realm,
        settings.keycloak_client_id,
        settings.keycloak_client_secret.get_secret_value(),
    )


def _build_opensearch_client(settings: Settings) -> OpenSearchClient:
    from src.adapter.opensearch.client import OpenSearchClient  # noqa: PLC0415

    parsed = urlparse(settings.opensearch_url)
    use_ssl = parsed.scheme == "https"
    return OpenSearchClient(
        hosts=[{"host": parsed.hostname, "port": parsed.port or (443 if use_ssl else 9200)}],
        http_auth=(
            settings.opensearch_username.get_secret_value(),
            settings.opensearch_password.get_secret_value(),
        ),
        use_ssl=use_ssl,
        verify_certs=False,
    )


# ---------------------------------------------------------------------------
# (a) seal_pending, per discovered (org_id, source_id) pair
# ---------------------------------------------------------------------------


async def _run_seal_pending_cycle_async() -> list[dict[str, str]]:
    from redis.asyncio import Redis as AsyncRedis  # noqa: PLC0415
    from sqlalchemy.ext.asyncio import create_async_engine  # noqa: PLC0415
    from sqlalchemy.pool import NullPool  # noqa: PLC0415

    from src.adapter.queue.stream_ingest import RedisStreamIngestAdapter  # noqa: PLC0415
    from src.adapter.repository.postgres_audit_log import (  # noqa: PLC0415
        PostgresAuditLogRepository,
    )
    from src.adapter.repository.postgres_sealed_batch import (  # noqa: PLC0415
        PostgresSealedBatchRepository,
    )
    from src.adapter.storage.sealed_batch_storage import S3SealedBatchStorage  # noqa: PLC0415
    from src.application.audit_log import AuditLogService  # noqa: PLC0415
    from src.application.batch_sealing import BatchSealingService  # noqa: PLC0415
    from src.application.sealing_trigger_policy import (  # noqa: PLC0415
        CompositeTriggerPolicy,
        SizeBoundTriggerPolicy,
        TimeBoundTriggerPolicy,
    )
    from src.application.timestamping import RFC3161TimestampService  # noqa: PLC0415
    from src.config import Settings  # noqa: PLC0415

    settings = Settings()  # type: ignore[call-arg]  # BaseSettings: real values come from env vars

    engine = create_async_engine(settings.database_url.get_secret_value(), poolclass=NullPool)
    redis_client = AsyncRedis.from_url(_stream_redis_url(settings))

    try:
        stream_adapter = RedisStreamIngestAdapter(redis_client)
        sealed_batch_repo = PostgresSealedBatchRepository(engine)
        audit_repo = PostgresAuditLogRepository(engine)
        audit_service = AuditLogService(audit_repo)
        timestamp_service = RFC3161TimestampService(settings.tsa_url) if settings.tsa_url else None
        storage = S3SealedBatchStorage(
            endpoint_url=_minio_endpoint_url(settings),
            access_key=settings.minio_access_key.get_secret_value(),
            secret_key=settings.minio_secret_key.get_secret_value(),
        )
        trigger_policy = CompositeTriggerPolicy(
            [
                SizeBoundTriggerPolicy(max_events=_SEAL_MAX_EVENTS),
                TimeBoundTriggerPolicy(max_age_seconds=_SEAL_MAX_AGE_SECONDS),
            ]
        )
        sealing_service = BatchSealingService(
            stream_adapter,
            storage,
            timestamp_service,
            audit_service,
            sealed_batch_repo,
            trigger_policy,
            consumer_name="kronos-beat-sealer",
            stall_alert_after_seconds=_SEAL_STALL_ALERT_AFTER_SECONDS,
        )

        pairs = await stream_adapter.list_active_streams()
        sealed_descriptors: list[dict[str, str]] = []
        for org_id, source_id in pairs:
            try:
                sealed = await sealing_service.seal_pending(org_id, source_id)
            except Exception:
                # One (org, source) pair's real failure (e.g. a transient
                # WORM/TSA outage -- BatchSealingService itself already
                # guarantees the underlying stream events stay unacked and
                # safe to retry next cycle, see its own docstring) must
                # never block every other pair's own real seal attempt this
                # cycle -- same "one bad thing doesn't sink the batch"
                # philosophy StreamNormalizationService's own per-event
                # dead-lettering already established, applied per-pair here.
                logger.exception(
                    "seal_pending_cycle_pair_failed",
                    extra={"org_id": str(org_id), "source_id": source_id},
                )
                continue
            if sealed is not None:
                sealed_descriptors.append(
                    {
                        "org_id": str(org_id),
                        "source_id": source_id,
                        "batch_id": str(sealed.batch_id),
                    }
                )
        logger.info(
            "seal_pending_cycle_done",
            extra={"pairs_considered": len(pairs), "batches_sealed": len(sealed_descriptors)},
        )
        return sealed_descriptors
    finally:
        await redis_client.aclose()
        await engine.dispose()


def run_seal_pending_cycle() -> list[dict[str, str]]:
    """Run one real seal_pending() cycle across every discovered (org,
    source) pair. Returns one descriptor per newly sealed batch (empty list
    if nothing was ready to seal this cycle -- an honest, expected outcome,
    not an error)."""
    return asyncio.run(_run_seal_pending_cycle_async())


# ---------------------------------------------------------------------------
# (b) normalize_batch, event-driven per newly-sealed batch
# ---------------------------------------------------------------------------


async def _run_normalize_batch_async(org_id: uuid.UUID, batch_id: uuid.UUID) -> dict[str, object]:
    from sqlalchemy.ext.asyncio import create_async_engine  # noqa: PLC0415
    from sqlalchemy.pool import NullPool  # noqa: PLC0415

    from src.adapter.repository.postgres_audit_log import (  # noqa: PLC0415
        PostgresAuditLogRepository,
    )
    from src.adapter.repository.postgres_dead_letter import (  # noqa: PLC0415
        PostgresDeadLetterSink,
    )
    from src.adapter.repository.postgres_sealed_batch import (  # noqa: PLC0415
        PostgresSealedBatchRepository,
    )
    from src.adapter.storage.sealed_batch_storage import S3SealedBatchStorage  # noqa: PLC0415
    from src.application.audit_log import AuditLogService  # noqa: PLC0415
    from src.application.stream_normalization import StreamNormalizationService  # noqa: PLC0415
    from src.application.stream_source_registry import (  # noqa: PLC0415
        get_default_stream_normalizer_registry,
    )
    from src.application.timeline_ingest import TimelineIngestionService  # noqa: PLC0415
    from src.config import Settings  # noqa: PLC0415

    settings = Settings()  # type: ignore[call-arg]  # BaseSettings: real values come from env vars

    engine = create_async_engine(settings.database_url.get_secret_value(), poolclass=NullPool)
    opensearch = _build_opensearch_client(settings)

    try:
        keycloak_admin = _build_keycloak_admin_client(settings)
        org_alias = await keycloak_admin.get_organization_alias(org_id)
        if org_alias is None:
            raise OrgAliasNotFoundError(
                f"org_id={org_id} (from sealed batch {batch_id}) has no real Keycloak "
                "organization -- refusing to guess an index name for it"
            )

        audit_repo = PostgresAuditLogRepository(engine)
        audit_service = AuditLogService(audit_repo)
        sealed_batch_repo = PostgresSealedBatchRepository(engine)
        dead_letter_sink = PostgresDeadLetterSink(engine)
        storage = S3SealedBatchStorage(
            endpoint_url=_minio_endpoint_url(settings),
            access_key=settings.minio_access_key.get_secret_value(),
            secret_key=settings.minio_secret_key.get_secret_value(),
        )
        ingestion = TimelineIngestionService(
            opensearch=opensearch,
            audit_log=audit_service,
            security_enabled=settings.opensearch_security_enabled,
        )
        normalizer_registry = get_default_stream_normalizer_registry()
        normalization_service = StreamNormalizationService(
            sealed_batch_repo,
            storage,
            ingestion,
            normalizer_registry,
            dead_letter_sink,
            audit_service,
        )

        result = await normalization_service.normalize_batch(org_id, batch_id, org_alias=org_alias)
        logger.info(
            "normalize_stream_batch_done",
            extra={
                "org_id": str(org_id),
                "batch_id": str(batch_id),
                "indexed_count": result.indexed_count,
                "dead_lettered_count": result.dead_lettered_count,
            },
        )
        return {
            "org_id": str(org_id),
            "batch_id": str(batch_id),
            "indexed_count": result.indexed_count,
            "dead_lettered_count": result.dead_lettered_count,
        }
    finally:
        await engine.dispose()
        await opensearch.close()


def run_normalize_batch(org_id: str, batch_id: str) -> dict[str, object]:
    """Normalize+index exactly one already-sealed batch. Called only as a
    chained follow-up from ``seal_pending_streams`` right after it seals a
    batch -- never separately scheduled (see this module's own docstring
    for why)."""
    return asyncio.run(_run_normalize_batch_async(uuid.UUID(org_id), uuid.UUID(batch_id)))


# ---------------------------------------------------------------------------
# (c) sync_org_findings, per real Keycloak organization
# ---------------------------------------------------------------------------


async def _run_sync_org_findings_cycle_async() -> dict[str, int]:
    from sqlalchemy.ext.asyncio import create_async_engine  # noqa: PLC0415
    from sqlalchemy.pool import NullPool  # noqa: PLC0415

    from src.adapter.opensearch.findings_client import (  # noqa: PLC0415
        SecurityAnalyticsFindingsClient,
    )
    from src.adapter.repository.postgres_audit_log import (  # noqa: PLC0415
        PostgresAuditLogRepository,
    )
    from src.adapter.repository.postgres_detection import (  # noqa: PLC0415
        PostgresDetectionRepository,
    )
    from src.application.audit_log import AuditLogService  # noqa: PLC0415
    from src.application.detection_sync import DetectionSyncService  # noqa: PLC0415
    from src.config import Settings  # noqa: PLC0415
    from src.domain.user import Role, TenantContext  # noqa: PLC0415

    settings = Settings()  # type: ignore[call-arg]  # BaseSettings: real values come from env vars

    engine = create_async_engine(settings.database_url.get_secret_value(), poolclass=NullPool)
    opensearch = _build_opensearch_client(settings)

    try:
        audit_repo = PostgresAuditLogRepository(engine)
        audit_service = AuditLogService(audit_repo)
        detection_repo = PostgresDetectionRepository(engine)
        findings_client = SecurityAnalyticsFindingsClient(
            base_url=settings.opensearch_url,
            admin_username=settings.opensearch_username.get_secret_value(),
            admin_password=settings.opensearch_password.get_secret_value(),
        )
        sync_service = DetectionSyncService(
            findings_client, detection_repo, audit_service, opensearch
        )

        keycloak_admin = _build_keycloak_admin_client(settings)
        organizations = await keycloak_admin.list_organizations()

        created_by_org: dict[str, int] = {}
        for org in organizations:
            tenant = TenantContext(
                org_id=org.org_id,
                org_alias=org.alias,
                user_id=_SYSTEM_USER_ID,
                username="celery-worker",
                roles=frozenset({Role.ANALYST}),
                correlation_id=str(uuid.uuid4()),
            )
            try:
                created = await sync_service.sync_org_findings(tenant)
            except Exception:
                # One org's real failure (e.g. that org's own SA detector
                # index momentarily unavailable) must never block every
                # other org's own real sync this cycle -- same per-item
                # isolation philosophy as run_seal_pending_cycle above.
                logger.exception(
                    "sync_org_findings_cycle_org_failed", extra={"org_id": str(org.org_id)}
                )
                continue
            created_by_org[str(org.org_id)] = created

        logger.info(
            "sync_org_findings_cycle_done",
            extra={
                "orgs_considered": len(organizations),
                "total_created": sum(created_by_org.values()),
            },
        )
        return created_by_org
    finally:
        await engine.dispose()
        await opensearch.close()


def run_sync_org_findings_cycle() -> dict[str, int]:
    """Run one real sync_org_findings() cycle across every real Keycloak
    organization. Returns {org_id: new_detection_count} (0 for an org with
    no new real findings this cycle -- an honest, expected outcome)."""
    return asyncio.run(_run_sync_org_findings_cycle_async())
