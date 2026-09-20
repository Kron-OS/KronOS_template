"""Per-Celery-task, loop-scoped resource construction for the Defender POLL
beat task (Gap Audit 2026-08 P1-2 / roadmap Milestone V2, item b; per-org
config: connector marketplace, `/admin/connectors`).

**Why this is its own module, not an addition to ``celery_runtime.py``.**
``celery_runtime.py``'s own ``TaskResources``/``_build_task_resources()``
are scoped to the evidence-parsing DAG (``process_intake``/``dispatch_parse``/
``parse_artefact_*``/``finalize_evidence``) and already documented, tested
collaborators for it. This task shares that module's *pattern* exactly
(build every loop-bound resource fresh inside this task's own
``asyncio.run()`` loop, dispose everything before the loop closes) but needs
a genuinely different resource set (an OAuth2 ``httpx.AsyncClient``, a Redis
stream/dedup pair, a ``PostgresSourceCursorRepository``, and now
``PostgresConnectorConfigRepository``/``VaultSecretStore``) that has nothing
to do with evidence parsing.

**Per-org rewrite (connector marketplace).** This used to poll exactly ONE
hardcoded KronOS org (``settings.defender_poll_org_id``), with credentials
from global env vars. It now discovers every org with an enabled
``ms-defender-alerts`` row in ``connector_configs`` (via
``PostgresConnectorConfigRepository.list_all_enabled_by_source_type``,
built from THIS task's own per-cycle engine, never the FastAPI process's
DI singleton -- ``wire_dependencies_sync()``'s own docstring is explicit
that Celery must never share a loop-bound engine/client across tasks) and
polls each with that org's own resolved credentials. Zero enabled orgs is
an honest, expected no-op (this feature can ship before any org has
configured Defender) -- NOT ``DefenderPollNotConfiguredError`` anymore,
which is now reserved for the one still-genuinely-exceptional case: the
per-org secret store itself isn't wired on this deployment
(``Settings.vault_connectors_approle_creds_file`` unset), meaning the
feature cannot function for ANY org regardless of how many have tried to
configure it.

**Vault-unreachable vs. per-org failure -- a real, load-bearing
distinction, not just an exception hierarchy exercise.** A connection-level
Vault failure (AppRole login itself fails) means Vault is down or
misconfigured for every org, not just the one being resolved when it's
first observed -- looping through the rest and recording N identical,
uninformative failures would spam the audit log and (via ``record_failure``'s
own auto-disable-at-threshold logic) risk auto-disabling every org's
otherwise-healthy config over a single infrastructure outage. This module
distinguishes that case (abort the whole cycle immediately, one log line,
no per-org ``record_failure`` calls at all) from a genuine per-org problem
(bad/expired Defender credentials for THAT org, or that org's own Graph
API call failing) via ``VaultSecretStore``'s own error message shape --
see ``_is_vault_connection_error`` below.

**Fresh httpx.AsyncClient per org, per cycle.** The FastAPI process's old
global Defender wiring (removed, Phase 7 cleanup) used to keep one
process-lifetime ``httpx.AsyncClient`` alive specifically so
``OAuth2ClientCredentialsOutboundAuthStrategy``'s own token cache persisted
across poll cycles -- that optimization never applied here (cross-event-loop
sharing risk, see this module's git history for the original analysis), and
now doubly doesn't apply since each org's client needs that org's own
credentials anyway, so there is no shared state to optimize across orgs
within one cycle either.
"""

from __future__ import annotations

import asyncio
import logging
import uuid

from src.exceptions import StorageError

logger = logging.getLogger(__name__)

_SOURCE_TYPE = "ms-defender-alerts"


class DefenderPollNotConfiguredError(RuntimeError):
    """Raised only when the per-org connector secret store itself isn't
    wired on this deployment (``Settings.vault_connectors_approle_creds_file``
    unset) -- meaning the Defender POLL connector cannot function for ANY
    org, not merely that zero orgs have configured it yet (that case is a
    normal, expected no-op, not an error -- see this module's own
    docstring)."""


def _is_vault_connection_error(exc: StorageError) -> bool:
    """True if *exc* represents Vault/AppRole itself being unreachable
    (affects every org), False if it's some other per-org storage problem.

    ``VaultSecretStore._login``/``_get_client`` wrap AppRole login failures
    in a ``StorageError`` whose message always starts with this exact
    prefix (see that module's own ``_login`` method) -- a real, stable
    string this module can key on without VaultSecretStore needing a
    dedicated exception subclass for what is, underneath, still honestly a
    StorageError.
    """
    return str(exc).startswith("VaultSecretStore: AppRole login failed")


async def _run_defender_poll_cycle_async() -> int:
    import httpx
    from redis.asyncio import Redis as AsyncRedis
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import NullPool

    from src.adapter.queue.event_dedup import RedisEventDedupChecker
    from src.adapter.queue.stream_ingest import RedisStreamIngestAdapter
    from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository
    from src.adapter.repository.postgres_connector_config import (
        PostgresConnectorConfigRepository,
    )
    from src.adapter.repository.postgres_source_cursor import PostgresSourceCursorRepository
    from src.adapter.secret.vault_secret_store import VaultSecretStore
    from src.application.audit_log import AuditLogService
    from src.application.connector_catalog import ConnectorCatalog
    from src.application.connector_config import ConnectorConfigService
    from src.application.integration_source import IntegrationSourceRegistry
    from src.application.integration_source_ingest import IntegrationSourceIngestService
    from src.config import Settings
    from src.domain.integration_source import IntegrationSourceIdentity
    from src.external.dependencies import (
        get_integration_source_dedup_ttl_seconds,
        get_integration_source_max_stream_length,
    )
    from src.external.integration_sources.defender import DefenderPollSource
    from src.external.middleware.integration_source_auth import (
        OAuth2ClientCredentialsOutboundAuthStrategy,
    )

    settings = Settings()  # type: ignore[call-arg]  # BaseSettings: real values come from env vars

    if not settings.vault_connectors_approle_creds_file:
        raise DefenderPollNotConfiguredError(
            "Per-org connector secret store not configured on this deployment "
            "(Settings.vault_connectors_approle_creds_file unset) -- the Defender "
            "POLL connector cannot function for any org until Vault is wired."
        )

    engine = create_async_engine(settings.database_url.get_secret_value(), poolclass=NullPool)
    from urllib.parse import urlsplit, urlunsplit  # noqa: PLC0415

    redis_url = settings.redis_url.get_secret_value()
    parsed_redis = urlsplit(redis_url)
    stream_redis_url = urlunsplit(parsed_redis._replace(path=f"/{settings.stream_redis_db}"))
    redis_client = AsyncRedis.from_url(stream_redis_url)

    try:
        connector_config_repo = PostgresConnectorConfigRepository(engine)
        secret_store = VaultSecretStore.from_approle_creds_file(
            settings.vault_url, settings.vault_connectors_approle_creds_file
        )
        audit_repo = PostgresAuditLogRepository(engine)
        audit_service = AuditLogService(audit_repo)
        connector_config_service = ConnectorConfigService(
            ConnectorCatalog(), connector_config_repo, secret_store, audit_service
        )

        enabled_configs = await connector_config_repo.list_all_enabled_by_source_type(_SOURCE_TYPE)
        if not enabled_configs:
            logger.info("defender_poll_no_enabled_orgs")
            return 0

        cursor_repo = PostgresSourceCursorRepository(engine)
        dedup_checker = RedisEventDedupChecker(redis_client)
        stream_adapter = RedisStreamIngestAdapter(redis_client)
        max_stream_length = get_integration_source_max_stream_length()
        dedup_ttl_seconds = get_integration_source_dedup_ttl_seconds()

        total_accepted = 0
        for config_row in enabled_configs:
            org_id: uuid.UUID = config_row.org_id
            try:
                resolved = await connector_config_service.resolve_runtime_config(org_id, _SOURCE_TYPE)
            except StorageError as exc:
                if _is_vault_connection_error(exc):
                    # Vault itself is down -- true for every remaining org
                    # too. Abort the whole cycle now rather than repeating
                    # this identical failure (and a misleading per-org
                    # record_failure) once per enabled org.
                    logger.error(
                        "defender_poll_vault_unreachable_aborting_cycle",
                        extra={"error": str(exc), "orgs_not_attempted": len(enabled_configs)},
                    )
                    break
                logger.error(
                    "defender_poll_org_config_resolve_failed",
                    extra={"org_id": str(org_id), "error": str(exc)},
                )
                await connector_config_service.record_failure(org_id, _SOURCE_TYPE)
                continue

            if resolved is None:
                # Disabled/deleted between list_all_enabled_by_source_type
                # and here -- a benign race with an admin action, not a
                # failure to record.
                continue

            source_id = f"{_SOURCE_TYPE}-{org_id}"
            try:
                async with httpx.AsyncClient() as http_client:
                    auth_strategy = OAuth2ClientCredentialsOutboundAuthStrategy(
                        http_client,
                        token_endpoint=(
                            f"https://login.microsoftonline.com/{resolved['defender_tenant_id']}"
                            "/oauth2/v2.0/token"
                        ),
                        client_id=resolved["defender_client_id"],
                        client_secret=resolved["defender_client_secret"],
                        scope="https://graph.microsoft.com/.default",
                    )
                    source = DefenderPollSource(
                        http_client,
                        base_url=resolved.get(
                            "defender_graph_base_url", "https://api.security.microsoft.com"
                        ),
                        auth_strategy=auth_strategy,
                    )
                    registry = IntegrationSourceRegistry()
                    registry.register(source)
                    ingest_service = IntegrationSourceIngestService(
                        registry,
                        stream_adapter,
                        dedup_checker,
                        cursor_repo,
                        audit_service,
                        max_stream_length=max_stream_length,
                        dedup_ttl_seconds=dedup_ttl_seconds,
                    )
                    identity = IntegrationSourceIdentity(
                        org_id=org_id,
                        source_id=source_id,
                        source_type=source.source_type,
                        auth_method="oauth2-client-credentials",
                    )
                    result = await ingest_service.run_poll_cycle(identity)
                    accepted = sum(1 for outcome in result.outcomes if outcome.accepted)
                    total_accepted += accepted
                    await connector_config_service.record_success(org_id, _SOURCE_TYPE)
                    logger.info(
                        "defender_poll_cycle_done",
                        extra={
                            "org_id": str(org_id),
                            "source_id": source_id,
                            "event_count": len(result.outcomes),
                            "accepted_count": accepted,
                            "cursor_advanced": result.cursor_advanced,
                        },
                    )
            except Exception as exc:  # noqa: BLE001 -- per-org isolation: one org's failure must not abort the cycle
                logger.error(
                    "defender_poll_org_failed", extra={"org_id": str(org_id), "error": str(exc)}
                )
                await connector_config_service.record_failure(org_id, _SOURCE_TYPE)
                continue

        return total_accepted
    finally:
        await redis_client.aclose()
        await engine.dispose()


def run_defender_poll_cycle() -> int:
    """Run one real Defender ``alerts_v2`` poll cycle for every org with an
    enabled ``ms-defender-alerts`` connector config, end-to-end.

    Opens one event loop (mirrors ``celery_runtime.run_evidence_coro``),
    builds every loop-bound resource fresh inside it, runs the cycle per
    org, and disposes everything before the loop closes.

    Raises :class:`DefenderPollNotConfiguredError` only if the per-org
    secret store itself isn't wired on this deployment. Zero enabled orgs
    is a normal no-op (returns 0). Any other exception is a real failure
    and propagates unchanged.
    """
    return asyncio.run(_run_defender_poll_cycle_async())
