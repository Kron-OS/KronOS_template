"""Per-Celery-task, loop-scoped resource construction for the Defender POLL
beat task (Gap Audit 2026-08 P1-2 / roadmap Milestone V2, item b).

**Why this is its own module, not an addition to ``celery_runtime.py``.**
``celery_runtime.py``'s own ``TaskResources``/``_build_task_resources()``
are scoped to the evidence-parsing DAG (``process_intake``/``dispatch_parse``/
``parse_artefact_*``/``finalize_evidence``) and already documented, tested
collaborators for it. This task shares that module's *pattern* exactly
(build every loop-bound resource fresh inside this task's own
``asyncio.run()`` loop, dispose everything before the loop closes) but needs
a genuinely different resource set (an OAuth2 ``httpx.AsyncClient``, a Redis
stream/dedup pair, a ``PostgresSourceCursorRepository``) that has nothing to
do with evidence parsing -- bolting them onto ``TaskResources`` would make
every future evidence-DAG task pay for Defender-specific imports/fields it
never uses.

**The core design problem this module exists to solve (Gap Audit P1-2,
Milestone S's own flagged follow-up).** ``configure_defender_poll_source_
from_settings()`` (``src/external/dependencies.py``) builds one
process-lifetime ``httpx.AsyncClient`` specifically so
``OAuth2ClientCredentialsOutboundAuthStrategy``'s own in-memory token cache
(``src/external/middleware/integration_source_auth.py``) is reused across
calls -- but that client (and the ``asyncio`` primitives httpx holds
internally) is bound to whatever event loop was running when it was
constructed. ``wire_dependencies_sync()`` (the Celery ``worker_init`` path)
never calls that configure function for exactly this reason (see its own
2026-08-09 docstring comment): every Celery task here runs inside its own
fresh loop via ``asyncio.run()``, so reusing one httpx client across
invocations would eventually hand an ``asyncio`` primitive a closed loop,
the same "Future attached to a different loop" failure class
``celery_runtime.py``'s own docstring already documents for Postgres/
OpenSearch.

**Design choice made here: a fresh ``httpx.AsyncClient`` (and fresh OAuth2
token fetch) every poll cycle, not a dedicated long-lived event loop
thread.** Considered both options named in the Milestone V2 brief:

- *(picked)* Fresh, task-scoped client per invocation. Losing the token
  cache across cycles costs exactly one extra ``POST
  https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`` per poll
  cycle. Microsoft's own v2.0 client-credentials docs (`OAuth2 client
  credentials flow
  <https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow>`_,
  fetched 2026-08-10) show a real example token response with
  ``"expires_in": 3599`` (~60 minutes) -- at this task's own 10-minute poll
  interval (see ``celery_app.py``'s ``beat_schedule``), that means the
  cached-token optimization the FastAPI path's process-lifetime client
  buys would only ever save 5 of every 6 possible token fetches even if it
  worked safely here; the real risk being traded away (a cross-event-loop
  ``httpx``/``asyncio`` failure that would take the whole poll cycle down,
  repeatedly, until a worker restart) is categorically worse than one
  extra cheap token POST every 10 minutes. This is the same class of
  tradeoff ``celery_runtime.py`` already made for Postgres/OpenSearch, not
  a new risk-acceptance pattern invented here.
- *(rejected, for now)* A dedicated long-lived event loop owned by a
  Celery worker/beat process. Genuinely more correct (real cross-cycle
  token caching), but a novel addition to this codebase's Celery patterns
  (nothing here runs a background loop thread today) for a benefit
  (avoiding ~6 extra token POSTs/hour to an endpoint this connector calls
  anyway) that does not currently justify the added operational surface.
  Revisit if a future poll-mode source's auth handshake is expensive
  enough that per-cycle re-authentication becomes the bottleneck, not the
  Graph API calls themselves.

Every other loop-bound resource here (Postgres cursor repository, Redis
stream/dedup clients) follows ``celery_runtime.py``'s own already-established
"build fresh, use, dispose before the loop exits" shape exactly -- nothing
new invented for those.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from urllib.parse import urlsplit, urlunsplit

logger = logging.getLogger(__name__)


class DefenderPollNotConfiguredError(RuntimeError):
    """Raised when Defender credentials or the target KronOS org are unset.

    An honest, expected pre-production state (mirrors ``configure_defender_
    poll_source_from_settings()``'s own "no real Entra ID app registration
    exists yet" framing) -- the calling Celery task treats this the same as
    every other beat task's own "repository not configured; skipping" idiom
    (see ``abort_orphan_uploads`` et al. in ``celery_app.py``), never as a
    retryable failure.
    """


async def _run_defender_poll_cycle_async() -> int:
    import httpx
    from redis.asyncio import Redis as AsyncRedis
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import NullPool

    from src.adapter.queue.event_dedup import RedisEventDedupChecker
    from src.adapter.queue.stream_ingest import RedisStreamIngestAdapter
    from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository
    from src.adapter.repository.postgres_source_cursor import PostgresSourceCursorRepository
    from src.application.audit_log import AuditLogService
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

    if (
        not settings.defender_tenant_id
        or not settings.defender_client_id
        or (settings.defender_client_secret is None)
    ):
        raise DefenderPollNotConfiguredError(
            "Defender poll source not configured "
            "(defender_tenant_id/defender_client_id/defender_client_secret unset)"
        )
    if not settings.defender_poll_org_id:
        raise DefenderPollNotConfiguredError(
            "defender_poll_org_id not configured -- no KronOS org to attribute "
            "this Defender alerts feed to"
        )

    # A malformed (but non-empty) defender_poll_org_id is a real deployment
    # misconfiguration, not an honest "unconfigured" state -- let ValueError
    # propagate to the task's generic except/retry branch (CLAUDE.md
    # invariant #8: fail loudly) rather than folding it into
    # DefenderPollNotConfiguredError's own silent-skip handling above.
    org_id = uuid.UUID(settings.defender_poll_org_id)
    source_id = settings.defender_poll_source_id

    engine = create_async_engine(settings.database_url.get_secret_value(), poolclass=NullPool)
    redis_url = settings.redis_url.get_secret_value()
    parsed_redis = urlsplit(redis_url)
    stream_redis_url = urlunsplit(parsed_redis._replace(path=f"/{settings.stream_redis_db}"))
    redis_client = AsyncRedis.from_url(stream_redis_url)

    try:
        async with httpx.AsyncClient() as http_client:
            auth_strategy = OAuth2ClientCredentialsOutboundAuthStrategy(
                http_client,
                token_endpoint=(
                    f"https://login.microsoftonline.com/{settings.defender_tenant_id}"
                    "/oauth2/v2.0/token"
                ),
                client_id=settings.defender_client_id,
                client_secret=settings.defender_client_secret.get_secret_value(),
                scope="https://graph.microsoft.com/.default",
            )
            source = DefenderPollSource(
                http_client,
                base_url=settings.defender_graph_base_url,
                auth_strategy=auth_strategy,
            )
            registry = IntegrationSourceRegistry()
            registry.register(source)

            audit_repo = PostgresAuditLogRepository(engine)
            audit_service = AuditLogService(audit_repo)
            cursor_repo = PostgresSourceCursorRepository(engine)
            dedup_checker = RedisEventDedupChecker(redis_client)
            stream_adapter = RedisStreamIngestAdapter(redis_client)

            ingest_service = IntegrationSourceIngestService(
                registry,
                stream_adapter,
                dedup_checker,
                cursor_repo,
                audit_service,
                max_stream_length=get_integration_source_max_stream_length(),
                dedup_ttl_seconds=get_integration_source_dedup_ttl_seconds(),
            )

            identity = IntegrationSourceIdentity(
                org_id=org_id,
                source_id=source_id,
                source_type=source.source_type,
                auth_method="oauth2-client-credentials",
            )
            result = await ingest_service.run_poll_cycle(identity)
            accepted = sum(1 for outcome in result.outcomes if outcome.accepted)
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
            return accepted
    finally:
        await redis_client.aclose()
        await engine.dispose()


def run_defender_poll_cycle() -> int:
    """Run exactly one real Defender ``alerts_v2`` poll cycle end-to-end.

    Opens one event loop (mirrors ``celery_runtime.run_evidence_coro``),
    builds every loop-bound resource (httpx client, Redis clients, Postgres
    engine) fresh inside it, runs the cycle, and disposes everything before
    the loop closes.

    Raises :class:`DefenderPollNotConfiguredError` if Defender credentials
    or the target org are unset (an honest, expected pre-production state).
    Any other exception is a real failure and propagates unchanged --
    ``IntegrationSourceIngestService.run_poll_cycle`` has already audited a
    real poll failure (``INTEGRATION_SOURCE_POLL_FAILED``) before raising it
    (CLAUDE.md invariant #8: fail loudly, audit before erasing the attempt).
    """
    return asyncio.run(_run_defender_poll_cycle_async())
