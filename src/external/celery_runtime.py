"""Per-Celery-task, loop-scoped DB/OpenSearch resource construction.

wire_dependencies_sync() (worker_init) intentionally leaves the Postgres
repositories and OpenSearch client unconfigured as process singletons — see
its docstring. Each Celery task instead calls run_evidence_coro(), which
opens exactly one event loop (via asyncio.run), builds a fresh NullPool
engine + fresh AsyncOpenSearch client + the repositories/services that need
them INSIDE that loop, runs the task body, and disposes/closes everything
before the loop closes. This avoids ever reusing an asyncpg connection or
aiohttp session across event loops.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TypeVar
from urllib.parse import urlparse

from src.adapter.opensearch.client import OpenSearchClient
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository
from src.adapter.repository.postgres_evidence import PostgresEvidenceRepository
from src.application.audit_log import AuditLogService
from src.application.parsing_orchestration import ParsingOrchestrationService
from src.application.timeline_ingest import TimelineIngestionService
from src.config import Settings
from src.external.dependencies import (
    get_evidence_storage,
    get_parser_registry,
    get_task_queue,
)

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass
class TaskResources:
    """Loop-scoped resources for a single Celery task invocation."""

    evidence_repository: PostgresEvidenceRepository
    audit_log_repository: PostgresAuditLogRepository
    audit_log_service: AuditLogService
    orchestration_service: ParsingOrchestrationService


async def _build_task_resources() -> tuple[TaskResources, object, OpenSearchClient]:
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import NullPool

    settings = Settings()  # type: ignore[call-arg]  # BaseSettings: real values come from env vars
    engine = create_async_engine(settings.database_url.get_secret_value(), poolclass=NullPool)

    evidence_repo = PostgresEvidenceRepository(engine)
    audit_repo = PostgresAuditLogRepository(engine)
    audit_service = AuditLogService(audit_repo)

    parsed = urlparse(settings.opensearch_url)
    use_ssl = parsed.scheme == "https"
    opensearch = OpenSearchClient(
        hosts=[{"host": parsed.hostname, "port": parsed.port or (443 if use_ssl else 9200)}],
        http_auth=(
            settings.opensearch_username.get_secret_value(),
            settings.opensearch_password.get_secret_value(),
        ),
        use_ssl=use_ssl,
        verify_certs=False,
    )

    timeline_ingest = TimelineIngestionService(
        opensearch=opensearch,
        audit_log=audit_service,
        security_enabled=settings.opensearch_security_enabled,
    )
    orchestration = ParsingOrchestrationService(
        evidence_repository=evidence_repo,
        storage=get_evidence_storage(),
        audit_log=audit_service,
        parser_registry=get_parser_registry(),
        task_queue=get_task_queue(),
        timeline_ingest=timeline_ingest,
    )

    resources = TaskResources(
        evidence_repository=evidence_repo,
        audit_log_repository=audit_repo,
        audit_log_service=audit_service,
        orchestration_service=orchestration,
    )
    return resources, engine, opensearch


def run_evidence_coro(work: Callable[[TaskResources], Awaitable[T]]) -> T:
    """Run *work* against fresh, loop-scoped DB/OpenSearch resources.

    Opens one event loop, builds the resources inside it, runs work(resources),
    then disposes the engine and closes the OpenSearch client before the loop
    exits — the whole lifecycle (create, use, teardown) happens on one loop.
    """

    async def _runner() -> T:
        resources, engine, opensearch = await _build_task_resources()
        try:
            return await work(resources)
        finally:
            await engine.dispose()  # type: ignore[attr-defined]
            await opensearch.close()

    return asyncio.run(_runner())
