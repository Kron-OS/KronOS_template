"""Concrete dependency wiring from environment / Settings.

Called once at process startup — both from the FastAPI lifespan and from the
Celery worker_init signal.  Keeps configure_dependencies() calls in one place.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


async def wire_dependencies_async() -> None:
    """Async variant — used by FastAPI lifespan (already in async context)."""
    from sqlalchemy.ext.asyncio import create_async_engine  # noqa: PLC0415

    from src.adapter.opensearch.client import (
        OpenSearchClient as OpenSearchTimelineIndex,  # noqa: PLC0415
    )
    from src.adapter.queue.celery_queue import CeleryTaskQueue  # noqa: PLC0415
    from src.adapter.repository.postgres_audit_log import (  # noqa: PLC0415
        PostgresAuditLogRepository,
    )
    from src.adapter.repository.postgres_evidence import (  # noqa: PLC0415
        PostgresEvidenceRepository,
    )
    from src.adapter.storage.s3 import S3EvidenceStorage  # noqa: PLC0415
    from src.config import Settings  # noqa: PLC0415
    from src.external.dependencies import (  # noqa: PLC0415
        build_step_up_ticket_store,
        configure_clamav_from_settings,
        configure_dependencies,
        configure_step_up_auth,
    )

    settings = Settings()

    engine = create_async_engine(
        settings.database_url.get_secret_value(),
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
    )

    audit_repo = PostgresAuditLogRepository(engine)
    evidence_repo = PostgresEvidenceRepository(engine)

    await PostgresAuditLogRepository.create_tables(engine)
    await PostgresEvidenceRepository.create_tables(engine)

    _minio_scheme = "https" if settings.minio_use_tls else "http"
    storage = S3EvidenceStorage(
        endpoint_url=f"{_minio_scheme}://{settings.minio_endpoint}",
        presign_endpoint_url=(
            f"{_minio_scheme}://{settings.minio_public_endpoint}"
            if settings.minio_public_endpoint
            else None
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

    timestamp_service = (
        RFC3161TimestampService(settings.tsa_url) if settings.tsa_url else None
    )

    configure_dependencies(
        audit_log_repository=audit_repo,
        evidence_repository=evidence_repo,
        evidence_storage=storage,
        task_queue=task_queue,
        opensearch_client=opensearch,
        max_upload_bytes=settings.max_upload_bytes,
        presigned_expiry_seconds=settings.presigned_url_expiry_seconds,
        opensearch_dashboards_url=settings.opensearch_dashboards_url,
        timestamp_service=timestamp_service,
        default_retention_days=settings.minio_default_retention_days,
    )
    configure_clamav_from_settings()

    logger.info("startup: dependencies wired (async)")


def wire_dependencies_sync() -> None:
    """Sync variant — used by Celery worker_init signal (sync context)."""
    import asyncio  # noqa: PLC0415

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(wire_dependencies_async())
    finally:
        loop.close()
    logger.info("startup: dependencies wired (sync/celery)")
