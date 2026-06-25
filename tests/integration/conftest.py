"""Integration test fixtures: Postgres + MinIO testcontainers."""

from __future__ import annotations

import shutil

import pytest

# Skip all integration tests when Docker is not available.
if not shutil.which("docker"):
    pytest.skip("Docker not available — skipping integration tests", allow_module_level=True)


@pytest.fixture(scope="session")
def postgres_engine():  # type: ignore[no-untyped-def]
    """Start a Postgres container and return a SQLAlchemy AsyncEngine."""
    from testcontainers.postgres import PostgresContainer

    with PostgresContainer("postgres:16-alpine") as pg:
        import asyncio

        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.pool import NullPool

        url = pg.get_connection_url().replace("psycopg2", "asyncpg")
        # NullPool: the engine is session-scoped but pytest-asyncio runs each
        # test in its own event loop. asyncpg connections are bound to the loop
        # that created them, so a pooled connection reused across loops raises
        # "another operation is in progress". NullPool opens a fresh connection
        # on the current loop per operation and closes it after, avoiding reuse.
        engine = create_async_engine(url, echo=False, poolclass=NullPool)

        # Create tables synchronously before yielding.
        async def _setup() -> None:
            from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository
            from src.adapter.repository.postgres_evidence import PostgresEvidenceRepository

            await PostgresEvidenceRepository.create_tables(engine)
            await PostgresAuditLogRepository.create_tables(engine)

        asyncio.run(_setup())
        yield engine
        asyncio.run(engine.dispose())


@pytest.fixture(scope="session")
def minio_storage(tmp_path_factory):  # type: ignore[no-untyped-def]
    """Start a MinIO container and return a configured S3EvidenceStorage."""
    try:
        from testcontainers.minio import MinioContainer
    except ImportError:
        pytest.skip("testcontainers[minio] not installed")

    with MinioContainer() as minio:
        from src.adapter.storage.s3 import S3EvidenceStorage

        storage = S3EvidenceStorage(
            endpoint_url=minio.get_url(),
            access_key=minio.access_key,
            secret_key=minio.secret_key,
            quarantine_bucket_prefix="kronos-evidence",
            evidence_bucket_prefix="kronos-evidence",
            use_tls=False,
        )
        yield storage
