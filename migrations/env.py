"""Alembic async environment for KronOS (Gap Audit P1-12 / Milestone V4).

Async template pattern per Alembic's own documented cookbook recipe
("Using Asyncio with Alembic", https://alembic.sqlalchemy.org/en/latest/cookbook.html#using-asyncio-with-alembic,
verified against the real installed alembic==1.19.0 via `alembic init -t async`
-- see poc/alembic_migration_baseline/README.md), adapted in two ways:

1. `create_async_engine(_database_url(), ...)` instead of the template's
   `async_engine_from_config(...)` -- this repo already has its own
   `settings.database_url` -> `create_async_engine()` convention
   (src/external/startup.py's wire_dependencies_async()); reusing the exact
   same call shape here keeps one pattern in the codebase instead of two.
2. The database URL comes from the `DATABASE_URL` environment variable
   directly (see `_database_url()` below), not from `alembic.ini`'s
   `sqlalchemy.url` (left as an unused placeholder) or a full
   `src.config.Settings()` instantiation -- Settings() requires ~15
   unrelated fields (MinIO/OpenSearch/Keycloak/Vault credentials) that a
   migration-only run (e.g. the `migrate` init-container, see
   docs/DATABASE_MIGRATIONS.md) has no reason to need. Every real KronOS
   process already receives DATABASE_URL via docker-compose today, so this
   introduces no new configuration surface.
"""

from __future__ import annotations

import asyncio
import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging. This line sets up loggers
# basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Repo root (parent of this migrations/ dir) -- alembic.ini's own
# `prepend_sys_path = .` already covers the common case (running `alembic`
# from the repo root), but inserting it explicitly here too means this
# env.py also works if a caller ever invokes alembic with `-c` from a
# different cwd (e.g. a container WORKDIR that isn't the repo root).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from migrations.target_metadata import build_target_metadata  # noqa: E402

# See migrations/target_metadata.py's own docstring for why this is a
# freshly-combined MetaData rather than one repository's own `_metadata`.
target_metadata = build_target_metadata()


def _database_url() -> str:
    """Real Postgres DSN from the environment (see module docstring)."""
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "DATABASE_URL must be set in the environment to run Alembic "
            "migrations, e.g. postgresql+asyncpg://kronos:...@postgres:5432/kronos "
            "-- see docs/DATABASE_MIGRATIONS.md."
        )
    return url


def run_migrations_offline() -> None:
    """Emit SQL to stdout without a live DB connection (`alembic upgrade head --sql`)."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    """Create a real async engine and run migrations through `run_sync()`."""
    connectable = create_async_engine(_database_url(), poolclass=pool.NullPool)

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
