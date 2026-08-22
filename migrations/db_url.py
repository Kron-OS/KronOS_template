"""Pure, alembic-context-independent DATABASE_URL resolution for migrations/env.py.

Split out from env.py (which imports `alembic.context` at module level — an
unconfigured proxy outside a real `alembic` invocation, e.g. `context.config`
raises `AttributeError` if accessed via a plain `import migrations.env` —
confirmed directly, not assumed). That makes env.py itself unsafe to import
from a unit test, so this one real behaviour (resolving the DSN from either a
plain env var or a mounted secret file) gets its own real, direct unit test
(tests/unit/test_migrations_db_url.py) instead of only being exercised
end-to-end via a real `alembic upgrade head` run.
"""

from __future__ import annotations

import os
from pathlib import Path


def resolve_database_url() -> str:
    """Resolve the Postgres DSN alembic should connect with.

    Checks `DATABASE_URL` directly first (docker-compose.dev.yml's existing
    plain-env-var convention — completely unchanged), then falls back to
    `DATABASE_URL_FILE` (Gap Audit Milestone MM: db-migrate previously baked
    the resolved DSN, password included, straight into
    docker-compose.prod.yml's `environment:` block — `docker inspect
    --format '{{json .Config.Env}}'` returned it in plaintext, see
    poc/backend_prod_secret_config_env_exposure/). `DATABASE_URL_FILE`
    mirrors the official `postgres` image's own `POSTGRES_PASSWORD_FILE`
    convention, already used elsewhere in this same compose file, rather
    than inventing a new one.

    Deliberately does NOT go through `src.config.Settings()`'s own new
    `secrets_dir` support (see that module's docstring) — migrations/env.py
    has never used Settings() (it requires ~15 unrelated MinIO/OpenSearch/
    Keycloak/Vault fields a migration-only run has no reason to need) and
    this keeps that pre-existing, intentional design unchanged.
    """
    url = os.environ.get("DATABASE_URL")
    if url and url.strip():
        return url.strip()

    url_file = os.environ.get("DATABASE_URL_FILE")
    if url_file:
        path = Path(url_file)
        if not path.is_file():
            raise RuntimeError(
                f"DATABASE_URL_FILE={url_file!r} does not exist or is not a file "
                "-- check the Docker secret is actually mounted at that path."
            )
        content = path.read_text().strip()
        if not content:
            raise RuntimeError(
                f"DATABASE_URL_FILE={url_file!r} is empty -- the secret file was "
                "created/mounted but never given real content."
            )
        return content

    raise RuntimeError(
        "DATABASE_URL (or DATABASE_URL_FILE pointing at a real secret file) must "
        "be set in the environment to run Alembic migrations, e.g. "
        "postgresql+asyncpg://kronos:...@postgres:5432/kronos -- see "
        "docs/DATABASE_MIGRATIONS.md."
    )
