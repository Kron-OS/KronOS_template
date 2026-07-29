"""Postgres advisory lock shared by every repository's create_tables().

The FastAPI app, celery-beat, and every Celery worker (celery-worker,
celery-worker-plaso, ...) each call create_tables() independently at process
startup, so several processes hit the same fresh database at once.
`create_all(checkfirst=True)` only protects against re-creating a table
already visible to *that* connection — it does not stop two connections from
both seeing "table not present" and issuing CREATE TABLE at the same instant.
When that happens, Postgres's own catalog inserts (pg_type/pg_class) can
collide and raise `duplicate key value violates unique constraint
"pg_type_typname_nsp_index"` even though the DDL is logically idempotent.

Taking this transaction-scoped advisory lock before create_all forces every
process to queue up: the first one creates whatever is missing, the rest
block until it commits (which releases the lock), then see the tables
already exist and skip creation — no concurrent CREATE TABLE ever happens.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncConnection

# Arbitrary bigint, just needs to be the same constant across every
# repository's create_tables() so they all serialize against one another.
_SCHEMA_CREATION_LOCK_KEY = 875_309_001


async def acquire_schema_creation_lock(conn: AsyncConnection) -> None:
    """Block until exclusive access to run schema DDL; auto-released at commit/rollback."""
    await conn.execute(
        sa.text("SELECT pg_advisory_xact_lock(:key)"), {"key": _SCHEMA_CREATION_LOCK_KEY}
    )
