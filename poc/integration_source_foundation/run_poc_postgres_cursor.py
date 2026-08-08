"""PoC (c): PostgresSourceCursorRepository against the REAL shared dev
Postgres instance (docker-postgres-1, already running -- not a fresh
testcontainer, per this session's own constraint against spinning up new
long-lived infra beyond what's already there for a one-off adapter check).

Creates its own table (``integration_source_cursors``, additive, does not
touch any existing table/data), does a real INSERT, a real
on-conflict-do-update UPDATE, and a real SELECT, then cleans up the rows it
created (does NOT drop the table -- consistent with every other
``create_tables``-style repository in this codebase, which are all designed
to be idempotent/safe to leave behind for a real deployment).
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy.ext.asyncio import create_async_engine

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.adapter.repository.postgres_source_cursor import (  # noqa: E402
    PostgresSourceCursorRepository,
    source_cursors_table,
)
from src.domain.integration_source import SourceCursor  # noqa: E402

DATABASE_URL = "postgresql+asyncpg://kronos:kronos_dev_password@postgres:5432/kronos"


async def main() -> None:
    engine = create_async_engine(DATABASE_URL)
    try:
        print(f"=== Connecting to REAL shared dev Postgres: {DATABASE_URL.split('@')[1]} ===")
        await PostgresSourceCursorRepository.create_tables(engine)
        print("[1] create_tables() succeeded (CREATE TABLE IF NOT EXISTS integration_source_cursors)")

        repo = PostgresSourceCursorRepository(engine)
        org_id = uuid.uuid4()
        source_id = "poc-postgres-check"

        assert await repo.get(org_id, source_id) is None
        print("[2] get() on a never-seen (org, source) correctly returns None")

        cursor_v1 = SourceCursor(org_id=org_id, source_id=source_id, cursor_value="token-v1", updated_at=datetime.now(UTC))
        await repo.upsert(cursor_v1)
        fetched = await repo.get(org_id, source_id)
        print(f"[3] upsert() + get() round trip: {fetched}")
        assert fetched is not None
        assert fetched.cursor_value == "token-v1"

        cursor_v2 = SourceCursor(org_id=org_id, source_id=source_id, cursor_value="token-v2", updated_at=datetime.now(UTC))
        await repo.upsert(cursor_v2)
        fetched2 = await repo.get(org_id, source_id)
        print(f"[4] second upsert() (on-conflict-do-update) + get(): {fetched2}")
        assert fetched2 is not None
        assert fetched2.cursor_value == "token-v2"

        # Cleanup: remove only the rows this PoC run created.
        async with engine.begin() as conn:
            await conn.execute(
                source_cursors_table.delete().where(
                    source_cursors_table.c.org_id == org_id, source_cursors_table.c.source_id == source_id
                )
            )
        print("[5] cleanup: deleted the PoC's own row (table itself left in place, matches other repos' convention)")

        print("\n=== POSTGRES CURSOR REPOSITORY PoC: ALL ASSERTIONS PASSED ===")
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
