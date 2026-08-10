"""PoC for Gap Audit V2 fix (c): SourceCursorRepository's live DI default
flip from InMemorySourceCursorRepository to PostgresSourceCursorRepository.

Proves the actual claim CLAUDE.md SS F requires: a cursor persisted by one
PostgresSourceCursorRepository instance is readable by a COMPLETELY FRESH
instance (new AsyncEngine, no shared Python object, no in-process cache) --
i.e. this is a real cross-process-restart-equivalent round-trip against the
real shared dev-stack Postgres (docker-postgres-1, kronos/kronos db, per
docker/docker-compose.dev.yml), not a mock and not a same-instance re-read.

Version pinned: sqlalchemy 2.0.51, asyncpg 0.31.0 (see pyproject.toml/venv
freeze) against postgres:16-alpine (docker-compose.dev.yml image tag).

How to run (dev stack's own postgres container must already be running --
it was, per `docker ps`, confirmed NOT started/stopped by this PoC):
    source /home/reca/venv/bin/activate
    python poc/v2_connector_wiring/source_cursor_postgres_default/run_poc.py
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import create_async_engine

from src.adapter.repository.postgres_source_cursor import (
    PostgresSourceCursorRepository,
    source_cursors_table,
)

DATABASE_URL = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"


async def main() -> None:
    test_org_id = uuid.uuid4()
    test_source_id = f"poc-defender-{uuid.uuid4().hex[:8]}"
    cursor_value = "2026-08-10T12:34:56.789Z"

    print("[1] Real engine #1 (fresh AsyncEngine) -> create_tables (checkfirst) ...")
    engine_1 = create_async_engine(DATABASE_URL)
    await PostgresSourceCursorRepository.create_tables(engine_1)
    repo_1 = PostgresSourceCursorRepository(engine_1)

    print("[2] repo_1.get() before any upsert (expect None) ...")
    before = await repo_1.get(test_org_id, test_source_id)
    print(f"    -> {before!r}")
    assert before is None, "expected no cursor before upsert"

    print(
        f"[3] repo_1.upsert(org={test_org_id}, source={test_source_id}, "
        f"cursor_value={cursor_value!r}) ..."
    )
    from src.domain.integration_source import SourceCursor

    written = await repo_1.upsert(
        SourceCursor(
            org_id=test_org_id,
            source_id=test_source_id,
            cursor_value=cursor_value,
            updated_at=datetime.now(UTC),
        )
    )
    print(f"    -> wrote {written!r}")

    await engine_1.dispose()
    print("[4] engine_1 disposed -- repo_1 and its connection are gone.")

    print(
        "[5] Real engine #2 (BRAND NEW AsyncEngine, no shared state with "
        "engine_1/repo_1) -> repo_2 ..."
    )
    engine_2 = create_async_engine(DATABASE_URL)
    repo_2 = PostgresSourceCursorRepository(engine_2)

    print(
        f"[6] repo_2.get(org={test_org_id}, source={test_source_id}) "
        "-- this is the real claim under test: does the cursor survive a "
        "fresh repository instantiation (mirrors a backend/worker restart)?"
    )
    fetched = await repo_2.get(test_org_id, test_source_id)
    print(f"    -> {fetched!r}")
    assert fetched is not None, "FAIL: cursor did not survive fresh repository instantiation"
    assert fetched.cursor_value == cursor_value
    assert fetched.org_id == test_org_id
    assert fetched.source_id == test_source_id
    print("[7] PASS: cursor value matches exactly across a fresh repository instance.")

    print("[8] Upserting again via repo_2 to prove update-on-conflict path too ...")
    new_cursor_value = "2026-08-10T13:00:00.000Z"
    await repo_2.upsert(
        SourceCursor(
            org_id=test_org_id,
            source_id=test_source_id,
            cursor_value=new_cursor_value,
            updated_at=datetime.now(UTC),
        )
    )
    refetched = await repo_2.get(test_org_id, test_source_id)
    assert refetched is not None
    assert refetched.cursor_value == new_cursor_value
    print(f"    -> {refetched!r} (PASS: on-conflict update overwrote the row, not a new one)")

    print("[9] Cleaning up test row from the shared dev-stack Postgres ...")
    async with engine_2.begin() as conn:
        result = await conn.execute(
            source_cursors_table.delete().where(
                source_cursors_table.c.org_id == test_org_id,
                source_cursors_table.c.source_id == test_source_id,
            )
        )
        print(f"    -> deleted {result.rowcount} row(s)")

    await engine_2.dispose()
    print("\nALL ASSERTIONS PASSED.")


if __name__ == "__main__":
    asyncio.run(main())
