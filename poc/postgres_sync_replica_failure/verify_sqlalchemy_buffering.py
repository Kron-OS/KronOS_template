"""Standalone check (own throwaway kronos-poc-sqla-stream-pg container, port
15432, 300k dummy rows -- NOT the shared dev stack): does SQLAlchemy asyncio's
`conn.execute(select(...))` + `for row in result: yield` pattern -- the exact
pattern used verbatim by src/adapter/repository/postgres_audit_log.py's
stream_by_org() and src/adapter/repository/postgres_evidence.py's
stream_all_by_state()/stream_all_quota_held() -- actually stream from
Postgres row-by-row, or fully buffer the result set in memory before the
first row is yielded?

Method: instrument the async generator to print a wall-clock timestamp at
"first row yielded" and "last row yielded", plus process RSS before the
query, right after conn.execute() returns, and after the loop completes. If
this is truly a streaming/row-by-row cursor, "time to first row" should be a
small, near-constant fraction of "time to last row" regardless of table
size, and RSS should grow gradually across the loop rather than jumping
immediately after execute() returns.
"""

import asyncio
import os
import time

import psutil
from sqlalchemy import MetaData, Table, Column, Integer, String, select
from sqlalchemy.ext.asyncio import create_async_engine

DATABASE_URL = "postgresql+asyncpg://postgres:pw@localhost:15432/testdb"

metadata = MetaData()
t = Table("t", metadata, Column("id", Integer, primary_key=True), Column("payload", String))

proc = psutil.Process(os.getpid())


def rss_mb() -> float:
    return proc.memory_info().rss / (1024 * 1024)


async def stream_like_repo(engine):
    """Verbatim mirror of PostgresAuditLogRepository.stream_by_org's shape."""
    async with engine.connect() as conn:
        print(f"[t={time.time():.3f}] RSS before execute(): {rss_mb():.1f} MiB")
        result = await conn.execute(select(t).order_by(t.c.id))
        print(f"[t={time.time():.3f}] RSS immediately after execute() returns "
              f"(before consuming any row): {rss_mb():.1f} MiB")
        first_row_time = None
        count = 0
        for row in result:  # sync "for row in result", exactly as in the repo code
            count += 1
            if first_row_time is None:
                first_row_time = time.time()
                print(f"[t={first_row_time:.3f}] first row yielded, RSS={rss_mb():.1f} MiB")
            if count % 100000 == 0:
                print(f"[t={time.time():.3f}] {count} rows consumed, RSS={rss_mb():.1f} MiB")
        last_row_time = time.time()
        print(f"[t={last_row_time:.3f}] last row yielded ({count} total), RSS={rss_mb():.1f} MiB")
        return first_row_time, last_row_time


async def main():
    engine = create_async_engine(DATABASE_URL)
    try:
        start = time.time()
        print(f"[t={start:.3f}] starting query against 300,000-row table")
        first_row_time, last_row_time = await stream_like_repo(engine)
        print()
        print(f"time to FIRST row: {first_row_time - start:.4f}s")
        print(f"time to LAST row:  {last_row_time - start:.4f}s")
        print(f"ratio (first/last): {(first_row_time - start) / (last_row_time - start):.4f}")
        print("(a ratio near 1.0 means first-row and last-row arrived at "
              "essentially the same moment -- i.e. the WHOLE result set was "
              "fetched/buffered before the generator yielded anything, "
              "confirming NOT row-by-row DB streaming. A ratio near 0 would "
              "indicate real incremental streaming.)")
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
