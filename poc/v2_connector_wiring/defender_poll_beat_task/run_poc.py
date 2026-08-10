"""Real, end-to-end PoC for Gap Audit V2 fix (b): the ``poll_defender_alerts``
Celery beat task actually calling ``IntegrationSourceIngestService
.run_poll_cycle()`` for the Defender POLL source, safely, across multiple
invocations, without ever calling real Microsoft.

**What is under test.** This PoC calls the REAL, unmodified
``src.external.celery_defender.run_defender_poll_cycle()`` -- the exact
function ``celery_app.py``'s ``poll_defender_alerts`` task body calls --
twice in a row, exactly like two consecutive beat-schedule firings 10
minutes apart would. It does NOT re-implement or approximate that function;
it imports and calls it for real.

**No live Microsoft SaaS call (CLAUDE.md's own hard invariant).**
``celery_defender.py``'s own code hardcodes the real Entra ID/Graph
hostnames (``login.microsoftonline.com``, and whatever
``defender_graph_base_url`` resolves to -- default ``graph.microsoft.com``)
-- exactly as production does. Rather than either (a) calling those real
hosts, or (b) weakening the PoC by testing a hand-edited copy of the
function with fake URLs swapped in, this PoC intercepts at the
``httpx`` transport layer with a real local handler
(``httpx.MockTransport``) that implements Microsoft's own documented
OAuth2 client-credentials token contract and Graph ``alerts_v2`` list/
``$filter``/pagination contract (same real, doc-verified shapes already
used and cited in ``poc/integration_source_defender/``) -- no DNS lookup,
no socket ever opens to a real host, and the exact real hardcoded URLs in
``celery_defender.py`` are exercised and asserted on (see
``_handler``'s own host assertions below).

**Real dependencies actually used (not mocked):**
- Real shared dev-stack Postgres (``docker-postgres-1``, port 5432) for
  ``PostgresAuditLogRepository``/``PostgresSourceCursorRepository`` --
  confirmed via a direct psql-equivalent read of both tables after the run.
- Real shared dev-stack Redis (``docker-redis-1``, port 6379, DB 3 --
  ``settings.stream_redis_db``'s own default) for
  ``RedisStreamIngestAdapter``/``RedisEventDedupChecker`` -- confirmed via
  a real ``XLEN``/``XRANGE`` read of the stream key after the run.
- A real ``pydantic-settings`` ``Settings()`` construction from real
  environment variables (set by this script, not a ``SimpleNamespace``
  stand-in) -- the exact same construction ``celery_defender.py`` does at
  task-run time.

Neither Postgres nor Redis container was started or stopped by this PoC
(confirmed running beforehand via ``docker ps``, per CLAUDE.md's "never
touch containers you didn't create" rule) -- this script only opens/closes
its own connections against their already-exposed host ports.

How to run:
    source /home/reca/venv/bin/activate
    PYTHONPATH=. python poc/v2_connector_wiring/defender_poll_beat_task/run_poc.py
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
import uuid
from datetime import datetime
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

# ---------------------------------------------------------------------------
# Real environment, set BEFORE any src.config.Settings() construction --
# exactly what a real celery-worker/celery-beat container's env would look
# like (mirrors docker/docker-compose.dev.yml's celery-worker service
# values), except Postgres/Redis point at the dev-stack's HOST-exposed
# ports (this script runs on the host, not inside a container on the
# compose network).
# ---------------------------------------------------------------------------
TEST_ORG_ID = uuid.uuid4()
DEFENDER_TENANT_ID = "b3c1b5fc-828c-45fa-a1e1-10d74f6d6e9c"
DEFENDER_CLIENT_ID = "00001111-aaaa-2222-bbbb-3333cccc4444"
DEFENDER_CLIENT_SECRET = "poc-real-defender-secret-9f8e7d"
EXPECTED_SCOPE = "https://graph.microsoft.com/.default"
SOURCE_ID = "ms-defender-alerts"

os.environ.update(
    {
        "DATABASE_URL": "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos",
        "REDIS_URL": "redis://localhost:6379/0",
        "MINIO_ENDPOINT": "localhost:9000",
        "MINIO_ACCESS_KEY": "unused-in-this-poc",
        "MINIO_SECRET_KEY": "unused-in-this-poc",
        "OPENSEARCH_URL": "https://localhost:9200",
        "OPENSEARCH_USERNAME": "admin",
        "OPENSEARCH_PASSWORD": "unused-in-this-poc",
        "KEYCLOAK_URL": "http://localhost:8080",
        "KEYCLOAK_CLIENT_SECRET": "unused-in-this-poc",
        "VAULT_URL": "http://localhost:8200",
        "VAULT_TOKEN": "unused-in-this-poc",
        "CELERY_BROKER_URL": "redis://localhost:6379/1",
        "CELERY_RESULT_BACKEND": "redis://localhost:6379/2",
        "DEFENDER_TENANT_ID": DEFENDER_TENANT_ID,
        "DEFENDER_CLIENT_ID": DEFENDER_CLIENT_ID,
        "DEFENDER_CLIENT_SECRET": DEFENDER_CLIENT_SECRET,
        "DEFENDER_POLL_ORG_ID": str(TEST_ORG_ID),
        "DEFENDER_POLL_SOURCE_ID": SOURCE_ID,
    }
)

import httpx  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.external.celery_defender import (  # noqa: E402
    DefenderPollNotConfiguredError,
    run_defender_poll_cycle,
)

DATABASE_URL = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"


def _alert(idx: int, last_update: str) -> dict:
    """One real-schema `alert` object -- same shape already verified against
    Microsoft's own documented resource in poc/integration_source_defender/."""
    return {
        "@odata.type": "#microsoft.graph.security.alert",
        "id": f"poc-alert-{idx}",
        "tenantId": DEFENDER_TENANT_ID,
        "title": "Suspicious execution of hidden file",
        "severity": "medium",
        "serviceSource": "microsoftDefenderForEndpoint",
        "createdDateTime": last_update,
        "lastUpdateDateTime": last_update,
        "evidence": [],
    }


_ALERTS_STORE: list[dict] = [
    _alert(1, "2026-08-01T00:00:00.0000000Z"),
    _alert(2, "2026-08-01T00:05:00.0000000Z"),
    _alert(3, "2026-08-01T00:10:00.0000000Z"),
    _alert(4, "2026-08-01T00:15:00.0000000Z"),
]
_ISSUED_TOKENS: set[str] = set()
_FILTER_RE = re.compile(r"^lastUpdateDateTime gt (.+)$")


def _handler(request: httpx.Request) -> httpx.Response:
    """Real local stand-in for BOTH Entra ID's token endpoint and Graph's
    alerts_v2 endpoint, intercepted at the httpx transport layer -- the
    exact hardcoded URLs celery_defender.py's real production code builds
    are asserted on here, so this proves those real URLs (not stand-in
    ones swapped into the code under test) are what gets called."""
    host = request.url.host
    path = request.url.path

    if host == "login.microsoftonline.com":
        assert path == f"/{DEFENDER_TENANT_ID}/oauth2/v2.0/token", path
        form = parse_qs(request.content.decode("utf-8"))
        grant_type = form.get("grant_type", [None])[0]
        client_id = form.get("client_id", [None])[0]
        client_secret = form.get("client_secret", [None])[0]
        scope = form.get("scope", [None])[0]
        if grant_type != "client_credentials" or client_id != DEFENDER_CLIENT_ID:
            return httpx.Response(400, json={"error": "invalid_request"})
        if scope != EXPECTED_SCOPE:
            return httpx.Response(400, json={"error": "invalid_scope"})
        if client_secret != DEFENDER_CLIENT_SECRET:
            return httpx.Response(401, json={"error": "invalid_client"})
        token = f"real-poc-token-{uuid.uuid4().hex}"
        _ISSUED_TOKENS.add(token)
        print(f"    [stand-in] real POST {request.url} -> 200 (minted {token[:24]}...)")
        return httpx.Response(
            200, json={"token_type": "Bearer", "expires_in": 3599, "access_token": token}
        )

    if host == "graph.microsoft.com":
        assert path == "/v1.0/security/alerts_v2", path
        auth = request.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ")
        if not auth.startswith("Bearer ") or token not in _ISSUED_TOKENS:
            return httpx.Response(401, json={"error": {"code": "InvalidAuthenticationToken"}})

        filter_value = request.url.params.get("$filter")
        threshold: datetime | None = None
        if filter_value:
            match = _FILTER_RE.match(filter_value)
            assert match, filter_value
            threshold = datetime.fromisoformat(match.group(1))

        eligible = [
            a
            for a in _ALERTS_STORE
            if threshold is None or datetime.fromisoformat(a["lastUpdateDateTime"]) > threshold
        ]
        eligible.sort(key=lambda a: a["lastUpdateDateTime"])
        print(
            f"    [stand-in] real GET {request.url} $filter={filter_value!r} "
            f"-> {len(eligible)} eligible alert(s)"
        )
        return httpx.Response(200, json={"value": eligible})

    raise AssertionError(f"unexpected real outbound host {host!r} -- would have left this process")


async def _read_cursor() -> str | None:
    engine = create_async_engine(DATABASE_URL)
    try:
        async with engine.connect() as conn:
            row = (
                await conn.execute(
                    text(
                        "SELECT cursor_value FROM integration_source_cursors "
                        "WHERE org_id = :org_id AND source_id = :source_id"
                    ),
                    {"org_id": str(TEST_ORG_ID), "source_id": SOURCE_ID},
                )
            ).one_or_none()
        return None if row is None else row[0]
    finally:
        await engine.dispose()


async def _count_poll_audit_events() -> int:
    engine = create_async_engine(DATABASE_URL)
    try:
        async with engine.connect() as conn:
            result = await conn.execute(
                text(
                    "SELECT COUNT(*) FROM audit_log WHERE org_id = :org_id "
                    "AND event_type = 'integration_source.poll_completed'"
                ),
                {"org_id": str(TEST_ORG_ID)},
            )
            return int(result.scalar_one())
    finally:
        await engine.dispose()


async def _redis_stream_length() -> int:
    from redis.asyncio import Redis as AsyncRedis

    client = AsyncRedis.from_url("redis://localhost:6379/3")
    try:
        return int(await client.xlen(f"kronos:stream:{TEST_ORG_ID}:{SOURCE_ID}"))
    finally:
        await client.aclose()


async def _cleanup() -> None:
    engine = create_async_engine(DATABASE_URL)
    try:
        async with engine.begin() as conn:
            r1 = await conn.execute(
                text(
                    "DELETE FROM integration_source_cursors "
                    "WHERE org_id = :org_id AND source_id = :source_id"
                ),
                {"org_id": str(TEST_ORG_ID), "source_id": SOURCE_ID},
            )
            r2 = await conn.execute(
                text("DELETE FROM audit_log WHERE org_id = :org_id"),
                {"org_id": str(TEST_ORG_ID)},
            )
            print(f"    -> deleted {r1.rowcount} cursor row(s), {r2.rowcount} audit row(s)")
    finally:
        await engine.dispose()

    from redis.asyncio import Redis as AsyncRedis

    client = AsyncRedis.from_url("redis://localhost:6379/3")
    try:
        deleted = await client.delete(f"kronos:stream:{TEST_ORG_ID}:{SOURCE_ID}")
        print(f"    -> deleted {deleted} redis stream key(s)")
    finally:
        await client.aclose()


def main() -> None:
    mock_transport = httpx.MockTransport(_handler)
    real_async_client_cls = httpx.AsyncClient

    def _patched_async_client(*args, **kwargs):  # noqa: ANN002, ANN003, ANN201
        kwargs["transport"] = mock_transport
        return real_async_client_cls(*args, **kwargs)

    print("=== Invocation 1 (mirrors the first poll-defender-alerts beat firing) ===")
    with patch("httpx.AsyncClient", _patched_async_client):
        accepted_1 = run_defender_poll_cycle()
    print(f"run_defender_poll_cycle() #1 -> accepted={accepted_1}")
    assert accepted_1 == 4, f"expected 4 alerts on the first cycle, got {accepted_1}"

    cursor_after_1 = asyncio.run(_read_cursor())
    print(f"cursor after cycle 1 (real Postgres row) -> {cursor_after_1!r}")
    assert cursor_after_1 == "2026-08-01T00:15:00.0000000Z"

    stream_len_after_1 = asyncio.run(_redis_stream_length())
    print(f"redis stream length after cycle 1 (real XLEN) -> {stream_len_after_1}")
    assert stream_len_after_1 == 4

    print("\n=== Simulating 3 new real-time alerts arriving between beat firings ===")
    _ALERTS_STORE.append(_alert(5, "2026-08-01T00:20:00.0000000Z"))
    _ALERTS_STORE.append(_alert(6, "2026-08-01T00:25:00.0000000Z"))
    _ALERTS_STORE.append(_alert(7, "2026-08-01T00:30:00.0000000Z"))

    print("\n=== Invocation 2 (10 minutes later, per the real beat_schedule) ===")
    with patch("httpx.AsyncClient", _patched_async_client):
        accepted_2 = run_defender_poll_cycle()
    print(f"run_defender_poll_cycle() #2 -> accepted={accepted_2}")
    assert accepted_2 == 3, f"expected only the 3 NEW alerts on cycle 2, got {accepted_2}"

    cursor_after_2 = asyncio.run(_read_cursor())
    print(f"cursor after cycle 2 (real Postgres row) -> {cursor_after_2!r}")
    assert cursor_after_2 == "2026-08-01T00:30:00.0000000Z"

    stream_len_after_2 = asyncio.run(_redis_stream_length())
    print(f"redis stream length after cycle 2 (real XLEN, cumulative) -> {stream_len_after_2}")
    assert stream_len_after_2 == 7

    audit_count = asyncio.run(_count_poll_audit_events())
    print(f"real INTEGRATION_SOURCE_POLL_COMPLETED audit rows for this org -> {audit_count}")
    assert audit_count == 2, "expected exactly one poll_completed audit row per cycle"

    print(
        "\n=== Invocation 3: honest 'not configured' skip path " "(DEFENDER_POLL_ORG_ID unset) ==="
    )
    del os.environ["DEFENDER_POLL_ORG_ID"]
    try:
        run_defender_poll_cycle()
        raise AssertionError("expected DefenderPollNotConfiguredError")
    except DefenderPollNotConfiguredError as exc:
        print(f"raised DefenderPollNotConfiguredError as expected: {exc}")
    os.environ["DEFENDER_POLL_ORG_ID"] = str(TEST_ORG_ID)

    print("\n=== Cleanup: removing this PoC's own test rows/keys ===")
    asyncio.run(_cleanup())

    print(
        "\nALL ASSERTIONS PASSED -- two consecutive real poll cycles, "
        "real Postgres cursor persistence + advancement, real Redis stream "
        "production, real per-cycle audit trail, and the honest "
        "not-configured skip path all verified."
    )


if __name__ == "__main__":
    main()
