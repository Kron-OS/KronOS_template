"""Real app-code verification for Milestone X2b (Redis DB-role separation).

Constructs the ACTUAL application classes this repo ships --
``RedisTicketStore`` (src/external/middleware/step_up_store.py) and
``RedisStreamIngestAdapter`` (src/adapter/queue/stream_ingest.py) -- against
the throwaway two-instance PoC topology (docker-compose.poc.yml), exactly
the way src/external/dependencies.py:1334 / src/external/startup.py:242-249
construct them from Settings in real deployments (plain
``redis.Redis.from_url()`` / ``redis.asyncio.Redis.from_url()``, no mocks).

Proves two things per CLAUDE.md §F:
  1. The real app classes genuinely connect to and round-trip data through
     the split topology's two ports (16379 = redis-auth-streams, 16380 =
     redis-celery).
  2. Cross-instance isolation holds at the real redis-py client level, not
     just via raw redis-cli: a ticket PUT on the auth-streams instance's
     DB0 is invisible to a client pointed at the celery instance, and a
     Celery-shaped key written to the celery instance's DB1 is invisible to
     a client pointed at the auth-streams instance.

Run from repo root with the pinned backend venv:
    /home/reca/venv/bin/python poc/redis_role_separation/verify_app_wiring.py
"""

from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

import redis  # noqa: E402
import redis.asyncio as aioredis  # noqa: E402

from src.adapter.queue.stream_ingest import RedisStreamIngestAdapter  # noqa: E402
from src.external.middleware.step_up_store import ConsumeResult, RedisTicketStore  # noqa: E402

AUTH_STREAMS_URL = "redis://:poc_auth_streams_pw@localhost:16379"
CELERY_URL = "redis://:poc_celery_pw@localhost:16380"


def _ok(label: str, cond: bool) -> None:
    status = "PASS" if cond else "FAIL"
    print(f"[{status}] {label}")
    if not cond:
        raise SystemExit(f"FAILED: {label}")


async def main() -> None:
    print("== Milestone X2b real app-wiring + cross-instance isolation PoC ==")

    # --- 1. RedisTicketStore against redis-auth-streams (DB0), real wiring ---
    # Mirrors src/external/dependencies.py:1334's build_step_up_ticket_store()
    # construction exactly: redis.Redis.from_url(url), db 0 implicit in the URL.
    auth_streams_client_db0 = redis.Redis.from_url(f"{AUTH_STREAMS_URL}/0")
    ticket_store = RedisTicketStore(auth_streams_client_db0)

    ticket_id = uuid.uuid4()
    user_id = uuid.uuid4()
    ticket_store.put(ticket_id, user_id, "evidence.download", "case-42")
    print(f"[INFO] put step-up ticket {ticket_id} on redis-auth-streams DB0")

    result = ticket_store.consume(ticket_id, user_id, "evidence.download", "case-42")
    _ok(
        "real RedisTicketStore round-trips a ticket on redis-auth-streams DB0",
        result == ConsumeResult.CONSUMED,
    )

    # --- 2. Cross-instance isolation: a SECOND ticket, checked from the
    # celery instance's client -- must be invisible there. ---
    ticket_id_2 = uuid.uuid4()
    user_id_2 = uuid.uuid4()
    ticket_store.put(ticket_id_2, user_id_2, "case.close", "case-99")
    print(f"[INFO] put a second step-up ticket {ticket_id_2} on redis-auth-streams DB0")

    celery_client_db0_shaped = redis.Redis.from_url(f"{CELERY_URL}/0")
    raw_key = f"kronos:stepup:{ticket_id_2}"
    cross_read = celery_client_db0_shaped.get(raw_key)
    _ok(
        "step-up ticket written to redis-auth-streams is INVISIBLE from redis-celery "
        "(cross-instance isolation, real redis-py client)",
        cross_read is None,
    )
    # Clean up the still-live ticket on the correct instance.
    ticket_store.consume(ticket_id_2, user_id_2, "case.close", "case-99")

    # --- 3. RedisStreamIngestAdapter against redis-auth-streams (DB3), real
    # wiring, mirroring src/external/startup.py:242-249's construction. ---
    stream_client_db3 = aioredis.Redis.from_url(f"{AUTH_STREAMS_URL}/3")
    stream_adapter = RedisStreamIngestAdapter(stream_client_db3)

    org_id = uuid.uuid4()
    message_id = await stream_adapter.produce(org_id, "poc-source", b"hello-x2b")
    print(f"[INFO] produced stream message {message_id} on redis-auth-streams DB3")
    active = await stream_adapter.list_active_streams()
    _ok(
        "real RedisStreamIngestAdapter.produce()+list_active_streams() round-trip "
        "on redis-auth-streams DB3",
        (org_id, "poc-source") in active,
    )

    # Cross-instance isolation for the stream key too: the celery instance's
    # DB3 client should see no such stream.
    celery_client_db3 = aioredis.Redis.from_url(f"{CELERY_URL}/3")
    stream_adapter_on_celery = RedisStreamIngestAdapter(celery_client_db3)
    active_on_celery = await stream_adapter_on_celery.list_active_streams()
    _ok(
        "stream produced on redis-auth-streams DB3 is INVISIBLE from redis-celery DB3 "
        "(cross-instance isolation, real redis-py client)",
        (org_id, "poc-source") not in active_on_celery,
    )

    # --- 4. Celery-shaped keys on redis-celery (DB1/DB2), and isolation the
    # other direction: written to redis-celery, invisible from redis-auth-streams. ---
    celery_broker_client = redis.Redis.from_url(f"{CELERY_URL}/1")
    celery_broker_client.lpush("kronos-poc-celery-broker-key", "task-payload")
    _ok(
        "real key written to redis-celery DB1 (broker-shaped) is readable there",
        celery_broker_client.lrange("kronos-poc-celery-broker-key", 0, -1) == [b"task-payload"],
    )

    auth_streams_client_db1_shaped = redis.Redis.from_url(f"{AUTH_STREAMS_URL}/1")
    cross_read_2 = auth_streams_client_db1_shaped.lrange("kronos-poc-celery-broker-key", 0, -1)
    _ok(
        "Celery-broker-shaped key written to redis-celery DB1 is INVISIBLE from "
        "redis-auth-streams (cross-instance isolation, real redis-py client)",
        cross_read_2 == [],
    )

    print("== All real app-wiring + cross-instance isolation checks passed ==")

    auth_streams_client_db0.close()
    celery_client_db0_shaped.close()
    celery_broker_client.close()
    auth_streams_client_db1_shaped.close()
    await stream_client_db3.aclose()
    await celery_client_db3.aclose()


if __name__ == "__main__":
    asyncio.run(main())
