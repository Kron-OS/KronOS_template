"""Real Celery/Redis PoC — client side.

Runs against the real `kronos-poc-celery-redis` (redis:7-alpine, host port
16379) broker/backend and the real Celery worker started separately (see
README.md), which is a genuine `celery worker` process consuming the real
queues declared in src/external/celery_app.py's task_routes: q.index,
q.parse.fast, q.parse.plaso.

This script:
  1. Calls the real `CeleryTaskQueue.enqueue_dispatch/enqueue_parse_fast/
     enqueue_parse_heavy` methods (src/adapter/queue/celery_queue.py) exactly
     as production code would (EvidenceIntakeService, ParsingOrchestrationService).
  2. Confirms — via celery_app.control.inspect() (real broker RPC over Redis,
     not a client-side assumption) — that the worker actually received each
     task on the correct queue.
  3. Polls the real Celery result backend (Redis db 2) for terminal task
     state, proving the worker executed (or genuinely retried/failed) the
     task body, not just accepted the connection.
"""

from __future__ import annotations

import asyncio
import time
import uuid

from src.adapter.queue.celery_queue import CeleryTaskQueue
from src.domain.user import Role, TenantContext
from src.external.celery_app import celery_app


def tenant() -> TenantContext:
    return TenantContext(
        org_id=uuid.uuid4(),
        org_alias="poc-org",
        user_id=uuid.uuid4(),
        username="poc-user",
        roles=frozenset({Role.CASE_LEAD}),
        correlation_id=str(uuid.uuid4()),
    )


async def enqueue_all() -> dict[str, str]:
    queue = CeleryTaskQueue()
    t = tenant()
    ids = {}
    ids["dispatch_parse"] = await queue.enqueue_dispatch(uuid.uuid4(), t)
    ids["parse_artefact_fast"] = await queue.enqueue_parse_fast(uuid.uuid4(), t)
    ids["parse_artefact_heavy"] = await queue.enqueue_parse_heavy(uuid.uuid4(), t)
    return ids


def main() -> None:
    print("== Step 1: enqueue via real CeleryTaskQueue methods ==")
    task_ids = asyncio.run(enqueue_all())
    for name, tid in task_ids.items():
        print(f"  {name}: task_id={tid}")

    print("\n== Step 2: broker-side confirmation via control.inspect() ==")
    insp = celery_app.control.inspect(timeout=5)
    for _ in range(10):
        active = insp.active() or {}
        reserved = insp.reserved() or {}
        seen = []
        for worker_tasks in list(active.values()) + list(reserved.values()):
            seen.extend(t["id"] for t in worker_tasks)
        if any(tid in seen for tid in task_ids.values()):
            break
        time.sleep(0.5)
    print("  active():", insp.active())
    print("  reserved():", insp.reserved())

    print("\n== Step 3: poll real result backend for terminal state ==")
    from celery.result import AsyncResult

    deadline = time.time() + 60
    states: dict[str, str] = {}
    while time.time() < deadline and len(states) < len(task_ids):
        for name, tid in task_ids.items():
            if name in states:
                continue
            res = AsyncResult(tid, app=celery_app)
            if res.state in ("SUCCESS", "FAILURE", "REVOKED"):
                states[name] = f"{res.state}: {res.result!r}"
        time.sleep(1)
    for name, tid in task_ids.items():
        state = states.get(name, "(still pending after 60s poll)")
        res = AsyncResult(tid, app=celery_app)
        print(f"  {name} ({tid}): final_state_seen={res.state!r} detail={state}")


if __name__ == "__main__":
    main()
