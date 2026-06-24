"""Celery application and parse task definitions.

Broker/backend URLs are read from environment variables with safe defaults so
this module can be imported in development without a running Redis instance.
The actual production values come from src/config.py at worker startup.
"""

from __future__ import annotations

import os
import uuid

from celery import Celery

celery_app = Celery(
    "kronos",
    broker=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/1"),
)
celery_app.conf.task_routes = {
    "kronos.parse_fast": {"queue": "parse.fast"},
    "kronos.parse_heavy": {"queue": "parse.heavy"},
}
celery_app.conf.task_serializer = "json"
celery_app.conf.result_serializer = "json"
celery_app.conf.accept_content = ["json"]


@celery_app.task(name="kronos.parse_fast", bind=True, max_retries=3)  # type: ignore[untyped-decorator]
def parse_evidence_fast(self: object, evidence_id: str, *, org_id: str, user_id: str) -> int:
    """Fast parse task — runs in gVisor sandbox (stub: sandbox not yet wired)."""
    import asyncio  # noqa: PLC0415

    from src.external.dependencies import (  # noqa: PLC0415
        _build_orchestration_service,
        _build_tenant_from_task,
    )

    tenant = _build_tenant_from_task(org_id, user_id)
    svc = _build_orchestration_service()
    return asyncio.run(svc.execute_parse(uuid.UUID(evidence_id), tenant))


@celery_app.task(name="kronos.parse_heavy", bind=True, max_retries=3)  # type: ignore[untyped-decorator]
def parse_evidence_heavy(self: object, evidence_id: str, *, org_id: str, user_id: str) -> int:
    """Heavy parse task — runs in Firecracker sandbox (stub: sandbox not yet wired).

    Currently delegates to the same execute_parse path as fast; Phase 4 will
    differentiate the sandbox invocation.
    """
    import asyncio  # noqa: PLC0415

    from src.external.dependencies import (  # noqa: PLC0415
        _build_orchestration_service,
        _build_tenant_from_task,
    )

    tenant = _build_tenant_from_task(org_id, user_id)
    svc = _build_orchestration_service()
    return asyncio.run(svc.execute_parse(uuid.UUID(evidence_id), tenant))
