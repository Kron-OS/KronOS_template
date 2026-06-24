"""Celery application and parse task definitions.

Broker/backend URLs come from pydantic Settings (src/config.py), which reads
from environment variables.  Importing Settings here means the app will validate
configuration at worker startup rather than silently using defaults.
"""

from __future__ import annotations

import uuid

from celery import Celery

from src.config import Settings

_settings = Settings()

celery_app = Celery(
    "kronos",
    broker=_settings.celery_broker_url.get_secret_value(),
    backend=_settings.celery_result_backend.get_secret_value(),
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
