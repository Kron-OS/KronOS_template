"""CeleryTaskQueue: enqueues parse tasks via Celery broker."""

from __future__ import annotations

import uuid

from src.adapter.queue.task_queue import TaskQueue
from src.domain.user import TenantContext


class CeleryTaskQueue(TaskQueue):
    """Sends tasks to Celery.  Imports the Celery app lazily to avoid import cycles."""

    async def enqueue_parse_fast(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        from src.external.celery_app import parse_evidence_fast  # noqa: PLC0415

        result = parse_evidence_fast.apply_async(
            args=[str(evidence_id)],
            kwargs={"org_id": str(tenant.org_id), "user_id": str(tenant.user_id)},
            queue="parse.fast",
        )
        return result.id  # type: ignore[no-any-return]

    async def enqueue_parse_heavy(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        from src.external.celery_app import parse_evidence_heavy  # noqa: PLC0415

        result = parse_evidence_heavy.apply_async(
            args=[str(evidence_id)],
            kwargs={"org_id": str(tenant.org_id), "user_id": str(tenant.user_id)},
            queue="parse.heavy",
        )
        return result.id  # type: ignore[no-any-return]
