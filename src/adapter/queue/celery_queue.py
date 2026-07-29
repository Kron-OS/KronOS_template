"""CeleryTaskQueue: enqueues parse tasks via Celery broker."""

from __future__ import annotations

import uuid

from src.adapter.queue.task_queue import TaskQueue
from src.domain.user import TenantContext


class CeleryTaskQueue(TaskQueue):
    """Sends tasks to Celery.  Imports the Celery app lazily to avoid import cycles."""

    async def enqueue_intake(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        """Enqueue process_intake (validate/scan/hash/promote), q.intake."""
        from src.external.celery_app import process_intake  # noqa: PLC0415

        result = process_intake.apply_async(
            kwargs={
                "evidence_id": str(evidence_id),
                "org_id": str(tenant.org_id),
                "user_id": str(tenant.user_id),
            },
            queue="q.intake",
        )
        return result.id  # type: ignore[no-any-return]

    async def enqueue_dispatch(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        """Enqueue dispatch_parse — the autonomous pipeline entry-point.

        The dispatch task detects the parser type and routes to fast or heavy
        queue.  Always sent to q.index so it executes on an indexing worker.
        """
        from src.external.celery_app import dispatch_parse  # noqa: PLC0415

        result = dispatch_parse.apply_async(
            kwargs={
                "evidence_id": str(evidence_id),
                "org_id": str(tenant.org_id),
                "user_id": str(tenant.user_id),
            },
            queue="q.index",
        )
        return result.id  # type: ignore[no-any-return]

    async def enqueue_parse_fast(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        from src.external.celery_app import parse_artefact_fast  # noqa: PLC0415

        result = parse_artefact_fast.apply_async(
            kwargs={
                "evidence_id": str(evidence_id),
                "org_id": str(tenant.org_id),
                "user_id": str(tenant.user_id),
            },
            queue="q.parse.fast",
        )
        return result.id  # type: ignore[no-any-return]

    async def enqueue_parse_heavy(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        from src.external.celery_app import parse_artefact_heavy  # noqa: PLC0415

        result = parse_artefact_heavy.apply_async(
            kwargs={
                "evidence_id": str(evidence_id),
                "org_id": str(tenant.org_id),
                "user_id": str(tenant.user_id),
            },
            queue="q.parse.plaso",
        )
        return result.id  # type: ignore[no-any-return]
