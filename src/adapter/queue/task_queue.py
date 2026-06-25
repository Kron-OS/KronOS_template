"""TaskQueue ABC and InMemoryTaskQueue for unit tests."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from src.domain.user import TenantContext


class TaskQueue(ABC):
    """Abstract task queue — Celery in production, in-memory stub for tests."""

    @abstractmethod
    async def enqueue_parse_fast(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        """Enqueue to the fast parse queue. Return the task ID."""

    @abstractmethod
    async def enqueue_parse_heavy(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        """Enqueue to the heavy parse queue. Return the task ID."""


class InMemoryTaskQueue(TaskQueue):
    """Captures enqueued tasks without running them — for unit tests."""

    def __init__(self) -> None:
        self.enqueued: list[tuple[str, uuid.UUID, TenantContext]] = []

    async def enqueue_parse_fast(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        task_id = str(uuid.uuid4())
        self.enqueued.append(("fast", evidence_id, tenant))
        return task_id

    async def enqueue_parse_heavy(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        task_id = str(uuid.uuid4())
        self.enqueued.append(("heavy", evidence_id, tenant))
        return task_id
