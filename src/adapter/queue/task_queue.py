"""TaskQueue ABC and InMemoryTaskQueue for unit tests."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from src.domain.user import TenantContext


class TaskQueue(ABC):
    """Abstract task queue — Celery in production, in-memory stub for tests."""

    @abstractmethod
    async def enqueue_intake(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        """Enqueue the process_intake task (validate/scan/hash/promote).

        Called by the lightweight, client-facing finalize_upload route (and
        by the retry-intake route for ERROR evidence with a retryable
        reason) instead of running that work inline on the request thread —
        see EvidenceIntakeService.start_intake()'s docstring for why. The
        client's declared SHA-256 is read from the already-persisted
        Evidence row (with_client_declared_sha256), not passed through here,
        so a retry never needs the client to resupply it.
        """

    @abstractmethod
    async def enqueue_dispatch(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        """Enqueue the dispatch_parse task (entry-point for the autonomous pipeline).

        Called automatically by EvidenceIntakeService after an evidence artifact
        reaches RECEIVED state.  The dispatch task detects the parser and routes
        to the appropriate fast/heavy parse queue — callers never pick the queue.
        Returns the Celery task ID (or a stub ID in tests).
        """

    @abstractmethod
    async def enqueue_parse_fast(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        """Enqueue to the fast parse queue. Return the task ID."""

    @abstractmethod
    async def enqueue_parse_heavy(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        """Enqueue to the heavy parse queue. Return the task ID."""

    @abstractmethod
    async def enqueue_volatility_dump_file(
        self, evidence_id: uuid.UUID, tenant: TenantContext, physaddr: int
    ) -> str:
        """Enqueue an on-demand windows.dumpfiles extraction (Milestone
        EEEEE) -- an analyst-triggered action on already-parsed evidence,
        never part of the autonomous per-evidence pipeline. Return the
        Celery task ID (or a stub ID in tests)."""

    @abstractmethod
    async def enqueue_volatility_registry_key(
        self, evidence_id: uuid.UUID, tenant: TenantContext, hive_offset: int, key: str | None
    ) -> str:
        """Enqueue an on-demand, scoped windows.registry.printkey call
        (Milestone EEEEE). Return the Celery task ID (or a stub ID in
        tests)."""


class InMemoryTaskQueue(TaskQueue):
    """Captures enqueued tasks without running them — for unit tests."""

    def __init__(self) -> None:
        self.enqueued: list[tuple[str, uuid.UUID, TenantContext]] = []

    async def enqueue_intake(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        task_id = str(uuid.uuid4())
        self.enqueued.append(("intake", evidence_id, tenant))
        return task_id

    async def enqueue_dispatch(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        task_id = str(uuid.uuid4())
        self.enqueued.append(("dispatch", evidence_id, tenant))
        return task_id

    async def enqueue_parse_fast(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        task_id = str(uuid.uuid4())
        self.enqueued.append(("fast", evidence_id, tenant))
        return task_id

    async def enqueue_parse_heavy(self, evidence_id: uuid.UUID, tenant: TenantContext) -> str:
        task_id = str(uuid.uuid4())
        self.enqueued.append(("heavy", evidence_id, tenant))
        return task_id

    async def enqueue_volatility_dump_file(
        self, evidence_id: uuid.UUID, tenant: TenantContext, physaddr: int
    ) -> str:
        task_id = str(uuid.uuid4())
        self.enqueued.append(("volatility_dump_file", evidence_id, tenant))
        return task_id

    async def enqueue_volatility_registry_key(
        self, evidence_id: uuid.UUID, tenant: TenantContext, hive_offset: int, key: str | None
    ) -> str:
        task_id = str(uuid.uuid4())
        self.enqueued.append(("volatility_registry_key", evidence_id, tenant))
        return task_id
