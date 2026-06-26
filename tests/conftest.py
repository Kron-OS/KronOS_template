"""Shared pytest fixtures and in-memory repository implementations for unit tests."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator

import pytest

from src.adapter.repository.audit_log import AuditLogRepository
from src.adapter.repository.evidence import EvidenceRepository
from src.application.audit_log import AuditLogService
from src.domain.audit import AuditEvent
from src.domain.evidence import Evidence, EvidenceState


class InMemoryAuditLogRepository(AuditLogRepository):
    """In-memory audit log for unit tests — no external dependencies."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    async def append(self, event: AuditEvent) -> AuditEvent:
        self._events.append(event)
        return event

    async def get_latest_hash(self, org_id: uuid.UUID) -> str | None:
        for event in reversed(self._events):
            if event.org_id == org_id:
                return event.row_hash
        return None

    async def get_latest_sequence(self, org_id: uuid.UUID) -> int:
        for event in reversed(self._events):
            if event.org_id == org_id:
                return event.sequence_number
        return 0

    async def stream_by_evidence(  # type: ignore[override]
        self, evidence_id: uuid.UUID
    ) -> AsyncIterator[AuditEvent]:
        for event in self._events:
            if event.evidence_id == evidence_id:
                yield event

    async def stream_by_case(  # type: ignore[override]
        self, case_id: uuid.UUID
    ) -> AsyncIterator[AuditEvent]:
        for event in self._events:
            if event.case_id == case_id:
                yield event

    async def stream_by_org(  # type: ignore[override]
        self, org_id: uuid.UUID
    ) -> AsyncIterator[AuditEvent]:
        for event in sorted(self._events, key=lambda e: e.sequence_number):
            if event.org_id == org_id:
                yield event

    @property
    def events(self) -> list[AuditEvent]:
        return list(self._events)


class InMemoryEvidenceRepository(EvidenceRepository):
    """In-memory evidence repository for unit tests."""

    def __init__(self) -> None:
        self._store: dict[uuid.UUID, Evidence] = {}

    async def save(self, evidence: Evidence) -> Evidence:
        self._store[evidence.evidence_id] = evidence
        return evidence

    async def update(self, evidence: Evidence) -> Evidence:
        self._store[evidence.evidence_id] = evidence
        return evidence

    async def get_by_id(self, evidence_id: uuid.UUID, org_id: uuid.UUID) -> Evidence | None:
        ev = self._store.get(evidence_id)
        if ev and ev.metadata.org_id == org_id:
            return ev
        return None

    async def stream_by_case(  # type: ignore[override]
        self, case_id: uuid.UUID, org_id: uuid.UUID
    ) -> AsyncIterator[Evidence]:
        for ev in self._store.values():
            if ev.metadata.case_id == case_id and ev.metadata.org_id == org_id:
                yield ev

    async def stream_by_state(  # type: ignore[override]
        self, state: EvidenceState, org_id: uuid.UUID
    ) -> AsyncIterator[Evidence]:
        for ev in self._store.values():
            if ev.state == state and ev.metadata.org_id == org_id:
                yield ev

    async def delete_by_id(self, evidence_id: uuid.UUID, org_id: uuid.UUID) -> bool:
        ev = self._store.get(evidence_id)
        if ev and ev.metadata.org_id == org_id:
            del self._store[evidence_id]
            return True
        return False


@pytest.fixture
def audit_repo() -> InMemoryAuditLogRepository:
    return InMemoryAuditLogRepository()


@pytest.fixture
def audit_service(audit_repo: InMemoryAuditLogRepository) -> AuditLogService:
    return AuditLogService(audit_repo)


@pytest.fixture
def evidence_repo() -> InMemoryEvidenceRepository:
    return InMemoryEvidenceRepository()
