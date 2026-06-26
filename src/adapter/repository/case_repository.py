"""Abstract and in-memory case repository."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from datetime import UTC, datetime

from src.domain.case import Case, CaseMetadata, CaseStatus


class CaseRepository(ABC):
    """Org-scoped case persistence."""

    @abstractmethod
    async def save(self, case: Case) -> Case:
        """Persist a new case and return it."""

    @abstractmethod
    async def get_by_id(self, case_id: uuid.UUID, org_id: uuid.UUID) -> Case | None:
        """Return the case if it belongs to org_id, otherwise None."""

    @abstractmethod
    async def list_by_org(
        self, org_id: uuid.UUID, page: int = 1, page_size: int = 50
    ) -> tuple[list[Case], int]:
        """Return a page of cases for the org plus the total count."""

    @abstractmethod
    async def update(self, case: Case) -> Case:
        """Replace the stored case with the supplied version."""

    @abstractmethod
    async def delete(self, case_id: uuid.UUID, org_id: uuid.UUID) -> bool:
        """Delete a case; returns True if a record was removed."""


class InMemoryCaseRepository(CaseRepository):
    """Thread-unsafe in-memory impl for unit tests."""

    def __init__(self) -> None:
        self._store: dict[uuid.UUID, Case] = {}

    async def save(self, case: Case) -> Case:
        self._store[case.case_id] = case
        return case

    async def get_by_id(self, case_id: uuid.UUID, org_id: uuid.UUID) -> Case | None:
        case = self._store.get(case_id)
        if case is None or case.org_id != org_id:
            return None
        return case

    async def list_by_org(
        self, org_id: uuid.UUID, page: int = 1, page_size: int = 50
    ) -> tuple[list[Case], int]:
        all_cases = sorted(
            [c for c in self._store.values() if c.org_id == org_id],
            key=lambda c: c.created_at,
            reverse=True,
        )
        total = len(all_cases)
        start = (page - 1) * page_size
        return all_cases[start : start + page_size], total

    async def update(self, case: Case) -> Case:
        if case.case_id not in self._store:
            raise KeyError(f"Case {case.case_id} not found")
        self._store[case.case_id] = case
        return case

    async def delete(self, case_id: uuid.UUID, org_id: uuid.UUID) -> bool:
        case = self._store.get(case_id)
        if case is None or case.org_id != org_id:
            return False
        del self._store[case_id]
        return True
