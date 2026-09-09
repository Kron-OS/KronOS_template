"""Abstract and in-memory case repository."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from src.domain.case import Case, CaseStatus

CaseSortField = Literal["createdAt", "updatedAt", "title"]
CaseSortOrder = Literal["asc", "desc"]


@dataclass(frozen=True)
class CaseFilter:
    """Optional filter/sort parameters for ``CaseRepository.list_by_org``.

    All fields default to "no filter" -- ``list_by_org(org_id)`` with no
    filter argument is unchanged behavior. ``q`` matches (case-insensitive,
    substring) against title, description, and reference_number combined
    with OR; every other field is a plain AND-ed equality/range predicate.
    """

    q: str | None = None
    status: CaseStatus | None = None
    classification: str | None = None
    created_from: datetime | None = None
    created_to: datetime | None = None
    sort_by: CaseSortField = "createdAt"
    sort_order: CaseSortOrder = "desc"


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
        self,
        org_id: uuid.UUID,
        page: int = 1,
        page_size: int = 50,
        *,
        filters: CaseFilter | None = None,
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
        self,
        org_id: uuid.UUID,
        page: int = 1,
        page_size: int = 50,
        *,
        filters: CaseFilter | None = None,
    ) -> tuple[list[Case], int]:
        candidates = [c for c in self._store.values() if c.org_id == org_id]
        if filters is not None:
            candidates = [c for c in candidates if _matches(c, filters)]
            sort_key = _SORT_KEY_FNS[filters.sort_by]
            candidates.sort(key=sort_key, reverse=filters.sort_order == "desc")
        else:
            candidates.sort(key=lambda c: c.created_at, reverse=True)

        total = len(candidates)
        start = (page - 1) * page_size
        return candidates[start : start + page_size], total

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


_SORT_KEY_FNS: dict[CaseSortField, Any] = {
    "createdAt": lambda c: c.created_at,
    "updatedAt": lambda c: c.updated_at,
    "title": lambda c: c.metadata.title.lower(),
}


def _matches(case: Case, filters: CaseFilter) -> bool:
    if filters.q:
        needle = filters.q.lower()
        haystacks = (case.metadata.title, case.metadata.description, case.metadata.reference_number)
        if not any(needle in h.lower() for h in haystacks if h):
            return False
    if filters.status is not None and case.status != filters.status:
        return False
    if (
        filters.classification is not None
        and case.metadata.classification != filters.classification
    ):
        return False
    if filters.created_from is not None and case.created_at < filters.created_from:
        return False
    if filters.created_to is not None and case.created_at > filters.created_to:
        return False
    return True
