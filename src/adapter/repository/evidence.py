"""Abstract repository for evidence metadata persistence."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from src.domain.evidence import Evidence, EvidenceState


class EvidenceRepository(ABC):
    """Evidence metadata CRUD, scoped to org_id at every access."""

    @abstractmethod
    async def save(self, evidence: Evidence) -> Evidence:
        """Persist a new evidence entity and return it."""

    @abstractmethod
    async def update(
        self, evidence: Evidence, *, expected_state: EvidenceState | None = None
    ) -> Evidence:
        """Replace the stored evidence entity with the supplied version.

        When *expected_state* is given, the write is conditioned on the
        persisted row currently being in that state — optimistic concurrency
        (EVID-4) so two concurrent callers racing a FSM transition (e.g. the
        autonomous dispatch path and a manual recovery call) cannot silently
        clobber each other; the loser must raise instead.
        """

    @abstractmethod
    async def get_by_id(self, evidence_id: uuid.UUID, org_id: uuid.UUID) -> Evidence | None:
        """Return evidence if it exists and belongs to org_id, otherwise None."""

    @abstractmethod
    def stream_by_case(self, case_id: uuid.UUID, org_id: uuid.UUID) -> AsyncIterator[Evidence]:
        """Yield all evidence for a case in creation order."""

    @abstractmethod
    def stream_by_state(self, state: EvidenceState, org_id: uuid.UUID) -> AsyncIterator[Evidence]:
        """Yield all evidence in a given state for an org (used by recovery tasks)."""

    @abstractmethod
    def stream_all_by_state(self, state: EvidenceState) -> AsyncIterator[Evidence]:
        """Yield all evidence in a given state across ALL orgs.

        Used exclusively by Celery orphan-cleanup beat tasks which need to
        identify stuck evidence platform-wide.  Never call from a request
        handler — use the org-scoped stream_by_state instead.
        """

    @abstractmethod
    async def delete_by_id(self, evidence_id: uuid.UUID, org_id: uuid.UUID) -> bool:
        """Delete evidence metadata. Returns True if the record existed, False otherwise."""

    @abstractmethod
    async def get_total_size_bytes(self, org_id: uuid.UUID) -> int:
        """Sum of ``size_bytes`` across all non-purged evidence for org_id.

        Backs TenantUsageService's real-time storage-usage computation
        (docs/TENANT_USAGE_QUOTA.md) -- a real SUM query scoped to this
        repository's own query surface rather than a raw-SQL bypass from
        the application layer.
        """

    @abstractmethod
    def stream_quota_held(self, org_id: uuid.UUID) -> AsyncIterator[Evidence]:
        """Yield RECEIVED evidence in org_id currently held for quota (quota_held=True).

        Org-scoped -- safe to call from a request handler (e.g. the admin
        quota PATCH route's direct resume trigger), unlike
        stream_all_quota_held below.
        """

    @abstractmethod
    def stream_all_quota_held(self) -> AsyncIterator[Evidence]:
        """Yield RECEIVED evidence across ALL orgs currently held for quota.

        Used exclusively by the auto_resume_quota_held beat task, mirroring
        stream_all_by_state's own cross-org restriction (CLAUDE.md §E.5) --
        never call from a request handler or any code reachable from one.
        """
