"""OrgQuota domain model — per-org storage quota configuration.

See docs/TENANT_USAGE_QUOTA.md for the full feature design. This is the
first real per-org settings persistence object in the codebase (the
existing ``/admin/settings`` route is a complete stub, see that route's own
docstring) -- kept narrowly scoped to storage quota only, not a generic
"OrgSettings" grab-bag.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from pydantic import BaseModel, Field


class OrgQuota(BaseModel):
    """Configured storage ceiling for one org.

    ``storage_quota_bytes`` is ``None`` when the org has never had a quota
    set -- a real, valid, common case meaning "unlimited", not a sentinel
    number (e.g. 0 or -1) to special-case awkwardly downstream.
    """

    model_config = {"frozen": True}

    org_id: uuid.UUID
    storage_quota_bytes: int | None = Field(default=None, ge=0)
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def with_quota_bytes(self, storage_quota_bytes: int | None) -> OrgQuota:
        """Return a copy with a new quota value (None = unlimited)."""
        return self.model_copy(
            update={"storage_quota_bytes": storage_quota_bytes, "updated_at": datetime.now(UTC)}
        )
