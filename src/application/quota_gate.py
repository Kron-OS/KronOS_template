"""StorageQuotaGate: the one class both quota enforcement hooks call.

See docs/TENANT_USAGE_QUOTA.md §2/§3 for the full design and the fail-open
reasoning below.
"""

from __future__ import annotations

import logging
import uuid

from pydantic import BaseModel

from src.adapter.repository.quota import OrgQuotaRepository
from src.application.tenant_usage import TenantUsageService
from src.exceptions import StorageError

logger = logging.getLogger(__name__)

# Storage ceiling, hard: new uploads rejected once real usage would exceed
# this multiple of the configured quota.
HARD_CEILING_MULTIPLIER = 1.5
# Ingestion ceiling, soft: dispatch-to-parse held once usage is at or above
# this multiple of the configured quota.
SOFT_CEILING_MULTIPLIER = 1.0


class QuotaDecision(BaseModel):
    """Never a bare bool -- always carries the real numbers behind a
    check_upload_allowed() verdict, mirroring this codebase's own
    established idiom for decision objects."""

    model_config = {"frozen": True}

    allowed: bool
    reason: str | None = None
    current_usage_bytes: int
    quota_bytes: int | None  # None = unlimited


class StorageQuotaGate:
    """Enforces the two per-org storage ceilings (docs/TENANT_USAGE_QUOTA.md §1).

    Fail-open by design: if the quota subsystem itself (OrgQuotaRepository /
    TenantUsageService) cannot reach Postgres, both checks return "allowed"
    / "not held" rather than raising. This is deliberately the OPPOSITE of
    ClamAV's production fail-closed gate (configure_clamav_from_settings) --
    that gate protects against a fundamentally different risk (malware
    reaching storage) where failing open is a security hole. A storage
    quota is a cost/capacity control, not a security control: failing
    closed here would mean a transient blip in this one new subsystem's own
    (possibly brand-new, not-yet-fully-migrated) table blocks or silently
    stalls the platform's central mission -- capturing forensic evidence --
    for every org, including ones that are nowhere near their quota. A
    temporarily-unenforced storage cap is a recoverable, boring problem
    (fix the DB, quota checks resume); evidence that should have been
    captured but wasn't because an unrelated accounting table had a bad
    moment is not recoverable. Every fail-open event is logged and would be
    a legitimate alerting signal in a production deployment -- there is no
    silent-and-unnoticed failure mode here, only the FAILURE-VS-BLOCK
    tradeoff.
    """

    def __init__(
        self, quota_repository: OrgQuotaRepository, usage_service: TenantUsageService
    ) -> None:
        self._quota_repo = quota_repository
        self._usage = usage_service

    async def check_upload_allowed(
        self, org_id: uuid.UUID, incoming_size_bytes: int
    ) -> QuotaDecision:
        """The 1.5x hard ceiling check, consulted before issuing a presigned upload URL."""
        try:
            quota = await self._quota_repo.get(org_id)
            usage = await self._usage.get_current_usage_bytes(org_id)
        except StorageError as exc:
            logger.warning(
                "quota_check_unavailable_fail_open_upload",
                extra={"org_id": str(org_id), "error": str(exc)},
            )
            return QuotaDecision(
                allowed=True,
                reason="quota_check_unavailable_fail_open",
                current_usage_bytes=0,
                quota_bytes=None,
            )

        if quota is None or quota.storage_quota_bytes is None:
            return QuotaDecision(
                allowed=True, reason=None, current_usage_bytes=usage, quota_bytes=None
            )

        hard_ceiling = int(quota.storage_quota_bytes * HARD_CEILING_MULTIPLIER)
        projected = usage + incoming_size_bytes
        if projected > hard_ceiling:
            return QuotaDecision(
                allowed=False,
                reason="storage_hard_ceiling_exceeded",
                current_usage_bytes=usage,
                quota_bytes=quota.storage_quota_bytes,
            )
        return QuotaDecision(
            allowed=True,
            reason=None,
            current_usage_bytes=usage,
            quota_bytes=quota.storage_quota_bytes,
        )

    async def is_ingestion_held(self, org_id: uuid.UUID) -> bool:
        """The 1.0x soft ceiling check, consulted before dispatching parsing."""
        try:
            quota = await self._quota_repo.get(org_id)
            usage = await self._usage.get_current_usage_bytes(org_id)
        except StorageError as exc:
            logger.warning(
                "quota_check_unavailable_fail_open_ingestion",
                extra={"org_id": str(org_id), "error": str(exc)},
            )
            return False

        if quota is None or quota.storage_quota_bytes is None:
            return False
        return usage >= quota.storage_quota_bytes
