"""CorrelationSyncService: mirrors real OpenSearch Security Analytics
correlation-engine matches into KronOS's own audited DetectionCorrelation
entity.

Roadmap M2/F3. Same orchestration shape as DetectionSyncService (resolve
real state, decide what's new, execute the mutation, audit it) and reuses
DetectionSyncService's own collaborators (DetectionRepository, AuditLogService)
rather than duplicating their tenant-scoping/audit logic -- a new sync PATH,
not a parallel entity (see poc/security_analytics_correlation/README.md
"Design decision").

Tenant isolation (roadmap invariant #3) is enforced ENTIRELY here, because
the real SA correlations API this class reads from
(CorrelationClient.fetch_correlations) has no org/tenant filter of its own
-- confirmed real: its only params are start/end timestamps, cluster-wide.
A pair is only ever recorded for *this* org if BOTH finding ids already
resolve to a Detection row this exact org previously synced (via
DetectionSyncService) -- never from anything the correlations response
itself claims. This mirrors the exact same "computed, never supplied"
contract DetectionSyncService already enforces for org_id.
"""

from __future__ import annotations

import logging
from typing import Any

from src.adapter.opensearch.correlation_client import CorrelationClient
from src.adapter.repository.detection import DetectionRepository
from src.adapter.repository.detection_correlation import DetectionCorrelationRepository
from src.application.audit_log import AuditLogService
from src.domain.audit import AuditEventType
from src.domain.detection import DetectionCorrelation
from src.domain.user import TenantContext
from src.exceptions import StorageError

logger = logging.getLogger(__name__)


class CorrelationSyncService:
    """Mirrors NEW real SA correlation matches into DetectionCorrelation
    rows, exactly once each, scoped strictly to findings this org already
    owns."""

    def __init__(
        self,
        correlation_client: CorrelationClient,
        detection_repository: DetectionRepository,
        correlation_repository: DetectionCorrelationRepository,
        audit_log: AuditLogService,
    ) -> None:
        self._correlation_client = correlation_client
        self._detections = detection_repository
        self._correlations = correlation_repository
        self._audit = audit_log

    async def sync_org_correlations(self, tenant: TenantContext, start_ms: int, end_ms: int) -> int:
        """Idempotently mirror this org's real SA correlation matches within
        [start_ms, end_ms) into DetectionCorrelation rows.

        Returns the count of NEW rows actually created this call. A pair is
        silently skipped (not an error) if either finding_id has no
        Detection already synced for this org -- that's expected for pairs
        involving another org's findings (the raw API is cluster-wide) or
        findings this org hasn't synced yet via DetectionSyncService.
        """
        raw_pairs = await self._correlation_client.fetch_correlations(start_ms, end_ms)
        created = 0
        for pair in raw_pairs:
            created += await self._sync_one(pair, tenant)
        logger.info(
            "correlation_sync_completed",
            extra={
                "org_id": str(tenant.org_id),
                "pairs_seen": len(raw_pairs),
                "created": created,
            },
        )
        return created

    async def _sync_one(self, pair: dict[str, Any], tenant: TenantContext) -> int:
        finding_id_a = pair.get("finding1", "")
        finding_id_b = pair.get("finding2", "")
        if not finding_id_a or not finding_id_b or finding_id_a == finding_id_b:
            return 0

        # Tenant-isolation gate (roadmap invariant #3): only correlate
        # findings THIS org already owns via its own prior DetectionSyncService
        # run -- never trust the cluster-wide correlations response as an
        # org signal.
        detection_a = await self._detections.get_by_finding_id(finding_id_a, tenant.org_id)
        detection_b = await self._detections.get_by_finding_id(finding_id_b, tenant.org_id)
        if detection_a is None or detection_b is None:
            return 0

        if await self._correlations.exists_for_pair(tenant.org_id, finding_id_a, finding_id_b):
            return 0

        correlation = DetectionCorrelation(
            org_id=tenant.org_id,
            detection_id_a=detection_a.detection_id,
            detection_id_b=detection_b.detection_id,
            finding_id_a=finding_id_a,
            finding_id_b=finding_id_b,
            rule_ids=tuple(pair.get("rules", [])),
        )
        details = {
            "correlation_id": str(correlation.correlation_id),
            "finding_id_a": finding_id_a,
            "finding_id_b": finding_id_b,
            "rule_ids": list(correlation.rule_ids),
        }
        try:
            async with self._audit.audit_context(
                AuditEventType.DETECTION_CORRELATED,
                AuditEventType.DETECTION_CORRELATION_SYNC_FAILED,
                org_id=tenant.org_id,
                case_id=detection_a.case_id,
                details=details,
            ):
                await self._correlations.save(correlation)
        except StorageError as exc:
            # Race with a concurrent sync call for the same pair -- the
            # pre-check above found nothing, but another writer beat us to
            # it. Idempotency still holds overall (mirrors
            # DetectionSyncService._sync_one's own race handling).
            logger.info(
                "correlation_sync_race_skipped",
                extra={
                    "finding_id_a": finding_id_a,
                    "finding_id_b": finding_id_b,
                    "org_id": str(tenant.org_id),
                    "error": str(exc),
                },
            )
            return 0
        return 1
