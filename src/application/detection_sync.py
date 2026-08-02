"""DetectionSyncService: mirrors real OpenSearch Security Analytics findings
into KronOS's own audited Detection entity.

Roadmap M2/C4. Orchestration-style service, the same shape as
ParsingOrchestrationService: resolve what real state exists, decide what's
new, execute the mutation, audit it. Strictly READ-ONLY with respect to
OpenSearch -- this class never calls any SA/alerting write endpoint, and
never touches Evidence, the evidence audit chain, or an indexed timeline
record (roadmap invariant #5: derived opinions must never mutate primary
evidence).
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Any

from src.adapter.opensearch.client import AbstractTimelineIndex
from src.adapter.opensearch.detector_provisioner import get_default_log_types
from src.adapter.opensearch.findings_client import FindingsClient
from src.adapter.repository.detection import DetectionRepository
from src.application.audit_log import AuditLogService
from src.application.risk_scoring import ASSET_CRITICALITY_NORMALIZED_LEVELS, DetectionRiskScorer
from src.domain.audit import AuditEventType
from src.domain.detection import Detection, DetectionRuleMatch, highest_rule_severity
from src.domain.user import TenantContext
from src.exceptions import StorageError

logger = logging.getLogger(__name__)

# Matches KronOS's case-index naming convention (timeline_normalization.py:
# kronos-{org}-case-{case_id}-{yyyymm}). Used only for best-effort case
# correlation -- never for tenant attribution (see _extract_case_id below).
_CASE_INDEX_RE = re.compile(r"^kronos-.+-case-(?P<case_id>[0-9a-fA-F-]{36})-\d{6}$")


def _extract_case_id(source_index: str) -> uuid.UUID | None:
    """Best-effort case correlation from the finding's own source index name.

    NOT a security/tenant boundary -- org_id is never derived this way (see
    sync_org_findings, which always uses tenant.org_id). Returns None for
    stream-scoped (roadmap B2) or otherwise unrecognized index names.
    """
    match = _CASE_INDEX_RE.match(source_index)
    if not match:
        return None
    try:
        return uuid.UUID(match.group("case_id"))
    except ValueError:
        return None


class DetectionSyncService:
    """Mirrors NEW real SA findings into Detection rows, exactly once each."""

    def __init__(
        self,
        findings_client: FindingsClient,
        detection_repository: DetectionRepository,
        audit_log: AuditLogService,
        timeline_index: AbstractTimelineIndex,
        log_types: tuple[str, ...] | None = None,
        risk_scorer: DetectionRiskScorer | None = None,
    ) -> None:
        self._findings_client = findings_client
        self._repo = detection_repository
        self._audit = audit_log
        self._timeline_index = timeline_index
        self._log_types = log_types or get_default_log_types()
        self._risk_scorer = risk_scorer or DetectionRiskScorer()

    async def sync_org_findings(self, tenant: TenantContext) -> int:
        """Idempotently mirror this org's real SA findings into Detection rows.

        org_id/org_alias always come from *tenant* -- never from anything
        read out of a finding document (roadmap invariant #3). Returns the
        count of NEW Detection rows actually created this call; re-running
        immediately with no new real findings returns 0 (see
        poc/detection_finding_sync/ for the real, captured proof).
        """
        raw_findings = await self._findings_client.fetch_org_findings(
            tenant.org_alias, self._log_types
        )
        created = 0
        for hit in raw_findings:
            created += await self._sync_one(hit, tenant)
        logger.info(
            "detection_sync_completed",
            extra={
                "org_id": str(tenant.org_id),
                "findings_seen": len(raw_findings),
                "created": created,
            },
        )
        return created

    async def _sync_one(self, hit: dict[str, Any], tenant: TenantContext) -> int:
        finding_id = hit["_id"]

        # Primary idempotency check -- the whole point of this method.
        existing = await self._repo.get_by_finding_id(finding_id, tenant.org_id)
        if existing is not None:
            return 0

        source = hit.get("_source", {})
        rule_matches = tuple(
            DetectionRuleMatch(
                rule_id=q["id"],
                rule_name=q.get("name"),
                tags=tuple(q.get("tags", [])),
            )
            for q in source.get("queries", [])
        )
        source_index = source.get("index", "")
        matched_document_ids = tuple(source.get("related_doc_ids", []))

        # Risk scoring (roadmap M5/F4) -- computed ONCE, right here, before
        # Detection is ever constructed (Detection is frozen; risk_score/
        # risk_factors are constructor args, not a post-hoc mutation, same
        # as case_id above). Uses only what's real and already resolvable
        # at this exact sync moment: this finding's own matched rules'
        # severity tags, plus whatever enrichment.ioc.*/enrichment.asset.*
        # fields its matched documents carry RIGHT NOW -- see
        # Detection.risk_score's own docstring for why that's the correct
        # replayability contract, not a live/on-demand recomputation later.
        rule_severity = highest_rule_severity(rule_matches)
        ioc_confidence, asset_criticality = await self._resolve_risk_inputs(
            source_index, matched_document_ids
        )
        risk_breakdown = self._risk_scorer.score(
            rule_severity=rule_severity,
            ioc_confidence=ioc_confidence,
            asset_criticality=asset_criticality,
        )

        detection = Detection(
            org_id=tenant.org_id,
            org_alias=tenant.org_alias,
            case_id=_extract_case_id(source_index),
            finding_id=finding_id,
            detector_name=source.get("monitor_name", ""),
            source_index=source_index,
            rule_matches=rule_matches,
            matched_document_ids=matched_document_ids,
            finding_timestamp=datetime.fromtimestamp(source["timestamp"] / 1000, tz=UTC),
            risk_score=risk_breakdown.score,
            risk_factors=risk_breakdown.factors,
        )

        details = {
            "detection_id": str(detection.detection_id),
            "finding_id": finding_id,
            "detector_name": detection.detector_name,
            "rule_ids": [m.rule_id for m in rule_matches],
            "risk_score": detection.risk_score,
        }
        try:
            async with self._audit.audit_context(
                AuditEventType.DETECTION_SYNCED,
                AuditEventType.DETECTION_SYNC_FAILED,
                org_id=tenant.org_id,
                case_id=detection.case_id,
                details=details,
            ):
                await self._repo.save(detection)
        except StorageError as exc:
            # Race with a concurrent sync call for the same org: the
            # pre-check above found nothing, but another writer beat us to
            # the (org_id, finding_id) uniqueness guarantee in the
            # meantime. Idempotency still holds overall -- just don't
            # double-count this finding as newly created.
            logger.info(
                "detection_sync_race_skipped",
                extra={"finding_id": finding_id, "org_id": str(tenant.org_id), "error": str(exc)},
            )
            return 0
        return 1

    async def _resolve_risk_inputs(
        self, source_index: str, matched_document_ids: tuple[str, ...]
    ) -> tuple[int | None, str | None]:
        """Fetch this finding's own real matched timeline documents and
        combine their enrichment.ioc.confidence/enrichment.asset.criticality
        fields (F2/F1) into single risk-scorer inputs.

        Multiple matched documents are combined by taking the MAX
        normalized value per factor -- "worst case wins", the same
        reasoning an alerting pipeline should use when one finding spans
        several source documents that could concern different hosts or
        indicators (a finding is exactly as risky as its riskiest matched
        document, not its average one). An index/doc id that no longer
        resolves (source purged, ISM rollover past its retention, index
        deleted) degrades honestly to an absent input for this finding --
        never a fabricated one -- and a lookup failure must never sink the
        whole sync run (mirrors EnrichmentPipeline.enrich()'s own "one
        source's failure must never sink ingest" idiom).
        """
        if not matched_document_ids:
            return None, None
        try:
            docs = await self._timeline_index.get_documents_by_id(
                source_index, list(matched_document_ids)
            )
        except Exception as exc:  # noqa: BLE001 -- see docstring
            logger.warning(
                "risk_scoring_document_lookup_failed",
                extra={"source_index": source_index, "error": str(exc)},
            )
            return None, None

        max_confidence: int | None = None
        max_criticality: str | None = None
        max_criticality_normalized = -1.0
        for doc in docs.values():
            enrichment = doc.get("enrichment") or {}

            confidence = (enrichment.get("ioc") or {}).get("confidence")
            if isinstance(confidence, int) and (
                max_confidence is None or confidence > max_confidence
            ):
                max_confidence = confidence

            criticality = (enrichment.get("asset") or {}).get("criticality")
            if isinstance(criticality, str):
                normalized = ASSET_CRITICALITY_NORMALIZED_LEVELS.get(criticality.strip().lower())
                if normalized is not None and normalized > max_criticality_normalized:
                    max_criticality_normalized = normalized
                    max_criticality = criticality

        return max_confidence, max_criticality
