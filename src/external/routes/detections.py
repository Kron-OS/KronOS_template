"""Detection list/detail/triage routes (roadmap M2/C6).

Backend-filtered, org-scoped surface over the audited ``Detection`` entity
(C4). Per the A3 gate STATUS note (docs/NEXTGEN_SOC_ROADMAP.md), this is the
ONLY tenant-facing path to real OpenSearch Security Analytics finding data —
Security Analytics/Alerting's own APIs (``_plugins/_security_analytics/*``)
are never proxied or exposed to a tenant session from this module, and the
native SA Dashboards UI is never linked here either.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from src.adapter.repository.detection import DetectionRepository
from src.application.detection_triage import DetectionTriageService
from src.domain.detection import Detection, DetectionTriageState
from src.domain.user import Role, TenantContext
from src.exceptions import DetectionStateError, ValidationError
from src.external.dependencies import (
    get_detection_repository,
    get_detection_triage_service,
    get_tenant_context,
)
from src.external.middleware.rbac import requires_role

router = APIRouter(prefix="/api/detections", tags=["detections"])


# ---------------------------------------------------------------------------
# DTOs
# ---------------------------------------------------------------------------


class DetectionRuleMatchOut(BaseModel):
    """API response DTO for one matched Sigma rule."""

    ruleId: str
    ruleName: str | None
    tags: list[str]


class RiskFactorOut(BaseModel):
    """API response DTO for one RiskScoreBreakdown factor (roadmap M5/F4)."""

    name: str
    weight: float
    normalizedValue: float | None
    detail: str


class DetectionOut(BaseModel):
    """API response DTO — field names match the frontend TypeScript Detection interface."""

    id: uuid.UUID
    orgId: uuid.UUID
    caseId: uuid.UUID | None
    findingId: str
    detectorName: str
    sourceIndex: str
    ruleMatches: list[DetectionRuleMatchOut]
    matchedDocumentIds: list[str]
    attackTags: list[str]
    findingTimestamp: str
    triageState: str
    syncedAt: str
    updatedAt: str
    riskScore: float | None
    riskFactors: list[RiskFactorOut]


class PaginatedDetections(BaseModel):
    items: list[DetectionOut]
    total: int
    page: int
    pageSize: int


class TriageIn(BaseModel):
    """Request body for POST /detections/{id}/triage."""

    targetState: DetectionTriageState


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("", response_model=PaginatedDetections)
async def list_detections(
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
    detection_repo: Annotated[DetectionRepository, Depends(get_detection_repository)],
    triage_state: Annotated[DetectionTriageState | None, Query(alias="triageState")] = None,
    case_id: Annotated[uuid.UUID | None, Query(alias="caseId")] = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200, alias="pageSize"),
) -> PaginatedDetections:
    """Org-scoped, filterable Detection list.

    ``org_id`` always comes from *tenant* — never a client-supplied
    parameter (roadmap invariant #3: tenant isolation is computed, never
    supplied). Read access mirrors the §1 permission matrix's "Search
    timeline (OS)" row (all four roles may read); mutating via ``/triage``
    is gated separately below.

    ``case_id``/``triage_state`` are additive in-memory filters applied
    over the org's own repository stream (mirrors ``cases.py``'s
    ``list_case_evidence`` pagination idiom) — adding a new filter
    dimension later (e.g. ``attack_tags``) needs only another predicate
    here, no repository or schema change.
    """
    source = (
        detection_repo.stream_by_case(case_id, tenant.org_id)
        if case_id is not None
        else detection_repo.stream_by_org(tenant.org_id)
    )
    items = [d async for d in source if triage_state is None or d.triage_state == triage_state]

    total = len(items)
    start = (page - 1) * page_size
    page_items = items[start : start + page_size]

    return PaginatedDetections(
        items=[_to_detection_out(d) for d in page_items],
        total=total,
        page=page,
        pageSize=page_size,
    )


@router.get("/{detection_id}", response_model=DetectionOut)
async def get_detection(
    detection_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
    detection_repo: Annotated[DetectionRepository, Depends(get_detection_repository)],
) -> DetectionOut:
    """Single Detection by id, org-scoped.

    404 (not 403) when the id belongs to another org or does not exist —
    a 403 would confirm the id is real, leaking cross-org existence
    (roadmap invariant #3).
    """
    detection = await detection_repo.get_by_id(detection_id, tenant.org_id)
    if detection is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Detection not found")
    return _to_detection_out(detection)


@router.post("/{detection_id}/triage", response_model=DetectionOut)
async def triage_detection(
    detection_id: uuid.UUID,
    body: TriageIn,
    tenant: Annotated[
        TenantContext, Depends(requires_role(Role.ORG_ADMIN, Role.CASE_LEAD, Role.ANALYST))
    ],
    triage_service: Annotated[DetectionTriageService, Depends(get_detection_triage_service)],
) -> DetectionOut:
    """Advance a Detection's triage FSM.

    Triage is a meaningful analytical action (mirrors the §1 matrix's
    "Upload evidence" row — org-admin/case-lead/analyst, not read-only),
    so it is gated stricter than the read routes above. Every transition
    goes through ``DetectionTriageService`` (audited both on success and
    rejection — roadmap invariant #4); this route never writes to the
    repository directly.

    An illegal FSM transition surfaces as 409 (mirrors ``evidence.py``'s
    ``EvidenceStateError`` → 409 idiom for ``DetectionStateError``), not a
    raw 500. "Detection not found or belongs to another org" is a 404
    (``DetectionTriageService.transition`` already scopes its own lookup
    by ``tenant.org_id``), never a 403 that would leak existence.
    """
    try:
        updated = await triage_service.transition(detection_id, body.targetState, tenant)
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except DetectionStateError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    return _to_detection_out(updated)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _to_detection_out(detection: Detection) -> DetectionOut:
    return DetectionOut(
        id=detection.detection_id,
        orgId=detection.org_id,
        caseId=detection.case_id,
        findingId=detection.finding_id,
        detectorName=detection.detector_name,
        sourceIndex=detection.source_index,
        ruleMatches=[
            DetectionRuleMatchOut(ruleId=m.rule_id, ruleName=m.rule_name, tags=list(m.tags))
            for m in detection.rule_matches
        ],
        matchedDocumentIds=list(detection.matched_document_ids),
        attackTags=list(detection.attack_tags),
        findingTimestamp=detection.finding_timestamp.isoformat(),
        triageState=detection.triage_state.value,
        syncedAt=detection.synced_at.isoformat(),
        updatedAt=detection.updated_at.isoformat(),
        riskScore=detection.risk_score,
        riskFactors=[
            RiskFactorOut(
                name=f.name, weight=f.weight, normalizedValue=f.normalized_value, detail=f.detail
            )
            for f in detection.risk_factors
        ],
    )
