"""Cases and per-case evidence listing routes."""

from __future__ import annotations

import urllib.parse
import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from src.adapter.repository.case_repository import CaseRepository
from src.adapter.repository.evidence import EvidenceRepository
from src.domain.audit import AuditEventType
from src.domain.case import Case, CaseMetadata, CaseStatus
from src.domain.evidence import EvidenceState
from src.domain.user import Role, TenantContext
from src.exceptions import KronOSException
from src.external.dependencies import (
    get_audit_log_service,
    get_case_repository,
    get_evidence_repository,
    get_opensearch_dashboards_url,
    get_tenant_context,
)
from src.external.middleware.rbac import requires_role

router = APIRouter(prefix="/api/cases", tags=["cases"])


# ---------------------------------------------------------------------------
# DTOs
# ---------------------------------------------------------------------------


class CreateCaseIn(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: str | None = None
    reference_number: str | None = None
    classification: str = "UNCLASSIFIED"


class CaseOut(BaseModel):
    case_id: uuid.UUID
    org_id: uuid.UUID
    title: str
    description: str | None
    reference_number: str | None
    status: str
    created_at: str
    updated_at: str


class PaginatedCases(BaseModel):
    items: list[CaseOut]
    total: int
    page: int
    page_size: int


class EvidenceListItem(BaseModel):
    evidence_id: uuid.UUID
    filename: str
    size_bytes: int
    sha256: str | None
    state: EvidenceState
    error_reason: str | None
    uploader_user_id: uuid.UUID
    created_at: str
    updated_at: str


class PaginatedEvidence(BaseModel):
    items: list[EvidenceListItem]
    total: int
    page: int
    page_size: int


class DashboardUrlOut(BaseModel):
    url: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
async def create_case(
    body: CreateCaseIn,
    tenant: Annotated[TenantContext, Depends(requires_role(Role.ORG_ADMIN, Role.CASE_LEAD))],
    case_repo: Annotated[CaseRepository, Depends(get_case_repository)],
    audit_svc=Depends(get_audit_log_service),
) -> CaseOut:
    """Create a new investigation case for the caller's org."""
    case = Case(
        org_id=tenant.org_id,
        org_alias=tenant.org_alias,
        owner_user_id=tenant.user_id,
        metadata=CaseMetadata(
            title=body.title,
            description=body.description,
            reference_number=body.reference_number,
            classification=body.classification,
        ),
    )
    try:
        case = await case_repo.save(case)
    except KronOSException as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc

    await audit_svc.log(
        AuditEventType.CASE_CREATED,
        org_id=tenant.org_id,
        case_id=case.case_id,
        actor_user_id=tenant.user_id,
        details={"title": body.title},
    )
    return _to_case_out(case)


@router.get("", response_model=PaginatedCases)
async def list_cases(
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
    case_repo: Annotated[CaseRepository, Depends(get_case_repository)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> PaginatedCases:
    """Return paginated cases for the caller's org."""
    cases, total = await case_repo.list_by_org(tenant.org_id, page=page, page_size=page_size)
    return PaginatedCases(
        items=[_to_case_out(c) for c in cases],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{case_id}", response_model=CaseOut)
async def get_case(
    case_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
    case_repo: Annotated[CaseRepository, Depends(get_case_repository)],
) -> CaseOut:
    """Return a single case by ID, scoped to the caller's org."""
    case = await case_repo.get_by_id(case_id, tenant.org_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    return _to_case_out(case)


@router.delete("/{case_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_case(
    case_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(requires_role(Role.ORG_ADMIN))],
    case_repo: Annotated[CaseRepository, Depends(get_case_repository)],
    audit_svc=Depends(get_audit_log_service),
) -> None:
    """Archive a case (org-admin only)."""
    case = await case_repo.get_by_id(case_id, tenant.org_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    archived = case.with_status(CaseStatus.ARCHIVED)
    await case_repo.update(archived)
    await audit_svc.log(
        AuditEventType.CASE_DELETED,
        org_id=tenant.org_id,
        case_id=case_id,
        actor_user_id=tenant.user_id,
        details={"action": "case.archived"},
    )


@router.get("/{case_id}/evidence", response_model=PaginatedEvidence)
async def list_case_evidence(
    case_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
    evidence_repo: Annotated[EvidenceRepository, Depends(get_evidence_repository)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
) -> PaginatedEvidence:
    """Return paginated evidence for a case."""
    items = []
    async for ev in evidence_repo.stream_by_case(case_id, tenant.org_id):
        items.append(ev)

    total = len(items)
    start = (page - 1) * page_size
    page_items = items[start : start + page_size]

    return PaginatedEvidence(
        items=[
            EvidenceListItem(
                evidence_id=ev.evidence_id,
                filename=ev.metadata.original_filename,
                size_bytes=ev.metadata.size_bytes,
                sha256=ev.sha256,
                state=ev.state,
                error_reason=ev.error_reason,
                uploader_user_id=ev.metadata.uploader_user_id,
                created_at=ev.created_at.isoformat(),
                updated_at=ev.updated_at.isoformat(),
            )
            for ev in page_items
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{case_id}/dashboard-url", response_model=DashboardUrlOut)
async def get_dashboard_url(
    case_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
    case_repo: Annotated[CaseRepository, Depends(get_case_repository)],
    dashboards_url: Annotated[str | None, Depends(get_opensearch_dashboards_url)] = None,
) -> DashboardUrlOut:
    """Return the OpenSearch Dashboards embed URL for this case's timeline."""
    if not dashboards_url:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OpenSearch Dashboards not configured",
        )

    case = await case_repo.get_by_id(case_id, tenant.org_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")

    index_pattern = f"kronos-{case.org_alias}-case-{case_id}-*"
    ks_filter = (
        f"(filters:!(('$state':(store:globalState),"
        f"meta:(alias:!n,disabled:!f,index:'{index_pattern}',"
        f"key:kronos.case_id,negate:!f,params:(query:'{case_id}'),type:phrase),"
        f"query:(match_phrase:(kronos.case_id:'{case_id}')))),"
        f"time:(from:now-30d,to:now))"
    )
    params = urllib.parse.urlencode(
        {
            "embed": "true",
            "show-top-menu": "false",
            "show-query-input": "true",
            "show-time-filter": "true",
            "_g": ks_filter,
        }
    )
    base = dashboards_url.rstrip("/")
    url = f"{base}/app/data-explorer/discover?{params}"
    return DashboardUrlOut(url=url)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _to_case_out(case: Case) -> CaseOut:
    return CaseOut(
        case_id=case.case_id,
        org_id=case.org_id,
        title=case.metadata.title,
        description=case.metadata.description,
        reference_number=case.metadata.reference_number,
        status=case.status.value,
        created_at=case.created_at.isoformat(),
        updated_at=case.updated_at.isoformat(),
    )
