"""Cases and per-case evidence listing routes."""

from __future__ import annotations

import urllib.parse
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from src.adapter.keycloak.admin_client import KeycloakAdminClient
from src.adapter.opensearch.dashboards_client import (
    DashboardsIndexPatternProvisioner,
    case_index_pattern_id,
)
from src.adapter.opensearch.detector_provisioner import DetectorProvisioner
from src.adapter.repository.case_repository import CaseRepository
from src.adapter.repository.evidence import EvidenceRepository
from src.adapter.storage.storage import EvidenceStorage
from src.application.audit_log import AuditLogService
from src.domain.audit import AuditEvent, AuditEventType
from src.domain.case import Case, CaseMetadata, CaseStatus
from src.domain.user import Role, TenantContext
from src.exceptions import KronOSException
from src.external.dependencies import (
    get_audit_log_service,
    get_case_repository,
    get_dashboards_index_pattern_provisioner,
    get_detector_provisioner,
    get_evidence_repository,
    get_evidence_storage,
    get_keycloak_admin_client,
    get_opensearch_dashboards_url,
    get_tenant_context,
)
from src.external.middleware.rbac import (
    assert_case_access,
    assert_case_lead_or_admin,
    requires_role,
)
from src.external.routes._http_helpers import sanitize_content_disposition_filename
from src.external.routes.evidence import EvidenceOut, to_evidence_out

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
    """API response DTO — field names match the frontend TypeScript Case interface."""

    id: uuid.UUID
    orgId: uuid.UUID
    title: str
    description: str | None
    reference: str | None
    status: str
    createdAt: str
    updatedAt: str
    createdBy: str
    evidenceCount: int = 0
    # Gap Audit Milestone RRRR: was silently absent -- every membership
    # mutation (add_case_member/remove_case_member) already existed and
    # was already tested, but no response DTO ever exposed the resulting
    # member list, so no UI could ever be built to show it. Real Keycloak
    # user ids, not resolved usernames -- resolving those needs a real
    # Admin API round trip the frontend does per-row (out of scope for
    # this DTO; the current UI shows raw ids, same as the API already did).
    memberUserIds: list[str] = Field(default_factory=list)


class PaginatedCases(BaseModel):
    items: list[CaseOut]
    total: int
    page: int
    pageSize: int


class PaginatedEvidence(BaseModel):
    items: list[EvidenceOut]
    total: int
    page: int
    pageSize: int


class DashboardUrlOut(BaseModel):
    url: str


class AddCaseMemberIn(BaseModel):
    """Assign an existing org user as a member of a case (AUTH-007)."""

    userId: uuid.UUID


class AuditEventOut(BaseModel):
    """API response DTO — field names match the frontend TypeScript AuditEvent interface."""

    id: uuid.UUID
    eventType: str
    evidenceId: uuid.UUID | None
    caseId: uuid.UUID | None
    orgId: uuid.UUID | None
    userId: str
    occurredAt: str
    details: dict[str, Any]
    rowHash: str | None
    sequenceNumber: int


class PaginatedAuditLog(BaseModel):
    items: list[AuditEventOut]
    total: int
    page: int
    pageSize: int


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("", response_model=CaseOut, status_code=status.HTTP_201_CREATED)
async def create_case(
    body: CreateCaseIn,
    background_tasks: BackgroundTasks,
    tenant: Annotated[TenantContext, Depends(requires_role(Role.ORG_ADMIN, Role.CASE_LEAD))],
    case_repo: Annotated[CaseRepository, Depends(get_case_repository)],
    audit_svc: Annotated[AuditLogService, Depends(get_audit_log_service)],
    dashboards_provisioner: Annotated[
        DashboardsIndexPatternProvisioner | None, Depends(get_dashboards_index_pattern_provisioner)
    ] = None,
    detector_provisioner: Annotated[
        DetectorProvisioner | None, Depends(get_detector_provisioner)
    ] = None,
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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        ) from exc

    await audit_svc.log(
        AuditEventType.CASE_CREATED,
        org_id=tenant.org_id,
        case_id=case.case_id,
        actor_user_id=tenant.user_id,
        details={"title": body.title},
    )

    # Best-effort: without this, Discover has no saved index pattern to open
    # and every real user lands on Dashboards' "create an index pattern
    # first" empty state (poc/opensearch_dashboards_dls/README.md). Failures
    # are logged, not raised — a transient Dashboards outage must not block
    # case creation.
    #
    # Genuinely real, verified-live finding (Milestone VVV): these two calls
    # used to be `await`ed directly here, which contradicted the "must not
    # block case creation" comment above -- both provisioners only swallow
    # ERRORS, not SLOWNESS, and a real run against a freshly-started
    # OpenSearch showed the "windows" detector's own real
    # POST /_plugins/_security_analytics/detectors call (its prepackaged
    # Sigma rule set is far larger than cloudtrail/network's) can genuinely
    # take longer than SecurityAnalyticsDetectorProvisioner's own 15s httpx
    # client timeout, so the awaited call really did make the whole
    # POST /api/cases response hang for 15+ seconds -- confirmed via real
    # backend logs (a 15s gap between the rules search and the timeout being
    # logged, `error: ""` matching a bare httpx.TimeoutException's empty
    # message) surfaced by a real browser E2E run, not a hypothetical.
    # BackgroundTasks (runs after the response is sent, not a Celery queue --
    # both provisioners are self-contained, own httpx.AsyncClient per call,
    # no request-scoped resource is used after the response) is what
    # actually fulfils the comment's own stated contract for the first time.
    if dashboards_provisioner is not None:
        background_tasks.add_task(
            dashboards_provisioner.ensure_case_index_pattern, tenant.org_alias, case.case_id
        )

    # Best-effort (roadmap M2/C2): idempotent, so this is cheap after the
    # first case for an org (existence check only) and real detector
    # creation only happens once, the first time. A transient Security
    # Analytics outage must not block case creation -- the provisioner
    # itself already swallows per-log-type failures; the next case
    # creation for this org will simply retry. See the dashboards_provisioner
    # comment above for why this is now a background task, not awaited.
    if detector_provisioner is not None:
        background_tasks.add_task(detector_provisioner.ensure_org_detectors, tenant.org_alias)

    return _to_case_out(case)


@router.get("", response_model=PaginatedCases)
async def list_cases(
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
    case_repo: Annotated[CaseRepository, Depends(get_case_repository)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200, alias="pageSize"),
) -> PaginatedCases:
    """Return paginated cases for the caller's org."""
    cases, total = await case_repo.list_by_org(tenant.org_id, page=page, page_size=page_size)
    return PaginatedCases(
        items=[_to_case_out(c) for c in cases],
        total=total,
        page=page,
        pageSize=page_size,
    )


@router.get("/{case_id}", response_model=CaseOut)
async def get_case(
    case_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
    case_repo: Annotated[CaseRepository, Depends(get_case_repository)],
) -> CaseOut:
    """Return a single case by ID, scoped to the caller's org and case membership."""
    case = await case_repo.get_by_id(case_id, tenant.org_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    assert_case_access(tenant, case)
    return _to_case_out(case)


@router.post("/{case_id}/members", response_model=CaseOut)
async def add_case_member(
    case_id: uuid.UUID,
    body: AddCaseMemberIn,
    tenant: Annotated[TenantContext, Depends(requires_role(Role.ORG_ADMIN, Role.CASE_LEAD))],
    case_repo: Annotated[CaseRepository, Depends(get_case_repository)],
    audit_svc: Annotated[AuditLogService, Depends(get_audit_log_service)],
    admin_client: Annotated[KeycloakAdminClient | None, Depends(get_keycloak_admin_client)],
) -> CaseOut:
    """Assign a user as a member of a case (AUTH-007).

    Per the §1 permission matrix ("Assign members": org-admin all, case-lead
    of case only), a case-lead may only assign members to a case they lead —
    enforced via ``assert_case_lead_or_admin``.

    Gap Audit Milestone QQQQ: ``body.userId`` is now validated against the
    caller's own org before being accepted — previously any UUID was
    accepted with no existence/org check at all (a real, low-severity gap
    named in Milestone KKKK's security assessment; low exploitability
    because ``CaseRepository.get_by_id`` is itself org-scoped, so a
    member id belonging to a different org's user still can't reach this
    case through that org's own query path, but an unvalidated id could
    still add dead/garbage membership rows with no feedback to the
    caller). Reuses the already-DI-wired ``KeycloakAdminClient.is_org_member``
    (the same real Admin API check ``admin.py``'s own ``_assert_user_in_org``
    already relies on for its own, route-local org-scoping guard) rather
    than inventing a second implementation. Honestly skipped (not silently
    bypassed — see the module-level dependency's own "None means not
    configured" contract) when no ``KeycloakAdminClient`` is configured,
    matching every other optional-Keycloak-Admin-API feature in this
    codebase (e.g. ``get_revoke_keycloak_session_action``).
    """
    case = await case_repo.get_by_id(case_id, tenant.org_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    assert_case_lead_or_admin(tenant, case)

    target_is_org_member = (
        admin_client is None or await admin_client.is_org_member(tenant.org_id, body.userId)
    )
    if not target_is_org_member:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Target user is not a member of your organization",
        )

    updated = await case_repo.update(case.with_member(body.userId))
    await audit_svc.log(
        AuditEventType.CASE_UPDATED,
        org_id=tenant.org_id,
        case_id=case_id,
        actor_user_id=tenant.user_id,
        details={"action": "case.member_added", "member_user_id": str(body.userId)},
    )
    return _to_case_out(updated)


@router.delete("/{case_id}/members/{user_id}", response_model=CaseOut)
async def remove_case_member(
    case_id: uuid.UUID,
    user_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(requires_role(Role.ORG_ADMIN, Role.CASE_LEAD))],
    case_repo: Annotated[CaseRepository, Depends(get_case_repository)],
    audit_svc: Annotated[AuditLogService, Depends(get_audit_log_service)],
) -> CaseOut:
    """Revoke a user's membership of a case (AUTH-007).

    Same gating as ``add_case_member`` (`assert_case_lead_or_admin` — a
    case-lead may only remove members from a case they lead), the mirror
    image the platform never had: membership was add-only until now.
    Idempotent, same as ``add_case_member``'s own union semantics —
    removing a user who isn't currently a member is a no-op success, not
    a 404, since the caller's intent ("this user should not be a member")
    is already satisfied either way.
    """
    case = await case_repo.get_by_id(case_id, tenant.org_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    assert_case_lead_or_admin(tenant, case)

    updated = await case_repo.update(case.without_member(user_id))
    await audit_svc.log(
        AuditEventType.CASE_UPDATED,
        org_id=tenant.org_id,
        case_id=case_id,
        actor_user_id=tenant.user_id,
        details={"action": "case.member_removed", "member_user_id": str(user_id)},
    )
    return _to_case_out(updated)


@router.delete("/{case_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_case(
    case_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(requires_role(Role.ORG_ADMIN, Role.CASE_LEAD))],
    case_repo: Annotated[CaseRepository, Depends(get_case_repository)],
    audit_svc: Annotated[AuditLogService, Depends(get_audit_log_service)],
) -> None:
    """Archive a case.

    AUTH-009: the permission matrix grants this to case-lead as well as
    org-admin, but only for a case the case-lead actually leads
    (``assert_case_lead_or_admin``) — previously this was org-admin-only,
    stricter than the documented matrix.
    """
    case = await case_repo.get_by_id(case_id, tenant.org_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    assert_case_lead_or_admin(tenant, case)

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
    case_repo: Annotated[CaseRepository, Depends(get_case_repository)],
    evidence_repo: Annotated[EvidenceRepository, Depends(get_evidence_repository)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200, alias="pageSize"),
) -> PaginatedEvidence:
    """Return paginated evidence for a case, scoped to org and case membership."""
    case = await case_repo.get_by_id(case_id, tenant.org_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    assert_case_access(tenant, case)

    items = []
    async for ev in evidence_repo.stream_by_case(case_id, tenant.org_id):
        items.append(ev)

    total = len(items)
    start = (page - 1) * page_size
    page_items = items[start : start + page_size]

    return PaginatedEvidence(
        items=[to_evidence_out(ev) for ev in page_items],
        total=total,
        page=page,
        pageSize=page_size,
    )


@router.get("/{case_id}/evidence/{evidence_id}/download")
async def download_evidence(
    case_id: uuid.UUID,
    evidence_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
    case_repo: Annotated[CaseRepository, Depends(get_case_repository)],
    evidence_repo: Annotated[EvidenceRepository, Depends(get_evidence_repository)],
    storage: Annotated[EvidenceStorage, Depends(get_evidence_storage)],
    audit_log: Annotated[AuditLogService, Depends(get_audit_log_service)],
) -> StreamingResponse:
    """Stream the real original evidence bytes for download (Gap Audit X1,
    docs/GAP_AUDIT_2026-08-17.md) -- previously no route exposed this at
    all; `EvidenceStorage.stream_object()` was only ever called internally
    (parsing/hashing/scanning).

    Read access, not a mutation -- gated identically to
    `list_case_evidence` above (any authenticated org member with real
    case access, all four roles including READ_ONLY, no role restriction
    beyond that). 404 (never 403) for a case/evidence id that doesn't
    exist or doesn't belong to the caller's org, matching this file's own
    "never leak cross-org existence via 403" convention.

    Streams real bytes straight through from MinIO -- never mints a
    presigned URL for this. A presigned URL could be used later or shared
    without the backend ever knowing; streaming through the backend keeps
    the audit event synchronous with the actual access, which is the
    whole point of logging it (CLAUDE.md SS A.2).
    """
    case = await case_repo.get_by_id(case_id, tenant.org_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    assert_case_access(tenant, case)

    evidence = await evidence_repo.get_by_id(evidence_id, tenant.org_id)
    if evidence is None or evidence.metadata.case_id != case_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")

    if evidence.minio_evidence_key is None:
        # Not yet promoted to the evidence (WORM) bucket -- e.g. still
        # UPLOADING/SCANNING/HASHING, or ERROR before promotion. There is
        # genuinely no object to stream yet; this is an honest 404; the
        # promoted key is what stream_object() needs, not the quarantine
        # key (which may already be deleted by the time this is called).
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence file is not yet available for download",
        )

    # Logged on real access-attempt (this call reaching here with a real,
    # promoted object to stream), not decoupled from the streaming
    # response's own eventual completion, which the server can't always
    # observe anyway for a client that disconnects mid-download.
    await audit_log.log(
        AuditEventType.EVIDENCE_DOWNLOAD,
        org_id=tenant.org_id,
        case_id=case_id,
        evidence_id=evidence_id,
        actor_user_id=tenant.user_id,
        actor_username=tenant.username,
        details={"original_filename": evidence.metadata.original_filename},
    )

    filename = sanitize_content_disposition_filename(evidence.metadata.original_filename)
    byte_stream = await storage.stream_object(evidence.minio_evidence_key, bucket="evidence")
    return StreamingResponse(
        byte_stream,
        media_type=evidence.metadata.content_type or "application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
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
    assert_case_access(tenant, case)

    # Real finding (poc/dashboards_embed/autoload_verification/): data-explorer
    # (the app data-explorer/discover actually runs inside) uses HASH-based
    # routing for its own Redux state -- a top-level `?_a=`/`?_g=` query
    # param (the previous approach) is silently ignored; the app's own
    # router overwrites it from getPreloadedState() (whatever index pattern
    # was last viewed) before the page ever renders. The real, working
    # state lives in the URL FRAGMENT as `#?_a=...&_g=...&_q=...`, confirmed
    # by loading a real hand-built URL in a real logged-in browser and
    # reading back what the app's own router settled on. `_a.metadata`
    # (src/plugins/data_explorer/public/utils/state_management/metadata_slice.ts
    # at tag 2.11.1) is what selects the index pattern by its real
    # saved-object id (case_index_pattern_id(), same id
    # DashboardsIndexPatternProvisioner provisions) — no separate `_a` key
    # for the query/filter; that lives in `_q` instead, confirmed against
    # the same real 2.11.1 source.
    pattern_id = case_index_pattern_id(case_id)
    q_state = (
        f"(filters:!(('$state':(store:appState),"
        f"meta:(alias:!n,disabled:!f,index:'{pattern_id}',"
        f"key:kronos.case_id,negate:!f,params:(query:'{case_id}'),type:phrase),"
        f"query:(match_phrase:(kronos.case_id:'{case_id}')))),"
        f"query:(language:kuery,query:''))"
    )
    # Real finding (frontend/e2e/dashboards-embed.spec.ts, Gap Audit
    # Milestone HHHH): `now-30d` was copied from a generic Discover-embed
    # example without checking it against what this platform actually
    # ingests. Real forensic evidence is virtually never inside the last
    # 30 days -- every committed real fixture under
    # tests/fixtures/samples/real/ is from 2015-2024 (confirmed directly,
    # e.g. system.evtx's own real event timestamps span 2015-08-08 to
    # 2015-08-09) -- so the case's own `kronos.case_id` filter was correct
    # but the DEFAULT view showed "0 hits"/an empty chart on every real
    # case, silently, no error. Widened to a fixed absolute start far
    # enough back to cover any real-world evidence date; the case filter
    # above is what actually scopes the data, this only controls what's
    # visible without the analyst manually widening the picker. Verified
    # live, both ways: reverting just this line to `now-30d` and re-running
    # the spec reproduces a real timeout waiting for "N hits" inside the
    # frame (the exact pre-fix bug), not a hypothetical.
    g_state = (
        "(filters:!(),refreshInterval:(pause:!t,value:0),"
        "time:(from:'2000-01-01T00:00:00.000Z',to:now))"
    )
    a_state = (
        f"(discover:(columns:!(_source),isDirty:!f,sort:!()),"
        f"metadata:(indexPattern:'{pattern_id}',view:discover))"
    )
    top_params = urllib.parse.urlencode(
        {
            "embed": "true",
            "show-top-menu": "false",
            "show-query-input": "true",
            "show-time-filter": "true",
            # Real finding (same PoC): resolveTenant() in the security
            # plugin's server-side tenant_resolver.ts checks a
            # security_tenant query param BEFORE falling back to the
            # session cookie -- setting it here makes the org's tenant
            # resolve on the very first request, skipping the "Select your
            # tenant" dialog real users otherwise always hit first.
            "security_tenant": f"kronos-{case.org_alias}",
        }
    )
    hash_state = f"_a={a_state}&_g={g_state}&_q={q_state}"
    # dashboards_url is browser-facing (see src/config.py) — load Dashboards
    # directly from its own origin rather than proxying it through nginx.
    # Dashboards emits absolute asset URLs (/ui/*, /bootstrap.js) rooted at
    # its own domain, so serving it under a subpath like /dashboards/ breaks
    # those paths; nginx's CSP frame-src is configured with this same origin
    # (see docker/nginx/nginx.conf.template) so the browser is allowed to
    # frame it.
    base = dashboards_url.rstrip("/")
    url = f"{base}/app/data-explorer/discover?{top_params}#?{hash_state}"
    return DashboardUrlOut(url=url)


@router.get("/{case_id}/audit", response_model=PaginatedAuditLog)
async def list_case_audit_events(
    case_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(requires_role(Role.ORG_ADMIN, Role.CASE_LEAD))],
    case_repo: Annotated[CaseRepository, Depends(get_case_repository)],
    audit_svc: Annotated[AuditLogService, Depends(get_audit_log_service)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500, alias="pageSize"),
) -> PaginatedAuditLog:
    """Return paginated audit events for a case, org- and role-scoped.

    AUTH-004: previously any authenticated org member (including analyst and
    read-only) could read a case's full custody trail. Per the §1 permission
    matrix ("View audit log": org-admin all, case-lead own case only,
    analyst/read-only none), this now requires org-admin or case-lead, and a
    case-lead must actually lead *this* case (AUTH-007's ownership check).
    """
    case = await case_repo.get_by_id(case_id, tenant.org_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    assert_case_lead_or_admin(tenant, case)

    # Gap Audit Milestone SS: stream_by_case now takes org_id itself
    # (defense-in-depth, mirrors every other repository's own pattern) --
    # the explicit post-filter below is now redundant with the repository's
    # own WHERE clause, but kept as a second, cheap layer rather than
    # removed, matching this codebase's own belt-and-braces precedent.
    events: list[AuditEvent] = []
    async for ev in audit_svc._repository.stream_by_case(case_id, tenant.org_id):
        if ev.org_id != tenant.org_id:
            continue
        events.append(ev)

    total = len(events)
    start = (page - 1) * page_size
    page_events = events[start : start + page_size]

    return PaginatedAuditLog(
        items=[_to_audit_out(e) for e in page_events],
        total=total,
        page=page,
        pageSize=page_size,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _to_case_out(case: Case) -> CaseOut:
    return CaseOut(
        id=case.case_id,
        orgId=case.org_id,
        title=case.metadata.title,
        description=case.metadata.description,
        reference=case.metadata.reference_number,
        status=case.status.value,
        createdAt=case.created_at.isoformat(),
        updatedAt=case.updated_at.isoformat(),
        createdBy=str(case.owner_user_id),
        memberUserIds=[str(uid) for uid in case.member_user_ids],
    )


def _to_audit_out(ev: AuditEvent) -> AuditEventOut:
    return AuditEventOut(
        id=ev.event_id,
        eventType=ev.event_type.value,
        evidenceId=ev.evidence_id,
        caseId=ev.case_id,
        orgId=ev.org_id,
        userId=str(ev.actor_user_id) if ev.actor_user_id else (ev.actor_username or ""),
        occurredAt=ev.occurred_at.isoformat(),
        details=ev.details,
        rowHash=ev.row_hash,
        sequenceNumber=ev.sequence_number,
    )
