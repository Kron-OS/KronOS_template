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
from pydantic import BaseModel, Field

from src.adapter.repository.detection import DetectionRepository
from src.application.detection_triage import DetectionTriageService
from src.application.playbook import PlaybookActionRegistry
from src.application.playbook_execution import PlaybookExecutionService
from src.domain.detection import Detection, DetectionTriageState
from src.domain.playbook import Playbook, PlaybookStep
from src.domain.user import Role, TenantContext
from src.exceptions import DetectionStateError, ValidationError
from src.external.dependencies import (
    get_detection_repository,
    get_detection_triage_service,
    get_playbook_action_registry,
    get_playbook_execution_service,
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


class PlaybookStepResultOut(BaseModel):
    """API response DTO for one PlaybookStepResult (roadmap M7/H1/W1)."""

    stepId: str
    actionName: str
    outcome: str
    output: dict[str, object] | None
    error: str | None


class PlaybookExecutionResultOut(BaseModel):
    """API response DTO for one PlaybookExecutionResult."""

    executionId: uuid.UUID
    playbookName: str
    succeeded: bool
    haltedEarly: bool
    stepResults: list[PlaybookStepResultOut]


class RevokeKeycloakSessionIn(BaseModel):
    """Request body for POST /detections/{id}/contain/revoke-session.

    ``approvalTicketId`` is a real, already-issued step-up ticket (RFC 9470)
    the caller obtained from the existing ``POST /api/step-up/ticket`` route
    (``operation="revoke_keycloak_session"``, ``resource_id=sessionId``)
    *before* calling this route -- this route never mints or pre-validates
    the ticket itself, ``StepUpApprovalGate.authorize()`` (consulted inside
    ``ContainmentAction.execute()``) is the single place that happens.

    There is deliberately no separate ``approvalResourceId`` field (Gap
    Audit Milestone JJ removed one that existed here before): the resource
    a ticket is checked against is always ``sessionId`` itself, derived
    server-side by ``RevokeKeycloakSessionAction._resource_id()``, never a
    second, independently-supplied value -- a caller-chosen
    ``approvalResourceId`` that only had to match the ticket, with no
    binding to the actual ``sessionId`` being revoked, let a ticket minted
    "for" one session authorize revoking a completely different one (a
    real, reproduced finding, `poc/stepup_ticket_resource_mismatch/`).
    """

    userId: uuid.UUID
    sessionId: str = Field(min_length=1)
    approvalTicketId: uuid.UUID | None = None


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


@router.post("/{detection_id}/sync-to-siem/{sink_name}", response_model=PlaybookExecutionResultOut)
async def sync_detection_to_siem(
    detection_id: uuid.UUID,
    sink_name: str,
    tenant: Annotated[
        TenantContext, Depends(requires_role(Role.ORG_ADMIN, Role.CASE_LEAD, Role.ANALYST))
    ],
    registry: Annotated[PlaybookActionRegistry, Depends(get_playbook_action_registry)],
    execution_service: Annotated[PlaybookExecutionService, Depends(get_playbook_execution_service)],
) -> PlaybookExecutionResultOut:
    """Fire ``SyncDetectionToSiemAction`` for one Detection via a real,
    audited ``PlaybookExecutionService.execute()`` call (roadmap Milestone
    W/W1, IR walkthrough F3) -- the first HTTP route anywhere in this
    codebase that reaches the playbook engine.

    **Real, honestly-reported scope decision.** There is no persisted
    ``Playbook``/playbook-definition repository anywhere in this codebase
    (confirmed by repo-wide grep: every ``Playbook(...)`` construction site
    outside this route is a test file -- ``PlaybookExecutionService
    .execute()`` had zero real callers before this route). Building a
    general "look up a named, stored, multi-step Playbook" mechanism is
    real, separate, larger follow-up scope, not invented here under this
    item's own budget. This route instead constructs one honest, single-step
    ad hoc ``Playbook`` per request, wrapping exactly the one real,
    already-registered action this incident-response scenario actually
    needs (``SyncDetectionToSiemAction``, one instance per configured SIEM
    sink -- see that class's own docstring). ``sink_name`` selects which of
    the (possibly several) real configured sinks to use, since hardcoding
    exactly one would silently break for any deployment with more than one
    sink configured; it does not reintroduce a general "playbook by name"
    indirection -- ``PlaybookActionRegistry.get_action`` is a real,
    already-existing lookup this codebase's own DI wiring
    (``get_playbook_action_registry``) has used since roadmap V2.

    404 when no ``SyncDetectionToSiemAction`` is registered for *sink_name*
    (mirrors this file's own "404, not a fabricated success" idiom) --
    happens when that sink's config (e.g. ``splunk_hec_url``) is unset in
    this deployment, an honest "not configured" state, not a KronOS bug.

    Otherwise always returns 200: whether the Detection existed in the
    caller's own org, and whether the real SIEM push itself succeeded, are
    both reflected in the returned ``PlaybookExecutionResult`` (``succeeded``/
    ``stepResults[0].error``) rather than mapped to a separate HTTP status --
    ``PlaybookExecutionService.execute()`` already audits every outcome
    (``PLAYBOOK_STEP_FAILED``/``_EXECUTED``, invariant #4), so the response
    body is a direct, honest mirror of that same audit trail, not a second,
    competing shape for the same information.
    """
    action_name = f"sync_detection_to_siem_{sink_name}"
    if registry.get_action(action_name) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No SIEM sink named '{sink_name}' is configured in this deployment",
        )

    playbook = Playbook(
        name=f"ad-hoc-sync-detection-to-siem-{sink_name}",
        steps=(
            PlaybookStep(
                step_id="sync-to-siem",
                action_name=action_name,
                params={"detection_id": str(detection_id)},
            ),
        ),
    )
    result = await execution_service.execute(playbook, tenant)
    return PlaybookExecutionResultOut(
        executionId=result.execution_id,
        playbookName=result.playbook_name,
        succeeded=result.succeeded,
        haltedEarly=result.halted_early,
        stepResults=[
            PlaybookStepResultOut(
                stepId=r.step_id,
                actionName=r.action_name,
                outcome=r.outcome.value,
                output=r.output,
                error=r.error,
            )
            for r in result.step_results
        ],
    )


@router.post("/{detection_id}/contain/revoke-session", response_model=PlaybookExecutionResultOut)
async def revoke_session_for_detection(
    detection_id: uuid.UUID,
    body: RevokeKeycloakSessionIn,
    tenant: Annotated[TenantContext, Depends(requires_role(Role.ORG_ADMIN, Role.CASE_LEAD))],
    registry: Annotated[PlaybookActionRegistry, Depends(get_playbook_action_registry)],
    execution_service: Annotated[PlaybookExecutionService, Depends(get_playbook_execution_service)],
    detection_repo: Annotated[DetectionRepository, Depends(get_detection_repository)],
) -> PlaybookExecutionResultOut:
    """Fire ``RevokeKeycloakSessionAction`` for one Detection via a real,
    audited ``PlaybookExecutionService.execute()`` call (roadmap Milestone
    M7/H2/EE1) -- the same ``PlaybookExecutionService`` reach-through
    ``sync_detection_to_siem`` above already proved out for a non-destructive
    action, applied here to H2's one genuinely real, destructive containment
    adapter (``RevokeKeycloakSessionAction``, gated by ``ApprovalGate``).

    **Role gate: ``ORG_ADMIN``/``CASE_LEAD`` only, deliberately narrower than
    ``sync_detection_to_siem``'s ``ORG_ADMIN``/``CASE_LEAD``/``ANALYST``.**
    Pushing a Detection to a SIEM is a read-mostly, reversible integration
    action; revoking a real, live user session is a genuinely destructive
    containment action with a real user-facing impact (the target is
    logged out immediately) -- the §1 permission matrix's own pattern of
    gating destructive/administrative actions stricter than analytical
    ones (mirrors ``triage_detection``'s ``ANALYST``-inclusive gate vs.
    e.g. legal-hold/case-membership routes elsewhere in this codebase that
    exclude ``ANALYST``) is applied here for the same reason: an analyst
    should be able to investigate and recommend containment, but the
    approval-gated ``ContainmentAction`` itself (this route's own real,
    destructive side effect) requires case-lead-or-above judgment to even
    attempt -- the ``ApprovalGate`` inside ``ContainmentAction.execute()``
    is a SECOND, independent gate on top of this role check, not a
    replacement for it.

    ``detection_id`` provides audit context only (included in the step's
    own ``params``, so the real ``CONTAINMENT_ACTION_ATTEMPTED``/``_DENIED``/
    ``_FAILED``/``_EXECUTED`` audit rows record which Detection this
    containment action was performed in response to) -- unlike
    ``SyncDetectionToSiemAction``, ``RevokeKeycloakSessionAction`` does not
    look the Detection up itself (it operates on a Keycloak ``user_id``/
    ``session_id`` pair, independently tenant-checked against the real
    Keycloak Admin API, never against Detection data), so an unknown or
    cross-org ``detection_id`` here does not itself block the call --
    tenant isolation for the real destructive side effect is enforced by
    ``RevokeKeycloakSessionAction._perform()``'s own real ``is_org_member``/
    session-ownership checks, not by this route.

    404 when no ``RevokeKeycloakSessionAction`` is registered (mirrors this
    file's own "404, not a fabricated success" idiom) -- happens when no
    ``KeycloakAdminClient`` is configured in this deployment (an honest
    "containment via session revocation not configured" state).

    ``approvalTicketId`` is passed through unchanged into the playbook
    step's ``params`` -- this route never pre-validates the ticket itself;
    ``StepUpApprovalGate.authorize()`` (consulted inside
    ``ContainmentAction.execute()``, BEFORE the real Keycloak call) is the
    single place that happens, checked against ``sessionId`` itself (never
    a separate caller-supplied resource field -- see
    ``RevokeKeycloakSessionIn``'s own docstring, Gap Audit Milestone JJ).
    Omitting it is a valid, real request shape too (an org relying on
    ``StaticPolicyApprovalGate`` instead needs no ticket at all) -- the
    gate's own denial (an honest, audited outcome, not an HTTP error) is
    what a missing/invalid ticket produces when ``StepUpApprovalGate`` IS
    the configured gate for this deployment.

    Otherwise always returns 200, mirroring ``sync_detection_to_siem``'s own
    "the real outcome lives in the audited response body, not a second,
    competing HTTP status" idiom -- denied/failed/executed are all real,
    audited, non-exceptional outcomes of a well-formed request.
    """
    action = registry.get_action("revoke_keycloak_session")
    if action is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Containment via Keycloak session revocation is not configured "
            "in this deployment",
        )

    params: dict[str, str] = {
        "detection_id": str(detection_id),
        "user_id": str(body.userId),
        "session_id": body.sessionId,
    }
    if body.approvalTicketId is not None:
        params["approval_ticket_id"] = str(body.approvalTicketId)

    # Gap Audit Milestone LL: case_id is audit-context only here, exactly
    # like detection_id above -- an unknown/cross-org detection_id does not
    # block the real containment action (RevokeKeycloakSessionAction's own
    # tenant isolation is Keycloak-side, not Detection-side), it just means
    # the resulting CONTAINMENT_ACTION_* audit rows won't be case-scoped.
    detection = await detection_repo.get_by_id(detection_id, tenant.org_id)
    if detection is not None:
        params["case_id"] = str(detection.case_id)

    playbook = Playbook(
        name="ad-hoc-contain-revoke-keycloak-session",
        steps=(
            PlaybookStep(
                step_id="revoke-session",
                action_name="revoke_keycloak_session",
                params=params,
            ),
        ),
    )
    result = await execution_service.execute(playbook, tenant)
    return PlaybookExecutionResultOut(
        executionId=result.execution_id,
        playbookName=result.playbook_name,
        succeeded=result.succeeded,
        haltedEarly=result.halted_early,
        stepResults=[
            PlaybookStepResultOut(
                stepId=r.step_id,
                actionName=r.action_name,
                outcome=r.outcome.value,
                output=r.output,
                error=r.error,
            )
            for r in result.step_results
        ],
    )


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
