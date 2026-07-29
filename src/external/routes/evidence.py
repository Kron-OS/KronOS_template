"""Evidence upload and parse routes."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from src.adapter.repository.case_repository import CaseRepository
from src.adapter.repository.evidence import EvidenceRepository
from src.application.evidence_intake import EvidenceIntakeService
from src.application.parsing_orchestration import ParsingOrchestrationService
from src.domain.evidence import (
    Evidence,
    EvidenceState,
    is_parse_stage_error_reason,
    is_retryable_error_reason,
)
from src.domain.user import Role, TenantContext
from src.exceptions import (
    AuthorizationError,
    EvidenceStateError,
    KronOSException,
    ParsingError,
    ValidationError,
)
from src.external.dependencies import (
    get_case_repository,
    get_evidence_repository,
    get_intake_service,
    get_parsing_orchestration_service,
    get_step_up_auth,
)
from src.external.middleware.rbac import assert_case_lead_or_admin, requires_role
from src.external.middleware.step_up_auth import StepUpAuth

router = APIRouter(prefix="/api/evidence", tags=["evidence"])


# ---------------------------------------------------------------------------
# Request / Response DTOs
# ---------------------------------------------------------------------------


class UploadRequestIn(BaseModel):
    """Request DTO — field names match the frontend TypeScript upload call."""

    filename: str = Field(min_length=1, max_length=1024)
    contentType: str
    sizeBytes: int = Field(ge=1)
    caseId: uuid.UUID


class UploadRequestOut(BaseModel):
    """Response DTO — field names match the frontend TypeScript UploadRequest interface."""

    evidenceId: uuid.UUID
    presignedUrl: str
    objectKey: str
    expiresInSeconds: int


class FinalizeUploadIn(BaseModel):
    # Sent as client_sha256 (snake_case) by the frontend already — not a DTO
    # naming mismatch, so left as-is.
    client_sha256: str = Field(
        min_length=64,
        max_length=64,
        description="Hex-encoded SHA-256 of the uploaded file, computed client-side",
    )


class EvidenceOut(BaseModel):
    """API response DTO — field names match the frontend TypeScript Evidence interface.

    Shared by both the evidence routes (upload/finalize) and the cases route's
    per-case evidence listing, so the two stay in sync.
    """

    id: uuid.UUID
    caseId: uuid.UUID
    filename: str
    contentType: str
    sizeBytes: int
    sha256: str | None
    md5: str | None
    state: EvidenceState
    errorReason: str | None
    # Which retry endpoint (if any) is worth offering for this ERROR
    # evidence — "intake" -> POST /evidence/{id}/retry-intake (re-enters
    # SCANNING, re-validates/re-scans/re-hashes the quarantined object),
    # "parse" -> POST /evidence/{id}/retry-parse (re-enters PARSING against
    # the already-promoted evidence-bucket object, no re-upload/re-scan).
    # None for terminal reasons (validation_failed/size_limit_exceeded/
    # infected:*/hash_mismatch/no_parser_found) where retrying can never
    # change the verdict — see domain.evidence.is_retryable_error_reason /
    # is_parse_stage_error_reason.
    retryAction: str | None = None
    uploadedBy: str
    uploadedAt: str
    updatedAt: str
    rfc3161Token: str | None = None
    legalHold: bool = False
    objectLockUntil: str | None = None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "/upload/request",
    response_model=UploadRequestOut,
    status_code=status.HTTP_201_CREATED,
)
async def request_upload(
    body: UploadRequestIn,
    tenant: Annotated[
        TenantContext, Depends(requires_role(Role.ORG_ADMIN, Role.CASE_LEAD, Role.ANALYST))
    ],
    intake: Annotated[EvidenceIntakeService, Depends(get_intake_service)],
    case_repo: Annotated[CaseRepository, Depends(get_case_repository)],
) -> UploadRequestOut:
    """Create an Evidence record and return a presigned URL for direct upload.

    AUTH-005: the §1 permission matrix excludes read-only members from
    uploading evidence; this route previously had no role check at all.
    """
    case = await case_repo.get_by_id(body.caseId, tenant.org_id)
    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found or does not belong to your organisation",
        )

    try:
        evidence, presigned = await intake.request_upload(
            filename=body.filename,
            content_type=body.contentType,
            size_bytes=body.sizeBytes,
            case_id=body.caseId,
            tenant=tenant,
        )
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    except KronOSException as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        ) from exc

    return UploadRequestOut(
        evidenceId=evidence.evidence_id,
        presignedUrl=presigned.url,
        objectKey=presigned.object_key,
        expiresInSeconds=presigned.expires_in_seconds,
    )


@router.post(
    "/upload/finalize/{evidence_id}",
    response_model=EvidenceOut,
    status_code=status.HTTP_202_ACCEPTED,
)
async def finalize_upload(
    evidence_id: uuid.UUID,
    body: FinalizeUploadIn,
    tenant: Annotated[
        TenantContext, Depends(requires_role(Role.ORG_ADMIN, Role.CASE_LEAD, Role.ANALYST))
    ],
    intake: Annotated[EvidenceIntakeService, Depends(get_intake_service)],
) -> EvidenceOut:
    """Confirm the upload landed, then hand off validate/scan/hash/promote
    to the autonomous pipeline (kronos.process_intake) — this route no
    longer runs that work itself.

    AUTH-005: same role gate as ``request_upload`` — finalize is the second
    half of the same upload action and must not be reachable by read-only.

    Returns 202 with evidence still in UPLOADING: this is a hand-off, not a
    completion. The frontend already listens to SSE for the RECEIVED/ERROR
    transition that follows; nothing about that contract changes here.

    A 422 here (evidence still in UPLOADING, error unchanged) means the
    object genuinely isn't visible in storage yet — simply calling this
    route again shortly is the correct client response, no separate retry
    endpoint needed for this specific case since no state was ever touched.
    """
    try:
        evidence = await intake.start_intake(
            evidence_id=evidence_id,
            client_sha256=body.client_sha256,
            tenant=tenant,
        )
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    except KronOSException as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        ) from exc

    return to_evidence_out(evidence)


@router.post(
    "/{evidence_id}/retry-intake",
    response_model=EvidenceOut,
    status_code=status.HTTP_202_ACCEPTED,
)
async def retry_intake(
    evidence_id: uuid.UUID,
    tenant: Annotated[
        TenantContext, Depends(requires_role(Role.ORG_ADMIN, Role.CASE_LEAD, Role.ANALYST))
    ],
    intake: Annotated[EvidenceIntakeService, Depends(get_intake_service)],
    evidence_repo: Annotated[EvidenceRepository, Depends(get_evidence_repository)],
) -> EvidenceOut:
    """Re-run intake for ERROR evidence with a retryable reason.

    Only offered for reasons is_retryable_error_reason() considers
    transient (storage/scanner connectivity, an intake that timed out,
    any other unanticipated failure) — terminal reasons (validation_failed,
    size_limit_exceeded, infected:*, hash_mismatch) reflect a real property
    of the uploaded bytes, so retrying the same quarantined object can
    never produce a different verdict; the frontend's Retry button is
    gated on EvidenceOut.isRetryable, and this route re-checks it
    server-side rather than trusting that gating alone.
    """
    evidence = await evidence_repo.get_by_id(evidence_id, tenant.org_id)
    if evidence is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
    if evidence.state != EvidenceState.ERROR:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Evidence is in state {evidence.state.value}, expected ERROR",
        )
    if not is_retryable_error_reason(evidence.error_reason):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Error reason '{evidence.error_reason}' is not retryable — re-upload instead",
        )

    if is_parse_stage_error_reason(evidence.error_reason):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Error reason '{evidence.error_reason}' is a parse-stage error — "
            "use POST /evidence/{id}/retry-parse instead",
        )

    try:
        await intake.retry_intake(evidence_id=evidence_id, tenant=tenant)
    except KronOSException as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        ) from exc

    return to_evidence_out(evidence)


@router.post(
    "/{evidence_id}/retry-parse",
    response_model=EvidenceOut,
    status_code=status.HTTP_202_ACCEPTED,
)
async def retry_parse(
    evidence_id: uuid.UUID,
    tenant: Annotated[
        TenantContext, Depends(requires_role(Role.ORG_ADMIN, Role.CASE_LEAD, Role.ANALYST))
    ],
    orchestrator: Annotated[
        ParsingOrchestrationService, Depends(get_parsing_orchestration_service)
    ],
    evidence_repo: Annotated[EvidenceRepository, Depends(get_evidence_repository)],
) -> EvidenceOut:
    """Re-run parsing/indexing for ERROR evidence with a retryable parse-stage reason.

    Unlike retry-intake, this re-enters PARSING directly against the object
    already promoted to the evidence bucket — intake (validate/scan/hash)
    already succeeded, only parsing or OpenSearch indexing failed
    (parse_failed / ingest_failed / parse_timeout), so no re-upload or
    re-scan is needed. no_parser_found is deliberately excluded — an
    unsupported format can't change on retry (see
    domain.evidence.is_retryable_error_reason).
    """
    evidence = await evidence_repo.get_by_id(evidence_id, tenant.org_id)
    if evidence is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
    if evidence.state != EvidenceState.ERROR:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Evidence is in state {evidence.state.value}, expected ERROR",
        )
    if not is_retryable_error_reason(evidence.error_reason):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Error reason '{evidence.error_reason}' is not retryable — re-upload instead",
        )
    if not is_parse_stage_error_reason(evidence.error_reason):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Error reason '{evidence.error_reason}' is an intake-stage error — "
            "use POST /evidence/{id}/retry-intake instead",
        )

    try:
        evidence = await orchestrator.retry_parse(evidence_id=evidence_id, tenant=tenant)
    except (ValidationError, ParsingError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    except KronOSException as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        ) from exc

    return to_evidence_out(evidence)


@router.post(
    "/parse/start/{evidence_id}",
    response_model=EvidenceOut,
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_parsing(
    evidence_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(requires_role(Role.ORG_ADMIN))],
    orchestrator: Annotated[
        ParsingOrchestrationService, Depends(get_parsing_orchestration_service)
    ],
) -> EvidenceOut:
    """Admin-only: manually re-trigger parsing for RECEIVED evidence.

    Under normal operation the pipeline is fully autonomous — this endpoint
    exists solely for operational recovery when auto-dispatch failed and an
    org-admin needs to unblock stuck evidence.  Requires ORG_ADMIN role.
    """
    try:
        evidence = await orchestrator.start_parsing(evidence_id, tenant)
    except (ValidationError, ParsingError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    except KronOSException as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        ) from exc

    return to_evidence_out(evidence)


@router.delete(
    "/{evidence_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_evidence(
    evidence_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(requires_role(Role.ORG_ADMIN, Role.CASE_LEAD))],
    intake: Annotated[EvidenceIntakeService, Depends(get_intake_service)],
    evidence_repo: Annotated[EvidenceRepository, Depends(get_evidence_repository)],
    case_repo: Annotated[CaseRepository, Depends(get_case_repository)],
    step_up_auth: Annotated[StepUpAuth, Depends(get_step_up_auth)],
    x_step_up_ticket: Annotated[str, Header(description="One-time step-up ticket UUID")] = "",
) -> None:
    """Delete evidence metadata. Requires org-admin, or case-lead of the case, + aal2 step-up.

    AUTH-009: the §1 permission matrix grants delete to case-lead "of case" as
    well as org-admin; this was previously org-admin-only, stricter than the
    documented matrix. ``_assert_case_ownership_for_evidence`` enforces the
    "of the case" qualifier (mirrors ``cases.py``'s ``assert_case_lead_or_admin``).

    The underlying WORM object is retained in MinIO until its retention period
    expires (per regulatory requirements).  Only the platform metadata record
    is removed.

    Clients must first obtain a step-up ticket via ``POST /api/step-up/ticket``
    (requires aal2 JWT) and pass it in the ``X-Step-Up-Ticket`` header.
    """
    await _assert_case_ownership_for_evidence(evidence_id, tenant, evidence_repo, case_repo)
    step_up_auth.assert_acr(tenant)

    try:
        ticket_id = uuid.UUID(x_step_up_ticket)
    except (ValueError, AttributeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid X-Step-Up-Ticket header",
            headers={"WWW-Authenticate": 'Bearer error="insufficient_user_authentication"'},
        ) from exc

    step_up_auth.consume_ticket(
        ticket_id=ticket_id,
        user_id=tenant.user_id,
        operation="evidence.delete",
        resource_id=str(evidence_id),
    )

    try:
        # acr=aal2 asserted above and a one-time step-up ticket was just consumed.
        await intake.delete_evidence(evidence_id=evidence_id, tenant=tenant, step_up_verified=True)
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except EvidenceStateError as exc:
        # Retention period still active — a state conflict, not an auth failure.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except KronOSException as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        ) from exc


class LegalHoldIn(BaseModel):
    """Request body for PUT /evidence/{id}/legal-hold."""

    hold: bool = Field(description="True to set the legal hold, False to clear it")


@router.put(
    "/{evidence_id}/legal-hold",
    response_model=EvidenceOut,
)
async def set_legal_hold(
    evidence_id: uuid.UUID,
    body: LegalHoldIn,
    tenant: Annotated[TenantContext, Depends(requires_role(Role.ORG_ADMIN, Role.CASE_LEAD))],
    intake: Annotated[EvidenceIntakeService, Depends(get_intake_service)],
    evidence_repo: Annotated[EvidenceRepository, Depends(get_evidence_repository)],
    case_repo: Annotated[CaseRepository, Depends(get_case_repository)],
) -> EvidenceOut:
    """Set or clear a legal hold, blocking purge regardless of retention expiry.

    Restricted to org-admin / case-lead **of the case** (Project_Specifications.md
    §2) — ``_assert_case_ownership_for_evidence`` enforces the "of the case"
    qualifier so a case-lead cannot hold/unhold evidence in a case they don't
    lead, consistent with the same rule applied to delete (AUTH-009).
    """
    await _assert_case_ownership_for_evidence(evidence_id, tenant, evidence_repo, case_repo)
    try:
        evidence = await intake.set_legal_hold(
            evidence_id=evidence_id, hold=body.hold, tenant=tenant
        )
    except ValidationError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except AuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except KronOSException as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        ) from exc

    return to_evidence_out(evidence)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


async def _assert_case_ownership_for_evidence(
    evidence_id: uuid.UUID,
    tenant: TenantContext,
    evidence_repo: EvidenceRepository,
    case_repo: CaseRepository,
) -> None:
    """Resolve the case owning ``evidence_id`` and enforce case-lead/admin ownership.

    Evidence-level actions restricted to "org-admin / case-lead of the case"
    (legal hold, delete — AUTH-009) need the owning case, not just the
    evidence's org_id, to enforce the matrix's "(of case)" qualifier the same
    way ``cases.py`` does via ``assert_case_lead_or_admin``.
    """
    if Role.ORG_ADMIN in tenant.roles:
        return
    evidence = await evidence_repo.get_by_id(evidence_id, tenant.org_id)
    if evidence is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence not found")
    case = await case_repo.get_by_id(evidence.metadata.case_id, tenant.org_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    assert_case_lead_or_admin(tenant, case)


def _retry_action_for(ev: Evidence) -> str | None:
    """Which retry endpoint (if any) applies to this evidence's current error."""
    if ev.state != EvidenceState.ERROR or not is_retryable_error_reason(ev.error_reason):
        return None
    return "parse" if is_parse_stage_error_reason(ev.error_reason) else "intake"


def to_evidence_out(ev: Evidence) -> EvidenceOut:
    """Serialize an Evidence domain entity to the shared API DTO.

    Shared with ``cases.py``'s per-case evidence listing so both endpoints
    return an identical shape — the frontend reuses the same evidence object
    from the list view when opening the detail drawer.
    """
    return EvidenceOut(
        id=ev.evidence_id,
        caseId=ev.metadata.case_id,
        filename=ev.metadata.original_filename,
        contentType=ev.metadata.content_type,
        sizeBytes=ev.metadata.size_bytes,
        sha256=ev.sha256,
        md5=ev.md5,
        state=ev.state,
        errorReason=ev.error_reason,
        retryAction=_retry_action_for(ev),
        uploadedBy=str(ev.metadata.uploader_user_id),
        uploadedAt=ev.created_at.isoformat(),
        updatedAt=ev.updated_at.isoformat(),
        # None renders as "Not anchored yet" in the detail drawer until the
        # evidence.hash.verified transition anchors a real TSA token.
        rfc3161Token=ev.rfc3161_token.hex() if ev.rfc3161_token else None,
        legalHold=ev.legal_hold,
        objectLockUntil=ev.object_lock_until.isoformat() if ev.object_lock_until else None,
    )
