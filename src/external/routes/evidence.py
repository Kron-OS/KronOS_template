"""Evidence upload and parse routes."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field

from src.adapter.repository.case_repository import CaseRepository
from src.application.evidence_intake import EvidenceIntakeService
from src.application.parsing_orchestration import ParsingOrchestrationService
from src.domain.evidence import Evidence, EvidenceState
from src.domain.user import Role, TenantContext
from src.exceptions import AuthorizationError, KronOSException, ParsingError, ValidationError
from src.external.dependencies import (
    get_case_repository,
    get_intake_service,
    get_parsing_orchestration_service,
    get_step_up_auth,
    get_tenant_context,
)
from src.external.middleware.rbac import requires_role
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
    uploadedBy: str
    uploadedAt: str
    updatedAt: str
    rfc3161Token: str | None = None


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
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
    intake: Annotated[EvidenceIntakeService, Depends(get_intake_service)],
    case_repo: Annotated[CaseRepository, Depends(get_case_repository)],
) -> UploadRequestOut:
    """Create an Evidence record and return a presigned URL for direct upload."""
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
)
async def finalize_upload(
    evidence_id: uuid.UUID,
    body: FinalizeUploadIn,
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
    intake: Annotated[EvidenceIntakeService, Depends(get_intake_service)],
) -> EvidenceOut:
    """Validate, scan, hash, and promote the uploaded file to RECEIVED state."""
    try:
        evidence = await intake.finalize_upload(
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
    "/parse/start/{evidence_id}",
    response_model=EvidenceOut,
    status_code=status.HTTP_202_ACCEPTED,
)
async def start_parsing(
    evidence_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
    orchestrator: Annotated[
        ParsingOrchestrationService, Depends(get_parsing_orchestration_service)
    ],
) -> EvidenceOut:
    """Transition RECEIVED evidence to PARSING and enqueue the parse task."""
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
    tenant: Annotated[TenantContext, Depends(requires_role(Role.ORG_ADMIN))],
    intake: Annotated[EvidenceIntakeService, Depends(get_intake_service)],
    step_up_auth: Annotated[StepUpAuth, Depends(get_step_up_auth)],
    x_step_up_ticket: Annotated[str, Header(description="One-time step-up ticket UUID")] = "",
) -> None:
    """Delete evidence metadata. Requires org-admin role + aal2 step-up ticket.

    The underlying WORM object is retained in MinIO until its retention period
    expires (per regulatory requirements).  Only the platform metadata record
    is removed.

    Clients must first obtain a step-up ticket via ``POST /api/step-up/ticket``
    (requires aal2 JWT) and pass it in the ``X-Step-Up-Ticket`` header.
    """
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
    except KronOSException as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        ) from exc


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


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
        uploadedBy=str(ev.metadata.uploader_user_id),
        uploadedAt=ev.created_at.isoformat(),
        updatedAt=ev.updated_at.isoformat(),
        # RFC 3161 timestamping is not yet wired into evidence intake;
        # None renders as "Not anchored yet" in the detail drawer.
        rfc3161Token=None,
    )
