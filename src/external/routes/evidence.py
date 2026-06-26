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
    filename: str = Field(min_length=1, max_length=1024)
    content_type: str
    size_bytes: int = Field(ge=1)
    case_id: uuid.UUID


class UploadRequestOut(BaseModel):
    evidence_id: uuid.UUID
    presigned_url: str
    object_key: str
    expires_in_seconds: int


class FinalizeUploadIn(BaseModel):
    client_sha256: str = Field(
        min_length=64,
        max_length=64,
        description="Hex-encoded SHA-256 of the uploaded file, computed client-side",
    )


class EvidenceOut(BaseModel):
    evidence_id: uuid.UUID
    state: EvidenceState
    sha256: str | None
    md5: str | None
    original_filename: str
    size_bytes: int
    error_reason: str | None


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
    case = await case_repo.get_by_id(body.case_id, tenant.org_id)
    if case is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found or does not belong to your organisation",
        )

    try:
        evidence, presigned = await intake.request_upload(
            filename=body.filename,
            content_type=body.content_type,
            size_bytes=body.size_bytes,
            case_id=body.case_id,
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
        evidence_id=evidence.evidence_id,
        presigned_url=presigned.url,
        object_key=presigned.object_key,
        expires_in_seconds=presigned.expires_in_seconds,
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

    return _to_evidence_out(evidence)


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

    return _to_evidence_out(evidence)


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
        await intake.delete_evidence(evidence_id=evidence_id, tenant=tenant)
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


def _to_evidence_out(ev: Evidence) -> EvidenceOut:
    return EvidenceOut(
        evidence_id=ev.evidence_id,
        state=ev.state,
        sha256=ev.sha256,
        md5=ev.md5,
        original_filename=ev.metadata.original_filename,
        size_bytes=ev.metadata.size_bytes,
        error_reason=ev.error_reason,
    )
