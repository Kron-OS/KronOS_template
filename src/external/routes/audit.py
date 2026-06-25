"""Audit log query and attestation endpoints."""

from __future__ import annotations

import hashlib
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from src.application.audit_log import AuditLogService, build_merkle_root
from src.domain.audit import AuditEvent
from src.domain.user import TenantContext
from src.exceptions import KronOSException
from src.external.dependencies import get_audit_log_service, get_tenant_context

router = APIRouter(prefix="/api/audit", tags=["audit"])


# ---------------------------------------------------------------------------
# Response DTOs
# ---------------------------------------------------------------------------


class AuditEventOut(BaseModel):
    event_id: uuid.UUID
    event_type: str
    actor_username: str | None
    case_id: uuid.UUID | None
    evidence_id: uuid.UUID | None
    occurred_at: str
    details: dict
    row_hash: str | None
    sequence_number: int


class PaginatedAuditLog(BaseModel):
    items: list[AuditEventOut]
    total: int
    page: int
    page_size: int


class MerkleProofStep(BaseModel):
    sibling_hash: str
    position: str  # "left" | "right"


class MerkleProofResponse(BaseModel):
    event_id: uuid.UUID
    leaf_hash: str
    proof: list[MerkleProofStep]
    root_hash: str


class ChainVerifyResponse(BaseModel):
    valid: bool
    detail: str | None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/cases/{case_id}", response_model=PaginatedAuditLog)
async def list_audit_events(
    case_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
    audit_svc: Annotated[AuditLogService, Depends(get_audit_log_service)],
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
) -> PaginatedAuditLog:
    """Return paginated audit events for a case (tenant-scoped)."""
    events: list[AuditEvent] = []
    async for ev in audit_svc._repository.stream_by_case(case_id):
        if ev.org_id != tenant.org_id:
            continue
        events.append(ev)

    total = len(events)
    start = (page - 1) * page_size
    page_events = events[start : start + page_size]

    return PaginatedAuditLog(
        items=[_to_out(e) for e in page_events],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/cases/{case_id}/verify", response_model=ChainVerifyResponse)
async def verify_chain(
    case_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
    audit_svc: Annotated[AuditLogService, Depends(get_audit_log_service)],
) -> ChainVerifyResponse:
    """Verify the hash chain integrity for an org's audit log."""
    try:
        valid, detail = await audit_svc.verify_chain(tenant.org_id)
    except KronOSException as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc
    return ChainVerifyResponse(valid=valid, detail=detail)


@router.get("/merkle-proof/{event_id}", response_model=MerkleProofResponse)
async def merkle_proof(
    event_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
    audit_svc: Annotated[AuditLogService, Depends(get_audit_log_service)],
) -> MerkleProofResponse:
    """Generate the Merkle inclusion proof for a single audit event.

    The caller can reconstruct the root hash by iterating the proof steps.
    """
    events: list[AuditEvent] = []
    target: AuditEvent | None = None
    async for ev in audit_svc._repository.stream_by_case(tenant.org_id):
        if ev.org_id != tenant.org_id:
            continue
        events.append(ev)
        if ev.event_id == event_id:
            target = ev

    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Event {event_id} not found")

    sorted_events = sorted(events, key=lambda e: e.sequence_number)
    leaves: list[bytes] = [hashlib.sha256((e.row_hash or "").encode()).digest() for e in sorted_events]
    target_idx = next(i for i, e in enumerate(sorted_events) if e.event_id == event_id)
    leaf_hash = leaves[target_idx].hex()

    proof = _build_proof(leaves, target_idx)
    root_hash = build_merkle_root(sorted_events)

    return MerkleProofResponse(
        event_id=event_id,
        leaf_hash=leaf_hash,
        proof=proof,
        root_hash=root_hash,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_proof(leaves: list[bytes], target_idx: int) -> list[MerkleProofStep]:
    """Generate sibling hashes from leaf to root."""
    steps: list[MerkleProofStep] = []
    layer = list(leaves)
    idx = target_idx

    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])  # duplicate last for odd count

        sibling_idx = idx ^ 1  # XOR flips LSB: left↔right sibling
        position = "right" if idx % 2 == 0 else "left"
        steps.append(MerkleProofStep(sibling_hash=layer[sibling_idx].hex(), position=position))

        next_layer: list[bytes] = []
        for i in range(0, len(layer), 2):
            combined = hashlib.sha256(layer[i] + layer[i + 1]).digest()
            next_layer.append(combined)
        layer = next_layer
        idx //= 2

    return steps


def _to_out(ev: AuditEvent) -> AuditEventOut:
    return AuditEventOut(
        event_id=ev.event_id,
        event_type=ev.event_type.value,
        actor_username=ev.actor_username,
        case_id=ev.case_id,
        evidence_id=ev.evidence_id,
        occurred_at=ev.occurred_at.isoformat(),
        details=ev.details,
        row_hash=ev.row_hash,
        sequence_number=ev.sequence_number,
    )
