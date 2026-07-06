"""Audit log query and attestation endpoints."""

from __future__ import annotations

import uuid
from datetime import date
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from src.adapter.repository.audit_log import AnchorRepository
from src.application.audit_log import AuditLogService
from src.domain.audit import AuditEvent, AuditEventType
from src.domain.merkle import build_merkle_root, leaf_hash
from src.domain.merkle import merkle_proof as compute_merkle_proof
from src.domain.user import TenantContext
from src.exceptions import KronOSException
from src.external.dependencies import get_audit_log_service, get_tenant_context

router = APIRouter(prefix="/api/audit", tags=["audit"])


# ---------------------------------------------------------------------------
# Response DTOs
# ---------------------------------------------------------------------------
#
# The paginated event-listing route lives in routes/cases.py as
# GET /api/cases/{case_id}/audit (matching the frontend's existing call and
# its other per-case list routes); this module keeps the chain-integrity
# endpoints, which the frontend does not yet call.


class MerkleProofStep(BaseModel):
    sibling_hash: str
    position: str  # "left" | "right"


class MerkleProofResponse(BaseModel):
    event_id: uuid.UUID
    day: date
    leaf_hash: str
    proof: list[MerkleProofStep]
    root_hash: str
    anchored: bool


class ChainVerifyResponse(BaseModel):
    valid: bool
    detail: str | None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


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
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        ) from exc
    return ChainVerifyResponse(valid=valid, detail=detail)


@router.get("/merkle-proof/{event_id}", response_model=MerkleProofResponse)
async def merkle_proof(
    event_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
    audit_svc: Annotated[AuditLogService, Depends(get_audit_log_service)],
    day: Annotated[
        date | None,
        Query(description="ISO date to scope the proof to; defaults to the event's own day"),
    ] = None,
) -> MerkleProofResponse:
    """Generate the Merkle inclusion proof for one audit event, scoped to a day.

    Validated against the stored daily anchor (AUDIT-05): a proof computed
    over a day's events is only meaningful if it matches the root the
    platform actually anchored (and TSA-timestamped) for that day.  Returns
    404 if the event or the day's anchor doesn't exist, 409 if the freshly
    computed root doesn't match the stored anchor (tamper signal).
    """
    events: list[AuditEvent] = []
    target: AuditEvent | None = None
    async for ev in audit_svc._repository.stream_by_org(tenant.org_id):
        if ev.event_id == event_id:
            target = ev
        events.append(ev)

    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"Event {event_id} not found"
        )

    scoped_day = day or target.occurred_at.date()
    # AUDIT_MERKLE_ANCHORED events are bookkeeping about the day, not members
    # of it (see AuditLogService.anchor_day's docstring) — excluded so the
    # recomputed root matches what was actually anchored.
    day_events = [
        e
        for e in events
        if e.occurred_at.date() == scoped_day
        and e.event_type != AuditEventType.AUDIT_MERKLE_ANCHORED
    ]
    if target.event_id not in {e.event_id for e in day_events}:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event {event_id} did not occur on {scoped_day.isoformat()}",
        )

    sorted_events = sorted(day_events, key=lambda e: e.sequence_number)
    row_hashes = [e.row_hash or "" for e in sorted_events]
    target_idx = next(i for i, e in enumerate(sorted_events) if e.event_id == event_id)

    root_hash = build_merkle_root(row_hashes)
    proof_steps = compute_merkle_proof(row_hashes, target_idx)

    anchored = False
    if isinstance(audit_svc._repository, AnchorRepository):
        anchor = await audit_svc._repository.get_anchor(scoped_day, org_id=tenant.org_id)
        if anchor is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"{scoped_day.isoformat()} has not been anchored yet",
            )
        anchored_root, _tsa_token = anchor
        if anchored_root != root_hash:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Computed root does not match the anchored root for this day",
            )
        anchored = True

    return MerkleProofResponse(
        event_id=event_id,
        day=scoped_day,
        leaf_hash=leaf_hash(row_hashes[target_idx].encode()).hex(),
        proof=[MerkleProofStep(sibling_hash=h, position=p) for h, p in proof_steps],
        root_hash=root_hash,
        anchored=anchored,
    )
