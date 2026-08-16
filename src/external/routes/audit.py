"""Audit log query and attestation endpoints."""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, date, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from src.adapter.repository.audit_log import AnchorRepository
from src.application.audit_log import AuditLogService
from src.domain.audit import AuditEvent, AuditEventType
from src.domain.merkle import build_merkle_root, leaf_hash
from src.domain.merkle import merkle_proof as compute_merkle_proof
from src.domain.user import Role, TenantContext
from src.exceptions import KronOSException
from src.external.dependencies import get_audit_log_service, get_tenant_context
from src.external.middleware.rbac import requires_role

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


# ---------------------------------------------------------------------------
# Full-org audit log export (feeds the offline `kronos-attest` CLI)
# ---------------------------------------------------------------------------


def _to_export_dict(ev: AuditEvent) -> dict[str, Any]:
    """Shape one AuditEvent exactly as kronos_attest.verifier expects.

    This is the *proven-correct* field mapping already exercised end-to-end
    against the real ``kronos-attest`` CLI in
    ``poc/chain_of_custody/run_poc.py``'s ``_to_json()`` helper (str(uuid),
    ``event_type.value``, ISO ``occurred_at``, etc.) — reused verbatim
    rather than re-derived, since ``kronos_attest/verifier.py::_canonical_json()``
    reads these exact keys to recompute row hashes and any drift here would
    silently break chain verification for every export.
    """
    return {
        "event_id": str(ev.event_id),
        "event_type": ev.event_type.value,
        "actor_user_id": str(ev.actor_user_id) if ev.actor_user_id else None,
        "actor_username": ev.actor_username,
        "org_id": str(ev.org_id) if ev.org_id else None,
        "case_id": str(ev.case_id) if ev.case_id else None,
        "evidence_id": str(ev.evidence_id) if ev.evidence_id else None,
        "details": ev.details,
        "occurred_at": ev.occurred_at.isoformat(),
        "sequence_number": ev.sequence_number,
        "prev_row_hash": ev.prev_row_hash,
        "row_hash": ev.row_hash,
    }


async def _export_event_stream(audit_svc: AuditLogService, org_id: uuid.UUID) -> AsyncIterator[str]:
    """Yield a JSON array of the org's full audit chain, one event at a time.

    Builds the array incrementally (``[``, each event's JSON separated by
    ``,``, then ``]``) instead of ``json.dumps()`` of a fully-materialized
    list, per CLAUDE.md SS A.5 ("no loading entire audit log into memory —
    paginate, stream, lazy-load"). ``stream_by_org`` is already an
    ``AsyncIterator[AuditEvent]`` (src/adapter/repository/audit_log.py), so
    this never holds more than one event in memory at a time.
    """
    yield "["
    first = True
    async for ev in audit_svc._repository.stream_by_org(org_id):
        if not first:
            yield ","
        first = False
        yield json.dumps(_to_export_dict(ev))
    yield "]"


@router.get("/export")
async def export_org_audit_log(
    tenant: Annotated[TenantContext, Depends(requires_role(Role.ORG_ADMIN))],
    audit_svc: Annotated[AuditLogService, Depends(get_audit_log_service)],
) -> StreamingResponse:
    """Stream the caller's ENTIRE org audit log as a JSON array export.

    This is the route that produces the file ``kronos-attest case-report``/
    ``day-report`` (the standalone offline CLI in ``kronos_attest/``)
    consumes. It is deliberately a full-org export — never case- or
    day-scoped server-side — even though most callers only *want* one
    case's or one day's trail:

    ``kronos_attest.report.AttestationReport.case_report()``/``day_report()``
    do their own client-side filtering (``case_id``/``day`` match) over
    whatever full event list they are handed, and then run
    ``ChainVerifier.verify()`` over the FILTERED result.
    ``ChainVerifier.verify()`` (kronos_attest/verifier.py) recomputes each
    event's row hash by chaining against the *previous event in the list it
    was given*, starting from a fixed genesis hash — it has no way to know
    what the *real* previous event in the org's chain was if that event was
    excluded before this route ever served the response. If this endpoint
    pre-filtered to one case, the served events' real ``prev_row_hash``
    values would point at whatever org-wide event immediately preceded them
    in Postgres — almost certainly a *different* case's event once an org
    has more than one case — and re-chaining over just the filtered subset
    would spuriously report ``chain_valid: false`` for any multi-case org,
    even though nothing was actually tampered with.

    The correct approach (proven end-to-end against the real CLI in
    ``poc/chain_of_custody/run_poc.py``, which exports
    ``repo.stream_by_org(org_id)`` in full) is to always serve the complete,
    unfiltered per-org chain and let ``kronos-attest``'s own
    ``--case-id``/``--day`` flags do the filtering client-side, after the
    full chain has already been hash-verified. Do NOT turn this into a
    case-scoped or day-scoped export server-side — that would reintroduce
    exactly this bug.

    Role gate: ``ORG_ADMIN`` only. There is no exact row for "export audit
    log" in the permission matrix (Project_Specifications.md /
    docs/access-management-review.md); this is a real judgment call, not a
    discovered fact — it defaults to ``ORG_ADMIN`` because a full-org export
    dumps every case's and every evidence item's audit trail in one
    document, the same sensitivity tier as
    ``POST /api/evidence/parse/start/{id}`` (also ``ORG_ADMIN``-only per
    CLAUDE.md SS E.6), the closest existing precedent for a whole-org,
    operationally sensitive action.

    Always scoped from the authenticated ``tenant.org_id`` — never a
    client-supplied org, matching every other route in this module.
    """
    export_date = datetime.now(UTC).date().isoformat()
    filename = f"kronos-audit-export-{tenant.org_alias}-{export_date}.json"
    return StreamingResponse(
        _export_event_stream(audit_svc, tenant.org_id),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
