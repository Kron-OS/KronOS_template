"""SSE endpoints for real-time evidence status updates."""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import AsyncIterator
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from src.adapter.repository.case_repository import CaseRepository
from src.adapter.repository.evidence import EvidenceRepository
from src.domain.user import TenantContext
from src.external.dependencies import (
    get_case_repository,
    get_evidence_repository,
    get_tenant_context,
)
from src.external.middleware.rbac import assert_case_access

router = APIRouter(prefix="/api/sse", tags=["sse"])

# In-memory one-shot ticket store.  In production replace with Redis (TTL 60s).
# Not safe under multiple Uvicorn workers — each process has its own dict.
_tickets: dict[str, dict[str, Any]] = {}

_POLL_INTERVAL_SECONDS = 5
_MAX_STREAM_SECONDS = 300  # 5-minute ceiling per connection
_TERMINAL_STATES = {"COMPLETE", "ERROR"}


class SSETicketIn(BaseModel):
    """Request DTO — field name matches the frontend TypeScript call."""

    caseId: uuid.UUID


class SSETicketResponse(BaseModel):
    """API response DTO — field names match the frontend TypeScript SSETicket interface."""

    ticket: str
    expiresIn: int


@router.post("/ticket", response_model=SSETicketResponse, status_code=status.HTTP_201_CREATED)
async def create_sse_ticket(
    body: SSETicketIn,
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
    case_repo: Annotated[CaseRepository, Depends(get_case_repository)],
) -> SSETicketResponse:
    """Issue a one-shot 60-second SSE ticket scoped to a case.

    Fixed 2026-08-15 (Task #14 security/red-team assessment, P1-SEC-1): this
    previously minted a ticket for ANY caseId the caller supplied, checking
    only that the caller is authenticated within their own org -- never that
    the case belongs to that org or that the caller has real case-level
    access to it (assert_case_access's own docstring: "org_id equality
    alone is not sufficient, that just proves the case belongs to the
    caller's tenant, not that the caller is entitled to see it"). Every
    other case-scoped route (cases.py) already pairs get_by_id(case_id,
    org_id) with assert_case_access -- this route now does too, so a
    legitimate member of Case A can no longer mint a ticket for Case B in
    the same org and receive that case's real-time evidence-state stream.
    """
    case = await case_repo.get_by_id(body.caseId, tenant.org_id)
    if case is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    assert_case_access(tenant, case)

    ticket = str(uuid.uuid4())
    _tickets[ticket] = {
        "case_id": str(body.caseId),
        "org_id": str(tenant.org_id),
        "expires": time.time() + 60,
    }
    return SSETicketResponse(ticket=ticket, expiresIn=60)


@router.get("/cases/{case_id}/evidence")
async def evidence_sse_stream(
    case_id: uuid.UUID,
    ticket: str,
    evidence_repo: Annotated[EvidenceRepository, Depends(get_evidence_repository)],
) -> StreamingResponse:
    """SSE stream that polls evidence state and emits status-change events.

    Consumes the one-shot ticket issued by POST /api/sse/ticket.
    Polls the evidence repository every 5 s and emits a JSON event when any
    evidence item changes state.  Sends keep-alive pings between polls.
    Stream closes after 5 minutes or when all evidence reaches a terminal state.
    """
    ticket_data = _tickets.pop(ticket, None)
    if (
        ticket_data is None
        or ticket_data["case_id"] != str(case_id)
        or time.time() > ticket_data["expires"]
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired SSE ticket",
        )

    org_id = uuid.UUID(ticket_data["org_id"])

    async def event_generator() -> AsyncIterator[str]:
        last_states: dict[str, str] = {}
        deadline = time.time() + _MAX_STREAM_SECONDS
        # Gap Audit Milestone FFFF: real, reproduced race found via a real
        # browser run of evidence-intake-retry-dev-stack.spec.ts, confirmed
        # against real celery-worker/kronos-backend logs and the
        # Playwright trace's own captured network timing. useEvidenceSSE.ts's
        # `kronos:sse-reconnect` (fired the instant a retry-intake/
        # retry-parse mutation's HTTP response lands) opens a BRAND NEW
        # connection -- `last_states` above starts empty every time -- so
        # this loop's first iteration always emits whatever the CURRENT
        # state is, even if that's still the pre-retry ERROR (Celery's own
        # task-dispatch latency means the retried process_intake/
        # parse_artefact_fast task can genuinely not have landed its first
        # state-changing write yet by the time this brand new connection's
        # first poll runs -- observed live: retry-intake POST returned,
        # this connection opened at T+22ms, but the retried Celery task's
        # own "Task received" log landed at T+~0ms to T+~700ms later,
        # i.e. genuinely still racing). Before this fix: the "stop once
        # terminal" check ran on THAT SAME first iteration, saw ERROR
        # (still technically a terminal state), concluded nothing left to
        # watch, sent `done`, and closed -- permanently, since the one-shot
        # ticket is already consumed and `done` (unlike `onerror`) never
        # starts the client's polling fallback. The evidence went on to
        # genuinely reach COMPLETE ~2.4s later (observed live,
        # celery-worker logs), but nothing was left listening. Fix: never
        # conclude "done" on a connection's very first observation --
        # every connection must see a state persist across at least one
        # full _POLL_INTERVAL_SECONDS cycle before it's treated as stably
        # terminal, giving an in-flight retry dispatched moments before
        # this exact connection opened a real chance to be observed.
        first_iteration = True
        try:
            while time.time() < deadline:
                current: dict[str, str] = {}
                async for ev in evidence_repo.stream_by_case(case_id, org_id):
                    current[str(ev.evidence_id)] = ev.state.value

                for ev_id, state in current.items():
                    if last_states.get(ev_id) != state:
                        # camelCase to match the frontend's SSEStatusEvent
                        # interface (same field-naming convention as every
                        # other DTO in this codebase, e.g. EvidenceOut).
                        payload = json.dumps({"evidenceId": ev_id, "state": state})
                        yield f"event: status\ndata: {payload}\n\n"

                last_states = current

                # Stop streaming once all evidence is terminal -- but never
                # on this connection's first-ever observation (see the
                # comment above this loop for the real race this guards).
                if (
                    not first_iteration
                    and current
                    and all(s in _TERMINAL_STATES for s in current.values())
                ):
                    yield "event: done\ndata: {}\n\n"
                    return

                first_iteration = False
                yield "event: ping\ndata: {}\n\n"
                await asyncio.sleep(_POLL_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            pass

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
