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

from src.adapter.repository.evidence import EvidenceRepository
from src.domain.user import TenantContext
from src.external.dependencies import get_evidence_repository, get_tenant_context

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
) -> SSETicketResponse:
    """Issue a one-shot 60-second SSE ticket scoped to a case."""
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

                # Stop streaming once all evidence is terminal.
                if current and all(s in _TERMINAL_STATES for s in current.values()):
                    yield "event: done\ndata: {}\n\n"
                    return

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
