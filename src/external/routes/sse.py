"""SSE endpoints for real-time evidence status updates."""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from src.domain.user import TenantContext
from src.external.dependencies import get_tenant_context

router = APIRouter(prefix="/api/sse", tags=["sse"])

# In-memory one-shot ticket store.  In production replace with Redis (TTL 60s).
_tickets: dict[str, dict] = {}


class SSETicketResponse(BaseModel):
    ticket: str
    expires_in: int


@router.post("/ticket", response_model=SSETicketResponse, status_code=status.HTTP_201_CREATED)
async def create_sse_ticket(
    case_id: uuid.UUID,
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
) -> SSETicketResponse:
    """Issue a one-shot 60-second SSE ticket scoped to a case."""
    ticket = str(uuid.uuid4())
    _tickets[ticket] = {
        "case_id": str(case_id),
        "org_id": str(tenant.org_id),
        "expires": time.time() + 60,
    }
    return SSETicketResponse(ticket=ticket, expires_in=60)


@router.get("/cases/{case_id}/evidence")
async def evidence_sse_stream(
    case_id: uuid.UUID,
    ticket: str,
) -> StreamingResponse:
    """SSE stream for evidence status updates.

    Consumes the one-shot ticket issued by POST /api/sse/ticket.
    Sends keep-alive pings every 15 s; status events are pushed by the
    Celery task layer (not yet wired in this stub).
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

    async def event_generator():  # type: ignore[return]
        try:
            for _ in range(4):  # max 60 s (4 × 15 s)
                yield "event: ping\ndata: {}\n\n"
                await asyncio.sleep(15)
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
