"""Step-up ticket issuance route (RFC 9470).

Verified missing via poc/auth_flow/: DELETE /api/evidence/{id} requires a
one-time X-Step-Up-Ticket (see StepUpAuth.consume_ticket in
src/external/middleware/step_up_auth.py), and that ticket is minted by
StepUpAuth.issue_ticket() -- but nothing in the codebase ever called
issue_ticket() from an HTTP route, and no router for it was registered in
fastapi_app.py. The evidence-delete docstring documents
"POST /api/step-up/ticket" as the client contract, but it never existed,
so there was no legitimate way to ever obtain a ticket -- evidence deletion
was unreachable via the real API.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from src.domain.user import TenantContext
from src.external.dependencies import get_step_up_auth, get_tenant_context
from src.external.middleware.step_up_auth import StepUpAuth

router = APIRouter(prefix="/api/step-up", tags=["step-up"])


class StepUpTicketIn(BaseModel):
    operation: str = Field(min_length=1, max_length=128, description='e.g. "evidence.delete"')
    resource_id: str = Field(min_length=1, max_length=128, description="ID the ticket is scoped to")


class StepUpTicketOut(BaseModel):
    ticketId: str


@router.post("/ticket", response_model=StepUpTicketOut, status_code=201)
async def issue_step_up_ticket(
    body: StepUpTicketIn,
    tenant: Annotated[TenantContext, Depends(get_tenant_context)],
    step_up_auth: Annotated[StepUpAuth, Depends(get_step_up_auth)],
) -> StepUpTicketOut:
    """Mint a one-time step-up ticket for a specific operation + resource.

    Requires the caller's JWT to already satisfy acr=aal2 (RFC 9470) --
    ``assert_acr`` raises 401 with the standard step-up challenge otherwise,
    same as every other aal2-gated route in this codebase. The ticket is
    single-use and scoped to (user, operation, resource_id); see
    ``StepUpAuth.consume_ticket`` for how a caller like
    ``DELETE /api/evidence/{id}`` redeems it.
    """
    step_up_auth.assert_acr(tenant)
    ticket_id = step_up_auth.issue_ticket(
        user_id=tenant.user_id,
        operation=body.operation,
        resource_id=body.resource_id,
    )
    return StepUpTicketOut(ticketId=str(ticket_id))
