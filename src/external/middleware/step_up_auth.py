"""Step-up authentication (RFC 9470) for high-sensitivity operations."""

from __future__ import annotations

import logging
import uuid

from fastapi import HTTPException, status

from src.domain.user import TenantContext
from src.external.middleware.step_up_store import (
    ConsumeResult,
    InMemoryTicketStore,
    TicketStore,
)

logger = logging.getLogger(__name__)

_AAL2 = "aal2"

# Maps ACR string values to integer levels for safe numeric comparison.
# Lexicographic comparison ("aal10" < "aal2") would give wrong results.
_ACR_LEVEL: dict[str, int] = {"aal1": 1, "aal2": 2}


def _acr_level(acr: str) -> int:
    """Return the numeric level for an ACR string, defaulting to 0 (least trusted)."""
    return _ACR_LEVEL.get(acr, 0)


class StepUpAuth:
    """Issues and validates one-time step-up tickets for MFA-gated operations.

    A step-up ticket is single-use and expires after 5 minutes.  The caller
    must hold a token with acr=aal2 (MFA) to obtain and use a ticket.

    Ticket persistence is delegated to a :class:`TicketStore`; the default
    in-memory store is process-local, while ``RedisTicketStore`` shares tickets
    across workers and replicas (see ``step_up_store``).

    RFC 9470: insufficient_user_authentication responses carry a
    WWW-Authenticate header that instructs the client to re-authenticate
    at the required ACR level.
    """

    def __init__(self, store: TicketStore | None = None) -> None:
        self._store = store or InMemoryTicketStore()

    def assert_acr(self, tenant: TenantContext, required_acr: str = _AAL2) -> None:
        """Raise HTTP 401 (RFC 9470) if the tenant's ACR does not meet *required_acr*."""
        if _acr_level(tenant.acr) < _acr_level(required_acr):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Step-up authentication required",
                headers={
                    "WWW-Authenticate": (
                        f'Bearer error="insufficient_user_authentication",'
                        f' acr_values="{required_acr}"'
                    )
                },
            )

    def issue_ticket(self, user_id: uuid.UUID, operation: str, resource_id: str) -> uuid.UUID:
        """Create and store a one-time step-up ticket; return its UUID."""
        ticket_id = uuid.uuid4()
        self._store.put(ticket_id, user_id, operation, resource_id)
        logger.info(
            "step_up_ticket_issued",
            extra={"ticket_id": str(ticket_id), "operation": operation},
        )
        return ticket_id

    def consume_ticket(
        self,
        ticket_id: uuid.UUID,
        user_id: uuid.UUID,
        operation: str,
        resource_id: str,
    ) -> None:
        """Validate and permanently invalidate a step-up ticket.

        Raises HTTP 401 if the ticket is missing, already used, expired,
        or does not match the requesting user / operation / resource.
        """
        result = self._store.consume(ticket_id, user_id, operation, resource_id)

        if result is ConsumeResult.MISMATCH:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Step-up ticket does not match the current request",
                headers={"WWW-Authenticate": 'Bearer error="insufficient_user_authentication"'},
            )
        if result is not ConsumeResult.CONSUMED:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Step-up ticket is invalid or already used",
                headers={"WWW-Authenticate": 'Bearer error="insufficient_user_authentication"'},
            )

        logger.info(
            "step_up_ticket_consumed",
            extra={"ticket_id": str(ticket_id), "operation": operation},
        )
