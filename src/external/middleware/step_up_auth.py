"""Step-up authentication (RFC 9470) for high-sensitivity operations."""

from __future__ import annotations

import logging
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from fastapi import HTTPException, status

from src.domain.user import TenantContext

logger = logging.getLogger(__name__)

_AAL2 = "aal2"
_TICKET_TTL_SECONDS = 300  # 5 minutes


@dataclass
class _Ticket:
    ticket_id: uuid.UUID
    user_id: uuid.UUID
    operation: str
    resource_id: str
    issued_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    used: bool = False


class StepUpAuth:
    """Issues and validates one-time step-up tickets for MFA-gated operations.

    A step-up ticket is single-use and expires after 5 minutes.  The caller
    must hold a token with acr=aal2 (MFA) to obtain and use a ticket.

    RFC 9470: insufficient_user_authentication responses carry a
    WWW-Authenticate header that instructs the client to re-authenticate
    at the required ACR level.
    """

    def __init__(self) -> None:
        self._tickets: dict[uuid.UUID, _Ticket] = {}
        self._lock = threading.Lock()

    def assert_acr(self, tenant: TenantContext, required_acr: str = _AAL2) -> None:
        """Raise HTTP 401 (RFC 9470) if the tenant's ACR does not meet *required_acr*."""
        if tenant.acr < required_acr:
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

    def issue_ticket(
        self, user_id: uuid.UUID, operation: str, resource_id: str
    ) -> uuid.UUID:
        """Create and store a one-time step-up ticket; return its UUID."""
        ticket_id = uuid.uuid4()
        with self._lock:
            self._purge_expired()
            self._tickets[ticket_id] = _Ticket(
                ticket_id=ticket_id,
                user_id=user_id,
                operation=operation,
                resource_id=resource_id,
            )
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
        with self._lock:
            self._purge_expired()
            ticket = self._tickets.get(ticket_id)

            if ticket is None or ticket.used:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Step-up ticket is invalid or already used",
                    headers={
                        "WWW-Authenticate": 'Bearer error="insufficient_user_authentication"'
                    },
                )

            if (
                ticket.user_id != user_id
                or ticket.operation != operation
                or ticket.resource_id != resource_id
            ):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Step-up ticket does not match the current request",
                    headers={
                        "WWW-Authenticate": 'Bearer error="insufficient_user_authentication"'
                    },
                )

            ticket.used = True

        logger.info(
            "step_up_ticket_consumed",
            extra={"ticket_id": str(ticket_id), "operation": operation},
        )

    def _purge_expired(self) -> None:
        now = datetime.now(UTC)
        expired = [
            tid
            for tid, t in self._tickets.items()
            if (now - t.issued_at).total_seconds() > _TICKET_TTL_SECONDS
        ]
        for tid in expired:
            del self._tickets[tid]
