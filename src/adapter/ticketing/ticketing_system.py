"""TicketingSystem: real outbound calls to an external ITSM/ticketing
system (roadmap M7/H4 -- "Case / ticket integration").

**Judgment call, read before extending (mirrors H2/H3's own honesty
precedent).** No real external ITSM product (Jira, ServiceNow, PagerDuty,
...) is deployed anywhere in this dev stack, and reaching a live
third-party SaaS ticketing API is explicitly out of scope for an unattended
pass (roadmap H4's own scope note). A generic outbound-webhook shape (one
HTTP POST, a real JSON payload, a real response code/body checked) is the
most defensible real target absent a specific named vendor -- it is exactly
the integration shape every major ITSM product's own "generic
webhook"/"inbound integration" feature already exposes (Jira Automation
webhooks, ServiceNow Inbound REST, PagerDuty Events API v2 all reduce to
"POST JSON, read back an id"), so this is not a fabricated stand-in
shape, it is the real lowest common denominator of that class of
integration. ``WebhookTicketingSystem`` below is verified in
``poc/detection_ticket_integration/`` against a REAL local HTTP receiver
the PoC itself stands up on ``127.0.0.1`` -- real bytes over a real
socket, real status codes inspected -- never a live vendor account.

Small, typed ABC (mirrors ``EvidenceStorage``/``KeycloakAdminClient``'s own
"one small interface, not a raw HTTP passthrough" idiom): exactly the two
operations this platform needs (create, update), never a generic
``send(method, path, body)`` escape hatch that would just move the vendor
coupling into every caller instead of behind one adapter.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

import httpx

from src.exceptions import TicketingError


@dataclass(frozen=True)
class TicketRef:
    """The real external system's own identifier for a ticket, plus an
    optional human-facing URL -- the only two facts KronOS ever trusts back
    from a ticketing system response (roadmap invariant #5: this is a
    traceability pointer, never authoritative state)."""

    ticket_id: str
    url: str | None = None


class TicketingSystem(ABC):
    """Real outbound operations against an external ticketing/ITSM system.

    New operations = new abstract methods here, not a generic passthrough
    (mirrors ``KeycloakAdminClient``'s own docstring reasoning) -- keeps
    every caller's real backend calls typed and centrally mockable in unit
    tests, per CLAUDE.md SS B.5.
    """

    @abstractmethod
    async def create_ticket(
        self, *, title: str, description: str, severity: str | None, metadata: dict[str, Any]
    ) -> TicketRef:
        """Create a new real ticket. Raises ``TicketingError`` if the real
        backend is unreachable or rejects the call -- never returns a
        fabricated ``TicketRef`` (CLAUDE.md SS1#8)."""

    @abstractmethod
    async def update_ticket(
        self, ticket_id: str, *, note: str, metadata: dict[str, Any]
    ) -> TicketRef:
        """Append *note* to the real, already-existing ticket *ticket_id*.
        Raises ``TicketingError`` on the same terms as ``create_ticket``."""


class WebhookTicketingSystem(TicketingSystem):
    """Generic outbound-webhook implementation: one HTTP POST per call, a
    real JSON envelope, the real response's ``ticket_id``/``url`` fields
    trusted back (nothing else). Verified against a real local receiver --
    see ``poc/detection_ticket_integration/``.

    The envelope shape (``event``, ``title``/``description``/``severity``
    or ``ticket_id``/``note``, plus a caller-supplied ``metadata`` dict) is
    deliberately generic-webhook-shaped, not modeled on any single named
    vendor's SDK -- see this module's own docstring for why that is the
    correct, honest choice for this pass.
    """

    def __init__(
        self, webhook_url: str, *, verify: bool | str = True, timeout: float = 15.0
    ) -> None:
        self._webhook_url = webhook_url
        self._verify = verify
        self._timeout = timeout

    async def create_ticket(
        self, *, title: str, description: str, severity: str | None, metadata: dict[str, Any]
    ) -> TicketRef:
        body = {
            "event": "kronos.ticket.create",
            "title": title,
            "description": description,
            "severity": severity,
            "metadata": metadata,
        }
        return await self._post(body)

    async def update_ticket(
        self, ticket_id: str, *, note: str, metadata: dict[str, Any]
    ) -> TicketRef:
        body = {
            "event": "kronos.ticket.update",
            "ticket_id": ticket_id,
            "note": note,
            "metadata": metadata,
        }
        return await self._post(body)

    async def _post(self, body: dict[str, Any]) -> TicketRef:
        try:
            async with httpx.AsyncClient(timeout=self._timeout, verify=self._verify) as client:
                response = await client.post(self._webhook_url, json=body)
        except httpx.HTTPError as exc:
            raise TicketingError(
                "Real webhook POST to ticketing backend failed to complete",
                context={
                    "webhook_url": self._webhook_url,
                    "event": body["event"],
                    "error": str(exc),
                },
            ) from exc

        if response.status_code not in (200, 201):
            raise TicketingError(
                "Ticketing backend rejected the real webhook call",
                context={
                    "webhook_url": self._webhook_url,
                    "event": body["event"],
                    "status_code": response.status_code,
                    "body": response.text[:500],
                },
            )

        try:
            payload = response.json()
            ticket_id = payload["ticket_id"]
        except (ValueError, KeyError, TypeError) as exc:
            raise TicketingError(
                "Ticketing backend returned a 2xx response with no usable ticket_id -- "
                "never fabricating one",
                context={
                    "webhook_url": self._webhook_url,
                    "event": body["event"],
                    "body": response.text[:500],
                    "error": str(exc),
                },
            ) from exc
        if not isinstance(ticket_id, str) or not ticket_id:
            raise TicketingError(
                "Ticketing backend returned a non-string/empty ticket_id",
                context={"webhook_url": self._webhook_url, "body": response.text[:500]},
            )
        return TicketRef(ticket_id=ticket_id, url=payload.get("url"))
