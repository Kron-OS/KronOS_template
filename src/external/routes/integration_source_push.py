"""Inbound webhook-push route for API-key-authenticated ``IntegrationSource``s
(roadmap Q1).

mTLS-authenticated push sources reuse the existing D2 collector transport
(``src/external/routes/collector_ingest.py`` on the separate dual-listener
app) and never reach this route -- see
``src/external/middleware/integration_source_auth.py``'s own module
docstring for why. This route is the one, real API-key-authenticated
transport, mounted on the main app since it needs no special TLS listener.

Thin DTO/HTTP-status translation only, mirroring ``collector_ingest.py``'s
own scope -- all real logic lives in
``InboundSourceAuthenticator``/``IntegrationSourceIngestService``.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from src.application.integration_source import IntegrationSourceError
from src.application.integration_source_ingest import (
    IntegrationSourceBackpressureError,
    IntegrationSourceIngestService,
)
from src.exceptions import AuthenticationError
from src.external.dependencies import (
    get_inbound_source_authenticator,
    get_integration_source_ingest_service,
)
from src.external.middleware.integration_source_auth import InboundSourceAuthenticator

router = APIRouter(prefix="/api/integrations", tags=["integration-sources"])


class EventOutcomeOut(BaseModel):
    accepted: bool
    duplicate: bool
    messageId: str | None


class PushIngestOut(BaseModel):
    results: list[EventOutcomeOut]


@router.post(
    "/push/{source_type}",
    response_model=PushIngestOut,
    status_code=status.HTTP_202_ACCEPTED,
)
async def push_webhook(
    source_type: str,
    request: Request,
    authenticator: Annotated[InboundSourceAuthenticator, Depends(get_inbound_source_authenticator)],
    service: Annotated[
        IntegrationSourceIngestService, Depends(get_integration_source_ingest_service)
    ],
) -> PushIngestOut:
    """Ingest one webhook-push call from an external tool.

    ``source_type`` in the URL path selects which registered
    ``IntegrationSource`` splits/interprets the raw body -- the identity
    (org/source) authorized to post here comes exclusively from the
    ``authenticator``'s own verified credential (roadmap invariant #3), and
    must match the same ``source_type`` the provisioned key was issued for
    (a key provisioned for one source_type cannot be replayed against a
    different one's route).
    """
    try:
        identity = await authenticator.authenticate(request.headers)
    except AuthenticationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    if identity.source_type != source_type:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Provisioned credential is scoped to source_type={identity.source_type!r}, "
                f"not {source_type!r}"
            ),
        )

    raw_body = await request.body()
    try:
        outcomes = await service.ingest_push(identity, raw_body)
    except IntegrationSourceBackpressureError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc
    except IntegrationSourceError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    return PushIngestOut(
        results=[
            EventOutcomeOut(accepted=o.accepted, duplicate=o.duplicate, messageId=o.message_id)
            for o in outcomes
        ]
    )
