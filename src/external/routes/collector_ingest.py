"""Collector-facing telemetry ingest route (roadmap M3/D2).

``identity`` is the ONLY source of ``org_id``/``source_id`` for every event
in the batch -- the request body's own per-event fields, if any, are never
read for tenant scoping (see ``CollectorIdentity``'s docstring for the
invariant this upholds). This route is a thin DTO/HTTP-status translation
layer only; all real logic lives in ``CollectorIngestService``.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from src.application.collector_ingest import BackpressureError, CollectorIngestService
from src.domain.collector import CollectorIdentity
from src.external.dependencies import get_collector_ingest_service
from src.external.middleware.collector_mtls import get_collector_identity

router = APIRouter(prefix="/api/collector", tags=["collector"])


class IngestEventsIn(BaseModel):
    events: list[dict[str, Any]] = Field(min_length=1, max_length=1000)


class EventOutcomeOut(BaseModel):
    accepted: bool
    duplicate: bool
    messageId: str | None


class IngestEventsOut(BaseModel):
    results: list[EventOutcomeOut]


@router.post("/ingest", response_model=IngestEventsOut, status_code=status.HTTP_202_ACCEPTED)
async def ingest_events(
    body: IngestEventsIn,
    identity: Annotated[CollectorIdentity, Depends(get_collector_identity)],
    service: Annotated[CollectorIngestService, Depends(get_collector_ingest_service)],
) -> IngestEventsOut:
    """Ingest a batch of events onto the caller's own (org_id, source_id) stream.

    ``identity`` comes exclusively from the verified mTLS client certificate
    (roadmap invariant #3) -- a collector cannot influence which org/source
    its events land under via anything in *body*.
    """
    try:
        outcomes = await service.ingest_events(identity, body.events)
    except BackpressureError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)
        ) from exc

    return IngestEventsOut(
        results=[
            EventOutcomeOut(accepted=o.accepted, duplicate=o.duplicate, messageId=o.message_id)
            for o in outcomes
        ]
    )
