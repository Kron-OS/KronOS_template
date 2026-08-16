"""Admin connector status route (Milestone W14, docs/ASSESSMENT_SYNTHESIS_2026-08.md
P2-W14, from docs/assessments/ux_onboarding_review.md SS1).

Closes a real, previously-confirmed UX gap: six EDR/SIEM connectors exist
(Wazuh/Suricata-Zeek/Defender as PUSH/POLL *sources*, Splunk/CEF/Sentinel as
sinks) but no admin-visible surface shows whether any of them are configured
or healthy for a given org. This route is read-only status, not
configuration -- it never mutates anything, so (like
``GET /api/admin/integration-sources`` in ``admin_integration_sources.py``)
it is ``ORG_ADMIN``-gated only, no step-up bar (step-up is reserved for
credential issuance/revocation, not for reading).

**The asymmetry this route must honestly reflect, not paper over** (design
decision fixed before this route was written, see the dispatching task):

- PUSH-mode sources (Wazuh, Suricata/Zeek generic webhooks, ...) are real,
  per-org self-service today: ``IntegrationSourceKeyRepository.list_by_org``
  (Milestone W8) returns every key ever provisioned for the caller's own
  org, org-admin-manageable via ``admin_integration_sources.py``'s own
  provision/revoke routes.
- The one real POLL-mode source, Microsoft Defender
  (``DefenderPollSource``, ``src/external/integration_sources/defender.py``),
  is NOT per-org self-service -- it is wired from a single GLOBAL
  ``Settings.defender_poll_org_id`` (``src/config.py``), set once at
  deployment time, not from any per-org table or admin route. This route
  includes a Defender entry IF AND ONLY IF the caller's own ``tenant.org_id``
  matches that global setting, and labels it accordingly ("configured for
  this org via platform settings", never implying the caller could change
  it from here). ``GenericPollSource`` (the other POLL implementation) has
  no config wiring anywhere and was closed as not-warranted in the same
  synthesis pass (P2-W17) -- deliberately absent from this route, not an
  oversight.

Recency signals are derived from the audit log, reusing
``routes/audit.py``'s own ``merkle_proof`` idiom of streaming
``audit_svc._repository.stream_by_org(tenant.org_id)`` once and filtering in
Python by ``event_type``/``details`` (rather than adding a new repository
query method) -- the established pattern for "read the whole org log,
filter for one query" in this codebase; a single stream pass here computes
every source's recency signal in one org-scoped read, so there is no
per-source N+1 fan-out.

Mirrors ``admin_integration_sources.py``'s own conventions: camelCase DTOs
(this repo's own route convention, see ``pyproject.toml``'s ``N815``
per-file-ignore for this module), org-scoping exclusively from
``tenant.org_id`` (never client-supplied).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from src.adapter.repository.integration_source_key import IntegrationSourceKeyRepository
from src.application.audit_log import AuditLogService
from src.domain.audit import AuditEvent, AuditEventType
from src.domain.user import Role, TenantContext
from src.external.dependencies import (
    get_audit_log_service,
    get_defender_poll_org_id,
    get_defender_poll_source_id,
    get_integration_source_key_repository,
)
from src.external.middleware.rbac import requires_role

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/admin/connectors", tags=["admin"])

# Must match DefenderPollSource.source_type
# (src/external/integration_sources/defender.py) exactly -- duplicated as a
# constant here rather than imported so this read-only status route never
# needs to construct an httpx.AsyncClient/OAuth2 strategy just to read one
# string property off a class that otherwise requires real credentials to
# instantiate.
_DEFENDER_SOURCE_TYPE = "ms-defender-alerts"

_PUSH_NOTE = "Self-service: this org provisioned this connector's API key directly."
_POLL_NOTE = (
    "Configured for this org via platform settings — not self-service; "
    "contact your KronOS operator to change it."
)

_ConnectorStatusState = Literal["never_used", "active", "failing", "revoked"]


# ---------------------------------------------------------------------------
# DTOs
# ---------------------------------------------------------------------------


class ConnectorStatusOut(BaseModel):
    """One connector's real, observed status -- never a fabricated/optimistic
    default. See this module's own docstring for the push/poll asymmetry
    ``selfService`` and ``note`` exist to make honest in the UI."""

    sourceId: str
    sourceType: str
    mode: Literal["push", "poll"]
    selfService: bool
    status: _ConnectorStatusState
    createdAt: str | None
    revokedAt: str | None
    lastIngestedAt: str | None
    lastPolledAt: str | None
    lastPollFailedAt: str | None
    lastFailureReason: str | None
    note: str


class ConnectorStatusListOut(BaseModel):
    items: list[ConnectorStatusOut]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _push_status(
    *, revoked_at: datetime | None, last_ingested_at: datetime | None
) -> _ConnectorStatusState:
    if revoked_at is not None:
        return "revoked"
    if last_ingested_at is not None:
        return "active"
    return "never_used"


def _poll_status(
    *, last_polled_at: datetime | None, last_poll_failed_at: datetime | None
) -> _ConnectorStatusState:
    if last_poll_failed_at is not None and (
        last_polled_at is None or last_poll_failed_at > last_polled_at
    ):
        return "failing"
    if last_polled_at is not None:
        return "active"
    return "never_used"


class _AuditSignals:
    """One pass over the org's audit stream, extracting exactly the
    per-source-id recency signals this route needs. Kept as a small,
    dedicated collaborator (not inline in the route function) so the
    single-stream-pass shape is easy to unit test independently of the
    route's HTTP plumbing."""

    def __init__(self) -> None:
        self.last_push_ingested_at: dict[str, datetime] = {}
        self.last_poll_completed_at: datetime | None = None
        self.last_poll_failed_at: datetime | None = None
        self.last_poll_failure_reason: str | None = None

    def observe(self, event: AuditEvent) -> None:
        if event.event_type == AuditEventType.INTEGRATION_SOURCE_PUSH_INGESTED:
            source_id = event.details.get("source_id")
            if not isinstance(source_id, str):
                return
            current = self.last_push_ingested_at.get(source_id)
            if current is None or event.occurred_at > current:
                self.last_push_ingested_at[source_id] = event.occurred_at
            return

        if event.details.get("source_type") != _DEFENDER_SOURCE_TYPE:
            return

        if event.event_type == AuditEventType.INTEGRATION_SOURCE_POLL_COMPLETED:
            current_completed = self.last_poll_completed_at
            if current_completed is None or event.occurred_at > current_completed:
                self.last_poll_completed_at = event.occurred_at
        elif event.event_type == AuditEventType.INTEGRATION_SOURCE_POLL_FAILED:
            if self.last_poll_failed_at is None or event.occurred_at > self.last_poll_failed_at:
                self.last_poll_failed_at = event.occurred_at
                reason = event.details.get("error")
                self.last_poll_failure_reason = reason if isinstance(reason, str) else None


def _resolve_defender_org_id(raw_org_id: str | None) -> uuid.UUID | None:
    """Parse ``raw_org_id`` (``Settings.defender_poll_org_id``) the same way
    ``celery_defender.py``'s own real poll task does -- a malformed
    (non-empty) value is a real deployment misconfiguration, not an honest
    "unconfigured" state, but this is a read-only status route, not the poll
    task itself: it logs the misconfiguration and treats it as "no entry"
    rather than 500ing the whole status page over it.
    """
    if not raw_org_id:
        return None
    try:
        return uuid.UUID(raw_org_id)
    except ValueError:
        logger.warning(
            "defender_poll_org_id_malformed",
            extra={"defender_poll_org_id": raw_org_id},
        )
        return None


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


@router.get("/status", response_model=ConnectorStatusListOut)
async def get_connector_status(
    tenant: Annotated[TenantContext, Depends(requires_role(Role.ORG_ADMIN))],
    key_repository: Annotated[
        IntegrationSourceKeyRepository, Depends(get_integration_source_key_repository)
    ],
    audit_svc: Annotated[AuditLogService, Depends(get_audit_log_service)],
    defender_poll_org_id: Annotated[str | None, Depends(get_defender_poll_org_id)],
    defender_poll_source_id: Annotated[str, Depends(get_defender_poll_source_id)],
) -> ConnectorStatusListOut:
    """Real, per-org connector status: every PUSH-mode source ever
    provisioned for the caller's org (self-service, W8), plus Microsoft
    Defender's global POLL status IF this org is the one
    ``defender_poll_org_id`` names (not self-service -- see module
    docstring). Never fabricates a connector or a status signal that
    wasn't actually observed in the audit log.
    """
    push_summaries = await key_repository.list_by_org(tenant.org_id)
    resolved_defender_org_id = _resolve_defender_org_id(defender_poll_org_id)
    include_defender = resolved_defender_org_id == tenant.org_id

    signals = _AuditSignals()
    async for event in audit_svc._repository.stream_by_org(tenant.org_id):
        signals.observe(event)

    items: list[ConnectorStatusOut] = []
    for summary in push_summaries:
        last_ingested_at = signals.last_push_ingested_at.get(summary.source_id)
        items.append(
            ConnectorStatusOut(
                sourceId=summary.source_id,
                sourceType=summary.source_type,
                mode="push",
                selfService=True,
                status=_push_status(
                    revoked_at=summary.revoked_at, last_ingested_at=last_ingested_at
                ),
                createdAt=summary.created_at.isoformat(),
                revokedAt=summary.revoked_at.isoformat() if summary.revoked_at else None,
                lastIngestedAt=last_ingested_at.isoformat() if last_ingested_at else None,
                lastPolledAt=None,
                lastPollFailedAt=None,
                lastFailureReason=None,
                note=_PUSH_NOTE,
            )
        )

    if include_defender:
        items.append(
            ConnectorStatusOut(
                sourceId=defender_poll_source_id,
                sourceType=_DEFENDER_SOURCE_TYPE,
                mode="poll",
                selfService=False,
                status=_poll_status(
                    last_polled_at=signals.last_poll_completed_at,
                    last_poll_failed_at=signals.last_poll_failed_at,
                ),
                createdAt=None,
                revokedAt=None,
                lastIngestedAt=None,
                lastPolledAt=(
                    signals.last_poll_completed_at.isoformat()
                    if signals.last_poll_completed_at
                    else None
                ),
                lastPollFailedAt=(
                    signals.last_poll_failed_at.isoformat() if signals.last_poll_failed_at else None
                ),
                lastFailureReason=signals.last_poll_failure_reason,
                note=_POLL_NOTE,
            )
        )

    return ConnectorStatusListOut(items=items)
