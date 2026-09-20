"""Admin connector status route (Milestone W14, docs/ASSESSMENT_SYNTHESIS_2026-08.md
P2-W14, from docs/assessments/ux_onboarding_review.md SS1).

Closes a real, previously-confirmed UX gap: connectors exist but no
admin-visible surface showed whether any of them were configured or
healthy for a given org. This route is read-only status, not
configuration -- it never mutates anything, so (like
``GET /api/admin/integration-sources`` in ``admin_integration_sources.py``)
it is ``ORG_ADMIN``-gated only, no step-up bar (step-up is reserved for
credential issuance/revocation, not for reading).

**PUSH-mode sources only (Wazuh, Suricata/Zeek), by design, not by
omission -- read this before adding POLL/SINK entries back here.** Before
the connector marketplace (`/admin/connectors`, ``admin_connector_config.py``)
existed, Microsoft Defender's POLL status was included here as a special
case gated on a single GLOBAL ``Settings.defender_poll_org_id`` -- there
was nowhere else in the UI a POLL connector's status could show up. Now
that Defender (and Splunk HEC/CEF syslog/Sentinel) are real, per-org
``connector_configs`` rows, their live status (``enabled``/
``consecutiveFailureCount``/``autoDisabledAt``) is already surfaced
directly on each connector's own marketplace catalog card
(``ConnectorConfigOut``, ``admin_connector_config.py``) -- reusing this
route's own audit-log-recency-scan approach for those types would mean
re-deriving a second, weaker status signal from a log that (for sinks)
doesn't even carry a `source_type`/`sink_name` field to filter by
(``DetectionSinkPushService`` pushes are generic over `IntegrationSink`,
by design -- see that module's own docstring), duplicating what the
`connector_configs` row already tracks authoritatively. This route's own
scope is deliberately narrowed back to what it does well: PUSH self-service
key status, exactly as ``IntegrationSourceKeyRepository.list_by_org``
(Milestone W8) already provides it.

Recency signals are derived from the audit log, reusing
``routes/audit.py``'s own ``merkle_proof`` idiom of streaming
``audit_svc._repository.stream_by_org(tenant.org_id)`` once and filtering in
Python by ``event_type``/``details`` (rather than adding a new repository
query method) -- the established pattern for "read the whole org log,
filter for one query" in this codebase.

Mirrors ``admin_integration_sources.py``'s own conventions: camelCase DTOs
(this repo's own route convention, see ``pyproject.toml``'s ``N815``
per-file-ignore for this module), org-scoping exclusively from
``tenant.org_id`` (never client-supplied).
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from src.adapter.repository.integration_source_key import IntegrationSourceKeyRepository
from src.application.audit_log import AuditLogService
from src.domain.audit import AuditEvent, AuditEventType
from src.domain.user import Role, TenantContext
from src.external.dependencies import get_audit_log_service, get_integration_source_key_repository
from src.external.middleware.rbac import requires_role

router = APIRouter(prefix="/api/admin/connectors", tags=["admin"])

_PUSH_NOTE = "Self-service: this org provisioned this connector's API key directly."

_ConnectorStatusState = Literal["never_used", "active", "failing", "revoked"]


# ---------------------------------------------------------------------------
# DTOs
# ---------------------------------------------------------------------------


class ConnectorStatusOut(BaseModel):
    """One PUSH connector's real, observed status -- never a fabricated/
    optimistic default. POLL/SINK connector status lives on the
    marketplace catalog's own ``ConnectorConfigOut`` instead (see this
    module's own docstring for why)."""

    sourceId: str
    sourceType: str
    mode: Literal["push"]
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


class _AuditSignals:
    """One pass over the org's audit stream, extracting exactly the
    per-source-id recency signal PUSH status needs. Kept as a small,
    dedicated collaborator (not inline in the route function) so the
    single-stream-pass shape is easy to unit test independently of the
    route's HTTP plumbing."""

    def __init__(self) -> None:
        self.last_push_ingested_at: dict[str, datetime] = {}

    def observe(self, event: AuditEvent) -> None:
        if event.event_type != AuditEventType.INTEGRATION_SOURCE_PUSH_INGESTED:
            return
        source_id = event.details.get("source_id")
        if not isinstance(source_id, str):
            return
        current = self.last_push_ingested_at.get(source_id)
        if current is None or event.occurred_at > current:
            self.last_push_ingested_at[source_id] = event.occurred_at


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
) -> ConnectorStatusListOut:
    """Real, per-org PUSH connector status: every source ever provisioned
    for the caller's org (self-service, W8). Never fabricates a connector
    or a status signal that wasn't actually observed in the audit log.
    """
    push_summaries = await key_repository.list_by_org(tenant.org_id)

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

    return ConnectorStatusListOut(items=items)
