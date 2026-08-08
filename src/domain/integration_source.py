"""Domain value objects for the ``IntegrationSource`` foundation (roadmap Q1).

See ``src/application/integration_source.py`` for the full design rationale
(why this is a new ABC rather than a ``ForensicParser`` extension). This
module holds only the pure, framework-free value objects shared by every
collaborator in that design -- mirrors ``src/domain/collector.py``'s own
scope (identity only, no logic) and ``src/domain/stream.py`` (provenance-
adjacent state), kept separate from ``timeline.py``/``stream.py`` because
neither of those modules' existing concerns (ECS record shape, stream
provenance) actually owns "which external tool authenticated this call" or
"where did we leave off polling" -- both are genuinely new concepts.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class IntegrationDeliveryMode(StrEnum):
    """How an external tool's events reach KronOS.

    Only PUSH and POLL are implemented in this pass (roadmap Q1/§4 -- Wazuh
    is push-shaped, Microsoft Defender is poll-shaped). A third shape,
    CrowdStrike-class long-lived supervised streaming, is a real, named,
    deliberately deferred extension point -- see this enum's own omission
    of a STREAM member and ``IntegrationSource``'s module docstring for why
    adding it later needs no change to PUSH/POLL's own contracts.
    """

    PUSH = "push"
    POLL = "poll"


class IntegrationSourceIdentity(BaseModel):
    """Authenticated identity of one configured external-tool connector.

    Mirrors ``CollectorIdentity``'s own non-negotiable invariant exactly
    (see that class's docstring): ``org_id``/``source_id`` must never be
    constructed from anything the external tool's own request/response
    payload says -- only from a real authentication/provisioning decision
    (``InboundSourceAuthenticator`` for push, static per-connector
    provisioning config for poll -- see
    ``src/external/middleware/integration_source_auth.py`` and
    ``src/application/integration_source.py``). A malicious or
    misconfigured external tool must not be able to write into another
    tenant's data by lying about its own identity in its own alert body.

    Deliberately not reusing ``CollectorIdentity`` itself: that type's
    ``cert_subject``/``not_after`` fields are mTLS-specific and would be
    dishonestly empty/fabricated for an API-key- or OAuth2-authenticated
    connector -- a new, honestly-shaped type is one field difference
    (``auth_method``) away from ``CollectorIdentity``, not a parallel
    hierarchy for its own sake.
    """

    model_config = {"frozen": True}

    org_id: uuid.UUID
    source_id: str = Field(min_length=1)
    source_type: str = Field(
        min_length=1,
        description=(
            "Registered IntegrationSource.source_type this identity is "
            "scoped to, e.g. 'generic-webhook'."
        ),
    )
    auth_method: str = Field(
        description=(
            "How this identity was established, e.g. 'mtls', 'api-key', "
            "'oauth2-client-credentials' -- informational/audit only, "
            "never re-derived from it."
        )
    )


class SourceCursor(BaseModel):
    """Durable per-(org, source) watermark for poll-based resumption.

    Genuinely new state (roadmap Q1/§4 point 3) -- nothing else in this
    codebase tracks "how far into an external tool's own event history have
    we already ingested." Distinct from the mTLS collector's content-hash
    dedup (``EventDedupChecker``): dedup answers "have we seen this exact
    event before" (works for push retries), this answers "where do we ask
    the external API to resume from" (required for poll -- a restarting
    poll connector with no watermark would have to choose between
    re-ingesting its entire history or silently dropping everything since
    its last successful call).

    ``cursor_value`` is deliberately an opaque string, not a timestamp: some
    real APIs cursor by opaque continuation token, others by a
    last-modified timestamp string, others by a monotonic id -- forcing one
    shape here would leak a specific vendor's convention into the
    foundation before any real vendor (Q4) has been built against it.
    """

    model_config = {"frozen": True}

    org_id: uuid.UUID
    source_id: str = Field(min_length=1)
    cursor_value: str
    updated_at: datetime
