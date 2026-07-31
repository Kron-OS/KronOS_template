"""CollectorIdentity: the org/source identity of a telemetry collector, derived
exclusively from its verified mTLS client certificate (roadmap M3/D2).

Never constructed from a collector's own request payload -- see
``src/domain/stream.py``'s ``StreamProvenance`` docstring for the invariant
this type exists to uphold structurally: a collector that lies about its
``org_id``/``source_id`` in an event body must not be able to write into
another tenant's data. This type is only ever constructed by
``src/external/middleware/collector_mtls.py`` after real X.509 chain
verification (enforced at the TLS transport layer, not here -- see that
module's docstring) and Subject Alternative Name parsing. No route or
service may construct one any other way.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field


class CollectorIdentity(BaseModel):
    """Authenticated collector identity: org + source, from a verified client cert.

    ``cert_subject``/``not_after`` are informational only (structured
    logging/observability) -- never parsed for identity, that is the SAN's
    job exclusively (see the extractor).
    """

    model_config = {"frozen": True}

    org_id: uuid.UUID
    source_id: str = Field(min_length=1)
    cert_subject: str = Field(description="Certificate CN, informational only")
    not_after: str = Field(description="Certificate expiry (ISO 8601), informational only")
