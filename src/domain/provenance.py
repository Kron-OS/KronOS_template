"""ProvenanceBase: fields shared by every kronos.* provenance shape.

Split out of ``src/domain/timeline.py`` into its own leaf module (roadmap
D4) so that ``EvidenceProvenance`` (``timeline.py``) and ``StreamProvenance``
(``stream.py``) can both depend on it without ``timeline.py`` and
``stream.py`` depending on *each other* -- a real circular import that only
appears once ``TimelineRecord.kronos`` is widened to the
``EvidenceProvenance | StreamProvenance`` union (D4's own job): that widening
requires ``timeline.py`` to import ``StreamProvenance`` from ``stream.py``,
which, if ``stream.py`` still imported ``ProvenanceBase`` from
``timeline.py`` as it did pre-D4, would be a genuine A->B->A cycle at module
load time (verified by trying it: ``ImportError: cannot import name
'StreamProvenance' from partially initialized module 'src.domain.stream'``,
depending on which module a caller happens to import first). Moving the one
shared base class here breaks the cycle structurally instead of papering
over it with deferred/forward-ref imports: this module imports nothing from
either ``timeline.py`` or ``stream.py``, so both can depend on it freely.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class ProvenanceBase(BaseModel):
    """Fields common to every kronos.* provenance block, forensic or streamed.

    ``org_id`` is always computed by the server -- from the authenticated
    ``TenantContext`` for evidence uploads, or from a verified collector
    client certificate for streams (roadmap D2) -- and is **never** accepted
    verbatim from a parser's or collector's own output/payload. This is
    invariant §1.3 in ``docs/NEXTGEN_SOC_ROADMAP.md``: a stream source lying
    about its own ``org_id`` in its payload must never be able to write into
    another tenant's data. Nothing in this domain layer enforces that by
    itself (it has no notion of "the request" or "the caller") -- the
    enforcement point is the application-layer service that constructs the
    provenance object, which is why this is documented here rather than
    coded as a validator.
    """

    model_config = {"frozen": True}

    org_id: uuid.UUID
    org_alias: str = Field(default="", description="Human-readable org alias for querying")
    parser: str = Field(description="Parser/collector name that produced this record")
    parser_version: str
    ingest_timestamp: datetime = Field(description="UTC time the record was written to OpenSearch")
