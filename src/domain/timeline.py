"""TimelineRecord domain model: ECS schema + kronos.* provenance block.

``kronos.*`` provenance splits into two concrete shapes (roadmap M1/B1):

- ``EvidenceProvenance`` -- a record parsed from an uploaded, hashed,
  case-scoped evidence file. This is the shape every one of today's six
  parsers (``src/external/parsers/*``) already produces.
- ``StreamProvenance`` (``src/domain/stream.py``) -- a record ingested from
  continuous telemetry (a future syslog/EDR/Zeek collector, roadmap M3),
  which has no owning evidence file, no per-file sha256, and no case at
  ingest time (a case is attached later, during triage).

Both share ``ProvenanceBase``. ``TimelineRecord.kronos`` is intentionally
**not yet** widened to the ``EvidenceProvenance | StreamProvenance`` union in
this pass -- see the follow-up note on ``KronosProvenance`` below for why,
and ``src/domain/stream.py`` for the discriminated-union type that is ready
for that follow-up to adopt.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

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


class EvidenceProvenance(ProvenanceBase):
    """Provenance for a record parsed from an uploaded, hashed evidence file.

    This is today's provenance shape, unchanged in behavior -- only the name
    changes (previously ``KronosProvenance``, defined directly in this
    module with these same fields). ``KronosProvenance`` below is kept as a
    plain alias so every existing caller (all six parsers under
    ``src/external/parsers/``, ``src/external/sandbox/firecracker.py``,
    ``src/adapter/repository/postgres_artifact.py``, and
    ``tests/fixtures/factories.py``) keeps working unmodified.
    """

    # Discriminator for the EvidenceProvenance | StreamProvenance union
    # (src/domain/stream.py:Provenance). Defaulted so every existing
    # construction site -- none of which passes `kind=` today -- keeps
    # working without modification.
    kind: Literal["evidence"] = "evidence"

    evidence_id: uuid.UUID
    case_id: uuid.UUID
    sha256: str = Field(description="SHA-256 of the source evidence file")
    record_index: int = Field(ge=0, description="Zero-based index within the parsed evidence file")

    # Additive, optional: only set for records extracted from a container
    # (KAPE zip, disk image). Lets an examiner filter "all events from
    # .../winevt/Logs/Security.evtx inside evidence.zip" -- surfaced as ECS
    # file.path. container_sha256 links a derived record back to the sealed
    # top-level evidence object even after recursive extraction.
    source_path: str | None = Field(
        default=None, description="Path of the originating file inside the container/image"
    )
    container_sha256: str | None = Field(
        default=None,
        description="SHA-256 of the top-level container (unset for non-container evidence)",
    )


# Backward-compatible alias. `KronosProvenance` is the exact name every
# existing call site imports and constructs; renaming the class in place to
# `EvidenceProvenance` and binding the old name to the same class object is
# a zero-behavior-change rename (same validation, same fields, same
# defaults) -- not a parallel/duplicate type. Widening these call sites to
# import `EvidenceProvenance` directly, and widening `TimelineRecord.kronos`
# itself to `EvidenceProvenance | StreamProvenance`, is explicitly left as
# scoped follow-up (see docs/NEXTGEN_SOC_ROADMAP.md B1/B2 and this task's
# final report) -- it touches all six parsers plus timeline_normalization.py
# and is out of this pass's src/domain/-only scope.
KronosProvenance = EvidenceProvenance


class ECSBase(BaseModel):
    """Minimal ECS base fields required for all timeline records."""

    model_config = {"frozen": True}

    # @timestamp is the canonical event time in ECS.
    timestamp: datetime = Field(alias="@timestamp")
    message: str | None = None

    # ECS event fields
    event_kind: str | None = Field(None, alias="event.kind")
    event_category: list[str] = Field(default_factory=list, alias="event.category")
    event_type: list[str] = Field(default_factory=list, alias="event.type")
    event_outcome: str | None = Field(None, alias="event.outcome")
    event_original: str | None = Field(None, alias="event.original")

    # ECS host fields
    host_name: str | None = Field(None, alias="host.name")
    host_os_name: str | None = Field(None, alias="host.os.name")

    # ECS user fields
    user_name: str | None = Field(None, alias="user.name")
    user_id: str | None = Field(None, alias="user.id")

    # ECS process fields
    process_pid: int | None = Field(None, alias="process.pid")
    process_name: str | None = Field(None, alias="process.name")

    model_config = {"frozen": True, "populate_by_name": True}


class TimelineRecord(BaseModel):
    """A single parsed forensic event, normalized to ECS + kronos.* provenance."""

    model_config = {"frozen": True, "populate_by_name": True}

    # Deterministic _id for idempotent OpenSearch ingestion.
    # SHA1(evidence_id:parser:record_index) — computed by TimelineIngestionService.
    document_id: str | None = None

    # ECS core fields (flattened for direct OpenSearch mapping)
    timestamp: datetime = Field(alias="@timestamp")
    message: str | None = None
    event_kind: str | None = Field(None, alias="event.kind")
    event_category: list[str] = Field(default_factory=list, alias="event.category")
    event_type: list[str] = Field(default_factory=list, alias="event.type")
    event_outcome: str | None = Field(None, alias="event.outcome")
    event_original: str | None = Field(None, alias="event.original")
    host_name: str | None = Field(None, alias="host.name")
    host_os_name: str | None = Field(None, alias="host.os.name")
    user_name: str | None = Field(None, alias="user.name")
    user_id: str | None = Field(None, alias="user.id")
    process_pid: int | None = Field(None, alias="process.pid")
    process_name: str | None = Field(None, alias="process.name")

    # Format-specific extra fields preserved as-is.
    extra: dict[str, Any] = Field(default_factory=dict)

    # kronos.* provenance block — mandatory for every record.
    #
    # Still narrowed to EvidenceProvenance, not widened to the
    # EvidenceProvenance | StreamProvenance union (src/domain/stream.py),
    # in this pass. Every current producer of a TimelineRecord (the six
    # parsers under src/external/parsers/, src/external/sandbox/
    # firecracker.py) is evidence-file-based, so this is not a regression
    # -- it's the scoped follow-up documented in this task's report:
    # widening this annotation is only safe once something in the
    # pipeline actually constructs a StreamProvenance (roadmap D1/D2/D4),
    # which does not exist yet.
    kronos: EvidenceProvenance
