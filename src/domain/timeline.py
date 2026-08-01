"""TimelineRecord domain model: ECS schema + kronos.* provenance block.

``kronos.*`` provenance splits into two concrete shapes (roadmap M1/B1):

- ``EvidenceProvenance`` -- a record parsed from an uploaded, hashed,
  case-scoped evidence file. This is the shape every one of today's six
  parsers (``src/external/parsers/*``) already produces.
- ``StreamProvenance`` (``src/domain/stream.py``) -- a record ingested from
  continuous telemetry (a Zeek/EDR/syslog collector, roadmap M3), which has
  no owning evidence file, no per-file sha256, and no case at ingest time (a
  case is attached later, during triage).

Both share ``ProvenanceBase`` (``src/domain/provenance.py`` -- moved to its
own leaf module in this pass precisely so this widening is possible without
a circular import; see that module's docstring). ``TimelineRecord.kronos``
is now widened to the ``Provenance = EvidenceProvenance | StreamProvenance``
discriminated union (roadmap D4 -- the first real producer of a
``StreamProvenance``, ``StreamNormalizationService``, now exists). Every
existing construction site (`TimelineRecord(kronos=EvidenceProvenance(...))`
or the `KronosProvenance` alias) keeps working unmodified: the union is
additive, and `EvidenceProvenance.kind` already defaults to `"evidence"`.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field

from src.domain.provenance import ProvenanceBase
from src.domain.stream import StreamProvenance


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


# Discriminated union of every kronos.* provenance shape (roadmap D4).
# Defined here, before TimelineRecord, rather than in src/domain/stream.py
# where StreamProvenance itself lives: stream.py no longer imports anything
# from this module (it now depends only on the shared leaf
# src/domain/provenance.py) precisely so this module can import
# StreamProvenance from stream.py without a circular import. Must be
# defined before TimelineRecord's class body below -- pydantic resolves
# `from __future__ import annotations` string annotations against this
# module's globals at class-creation time, not lazily on first use, so a
# forward reference to a name defined later in the same file would leave
# the model "incomplete" until a manual model_rebuild() call.
Provenance = Annotated[EvidenceProvenance | StreamProvenance, Field(discriminator="kind")]


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
    # Widened (roadmap D4) to the discriminated Provenance union defined at
    # the bottom of this module: EvidenceProvenance for the six file-based
    # parsers (unchanged), StreamProvenance for StreamNormalizationService's
    # continuous-telemetry records (src/application/stream_normalization.py).
    kronos: Provenance
