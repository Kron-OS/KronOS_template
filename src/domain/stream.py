"""StreamProvenance: kronos.* provenance for continuous telemetry (roadmap M3).

``EvidenceProvenance`` (``src/domain/timeline.py``) mandates ``evidence_id``,
``case_id``, a source-file ``sha256``, and a ``record_index`` -- correct for
a record parsed out of an uploaded, hashed evidence file, but structurally
wrong for continuous telemetry (a future syslog/EDR/Zeek collector, D1/D2):

- There is no owning evidence file, so no real ``evidence_id`` exists.
- There is nothing to hash per-event; hashing/sealing happens per *batch*
  (roadmap D3, Merkle root over per-event hashes), not per source file.
- A case is not known at ingest time -- telemetry lands in a stream index
  first and gets attached to a case later, during triage (roadmap B2).

Papering over this with sentinel/placeholder UUIDs for ``evidence_id`` or
``case_id`` would let a stream record silently impersonate custody it does
not have -- an ``evidence_id`` that does not point to a real ``Evidence`` row
is a forensic-integrity bug, not a convenience. ``StreamProvenance`` is a
distinct, honestly-shaped type instead, sharing only what is genuinely
common with evidence-file provenance (``ProvenanceBase``).

This module is a real, tested, standalone sibling type this pass -- it is
**not yet wired** into ``TimelineRecord.kronos`` (still narrowed to
``EvidenceProvenance`` in ``src/domain/timeline.py``) because nothing in the
pipeline produces a ``StreamProvenance`` yet (that's D1/D2/D4). See this
task's final report for the exact follow-up list.
"""

from __future__ import annotations

import uuid
from typing import Annotated, Literal

from pydantic import Field

from src.domain.timeline import EvidenceProvenance, ProvenanceBase


class StreamProvenance(ProvenanceBase):
    """Provenance for a record ingested from continuous telemetry, not a file.

    ``org_id`` inherits the same non-negotiable constraint documented on
    ``ProvenanceBase``: for a stream, the authoritative source is the
    verified collector client certificate (roadmap D2 -- step-ca-issued
    mTLS identity), never a field the collector's own payload can set. A
    collector that lies about its ``org_id`` in the event body must not be
    able to write into another tenant's data; this type does not enforce
    that itself (no domain-layer object can), it only avoids *inviting* the
    mistake by never taking org identity from a "stream payload" field.
    """

    kind: Literal["stream"] = "stream"

    source_id: str = Field(
        min_length=1,
        description=(
            "Identifies the stream/collector source, e.g. 'zeek-conn-log' or "
            "'edr-vendor-x-host42'. Not a case/evidence identifier -- scoping "
            "is per-source, per-org."
        ),
    )
    # Seam for the future SealedBatch entity (roadmap B3/D3): a stream
    # segment is time- or size-bounded, sealed into one WORM object with one
    # TSA token and a Merkle root over per-event hashes so any single event
    # stays independently provable. SealedBatch itself does not exist yet --
    # batch_id is deliberately just a UUID reference today, not a foreign
    # key to a real repository, so this pass does not have to build that
    # entity to give stream records a real place to point once it exists.
    batch_id: uuid.UUID = Field(
        description="Sealed batch this event belongs to (future SealedBatch, roadmap D3)"
    )
    event_offset: int = Field(
        ge=0,
        description="Zero-based position of this event within its stream/batch (record_index-equivalent)",
    )
    # Optional and absent at ingest time by design -- attached later during
    # triage (roadmap B2), unlike EvidenceProvenance.case_id which is
    # mandatory because a case always exists before an evidence file is
    # uploaded into it.
    case_id: uuid.UUID | None = Field(
        default=None,
        description="Case this event has been triaged into, if any -- NOT required at ingest",
    )


# Discriminated union, ready for the (explicitly scoped-out-of-this-pass)
# follow-up that widens TimelineRecord.kronos to this type. Verified in
# poc/provenance_split/ and tests/unit/domain/test_stream_provenance.py:
# pydantic.TypeAdapter(Provenance) correctly round-trips both branches via
# the `kind` discriminator and rejects a payload with neither/an unknown
# `kind`.
Provenance = Annotated[EvidenceProvenance | StreamProvenance, Field(discriminator="kind")]
