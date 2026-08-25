"""SealedBatch: the immutable, WORM-protected artifact chain-of-custody seam
for continuous telemetry (roadmap M3/D3).

``StreamProvenance.batch_id`` (``src/domain/stream.py``) has anticipated this
entity since B1/D1: continuous telemetry cannot be hashed/scanned/timestamped
per-event without becoming prohibitively expensive at real ingest volume, so
custody is established per *batch* instead -- a time- or size-bounded segment
of a single (org, source) stream, sealed into exactly one WORM object, one
RFC 3161 TSA token, one audit event, and a Merkle root over the batch's own
per-event hashes.

The Merkle root construction is deliberately the *same* one already proven by
``AuditLogService.anchor_day()`` (``src/application/audit_log.py``) and
``src/domain/merkle.py`` -- RFC 6962-style leaf/node domain separation,
promotion of unpaired nodes. This entity does not reimplement any of that; it
only stores ``leaf_hashes`` (one per event, in the exact order they were
included in the batch -- also the order ``message_ids`` uses) so that
``src.domain.merkle.merkle_proof(leaf_hashes, index)`` /
``verify_proof(leaf, proof, merkle_root)`` can reconstruct and check an
inclusion proof for any single event *without ever needing to re-fetch the
WORM object* -- "any single event within the batch stays independently
provable" (roadmap D3 objective) means provable from this Postgres row alone.

Per roadmap invariant #5, a sealed batch is now itself a primary evidentiary
artifact (like ``Evidence``), not a derived opinion -- once persisted it is
never mutated, matching ``AuditEvent``'s ``frozen=True`` idiom.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field, model_validator


class SealedBatch(BaseModel):
    """One immutable, sealed segment of a single (org_id, source_id) stream.

    ``org_id`` is never taken from event payload content -- it is always the
    key of the real D1 stream (``kronos:stream:{org_id}:{source_id}``) the
    events were actually consumed from (roadmap invariant #3), passed in by
    the caller (``BatchSealingService``) that did the consuming, never
    inferred from the events themselves.
    """

    model_config = {"frozen": True}

    batch_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    org_id: uuid.UUID
    source_id: str = Field(min_length=1)
    sealed_at: datetime

    event_count: int = Field(ge=1)
    # Per-event SHA-256 hex digests, in the same order as message_ids --
    # these ARE the Merkle leaves (fed through src.domain.merkle.leaf_hash's
    # own domain separation internally by build_merkle_root/merkle_proof,
    # exactly like AuditEvent.row_hash is for the audit-log tree).
    leaf_hashes: tuple[str, ...]
    # The real D1 StreamMessage.message_id for each event, same order/index
    # as leaf_hashes -- lets an operator look up "which real stream entry is
    # leaf index 7" without re-reading the WORM object.
    message_ids: tuple[str, ...]
    merkle_root: str

    worm_bucket: str
    worm_object_key: str

    # DER-encoded RFC 3161 TimeStampToken bytes, or None only if no TSA was
    # configured at all (dev/test) -- see BatchSealingService's docstring:
    # unlike AuditLogService.anchor_day() (TSA is best-effort there), a
    # *configured* TSA that fails must abort the whole seal, so a persisted
    # SealedBatch row with tsa_token=None only ever means "no TSA configured
    # in this deployment", never "TSA was tried and failed".
    tsa_token: bytes | None = None

    # Watermark fields: the first/last real stream message id this batch
    # covers, used by the next seal cycle's gap check (an unsealed-trim
    # detector compares the stream's current earliest retained id against
    # the most recent SealedBatch.last_message_id for this (org, source)).
    first_message_id: str
    last_message_id: str

    @model_validator(mode="after")
    def _leaves_and_ids_align(self) -> SealedBatch:
        if len(self.leaf_hashes) != self.event_count or len(self.message_ids) != self.event_count:
            raise ValueError(
                "leaf_hashes/message_ids length must equal event_count "
                f"(event_count={self.event_count}, "
                f"leaf_hashes={len(self.leaf_hashes)}, message_ids={len(self.message_ids)})"
            )
        return self
