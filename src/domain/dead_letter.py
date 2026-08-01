"""DeadLetterEvent: the durable record of one stream event that failed to
normalize (roadmap M3/D5).

Sibling to ``SealedBatch`` (``src/domain/sealed_batch.py``) in spirit -- a
small, frozen, append-only record -- but deliberately NOT a chain-of-custody
artifact in the same sense: a dead-lettered event is a single already-sealed
event that ``StreamSourceNormalizer.normalize()`` (``src/application/
stream_source_registry.py``) could not turn into ECS fields (malformed JSON,
a missing required field, etc.). It still comes from a sealed, WORM-anchored
batch -- the raw bytes are never lost, they are simply routed here instead of
into OpenSearch, so an operator can inspect exactly what failed and why
without that one bad event silently swallowing the rest of a perfectly-good
batch (``StreamNormalizationService.normalize_batch``'s own docstring
explains the bug this closes).

``org_id`` is always the sealed batch's own ``org_id`` (never inferred from
payload content, same invariant every other tenant-scoped entity in this
codebase follows).
"""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class DeadLetterEvent(BaseModel):
    """One stream event that failed normalization, preserved for inspection.

    ``payload`` is the exact raw bytes decoded out of the sealed batch's WORM
    manifest for this ``event_offset`` -- an operator can re-run the
    registered normalizer against it directly once the root cause (a schema
    change upstream, a genuinely corrupt line, etc.) is understood, without
    needing to re-fetch the whole batch's WORM object.
    """

    model_config = {"frozen": True}

    dead_letter_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    org_id: uuid.UUID
    source_id: str = Field(min_length=1)
    batch_id: uuid.UUID
    event_offset: int = Field(ge=0)
    payload: bytes
    error_type: str = Field(min_length=1)
    error_message: str
    dead_lettered_at: datetime
