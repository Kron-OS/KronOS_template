"""EventDedupChecker: content-hash-based idempotency for collector retries
(roadmap M3/D2).

A collector that retries a batch after a network blip (no ack received, so
it cannot know whether the server actually produced the event) must not
have those events land twice in the stream. The real mechanism: SHA-256
over the exact canonical event bytes as an idempotency key, checked with an
atomic SET-if-not-exists against Redis -- the same real, already-verified
Redis instance D1's ``StreamIngestAdapter`` uses (``poc/stream_ingest_redis/``).
Atomicity matters: two concurrent retries of the same event must not both
observe "not seen yet" and both produce.

TTL-bounded, not permanent: an unbounded dedup set is unbounded storage
growth for real production event volumes. A genuine retry arriving *after*
the TTL elapses would double-ingest -- an explicit, documented trade-off,
not an oversight. ``settings.collector_dedup_ttl_seconds`` should be set
well beyond any realistic collector retry/backoff window.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod


class EventDedupChecker(ABC):
    """Per-(org, source) content-hash idempotency check."""

    @abstractmethod
    async def is_duplicate(
        self, org_id: uuid.UUID, source_id: str, content_hash: str, *, ttl_seconds: int
    ) -> bool:
        """Atomically records *content_hash* as seen for this (org, source).

        Returns True if it was ALREADY seen within the last *ttl_seconds*
        (this call is the duplicate -- caller must not re-produce it).
        Returns False if this is the first time (and it is now recorded).
        """


class RedisEventDedupChecker(EventDedupChecker):
    """Real Redis implementation: ``SET key 1 NX EX ttl_seconds``.

    ``NX`` makes the "already exists" check and the "record it" write one
    atomic operation -- no separate GET-then-SET race window.
    """

    def __init__(self, redis_client) -> None:  # type: ignore[no-untyped-def]
        self._redis = redis_client

    def _key(self, org_id: uuid.UUID, source_id: str, content_hash: str) -> str:
        return f"kronos:dedup:{org_id}:{source_id}:{content_hash}"

    async def is_duplicate(
        self, org_id: uuid.UUID, source_id: str, content_hash: str, *, ttl_seconds: int
    ) -> bool:
        was_newly_set = await self._redis.set(
            self._key(org_id, source_id, content_hash), "1", nx=True, ex=ttl_seconds
        )
        return not bool(was_newly_set)


class InMemoryEventDedupChecker(EventDedupChecker):
    """Thread-unsafe in-memory stand-in for unit tests -- no real TTL expiry
    (entries live for the process lifetime); tests needing real TTL
    semantics belong in ``poc/collector_ingest_mtls/``, not here (mirrors
    ``InMemoryStreamIngestAdapter``'s own documented scope: a simple double
    for callers that just need *a* dedup check, not a Redis reimplementation).
    """

    def __init__(self) -> None:
        self._seen: set[tuple[uuid.UUID, str, str]] = set()

    async def is_duplicate(
        self, org_id: uuid.UUID, source_id: str, content_hash: str, *, ttl_seconds: int
    ) -> bool:
        key = (org_id, source_id, content_hash)
        if key in self._seen:
            return True
        self._seen.add(key)
        return False
