"""StreamIngestAdapter ABC + RedisStreamIngestAdapter: durable, replayable,
at-least-once continuous-telemetry transport (roadmap M3/D1).

Real, live-cluster verified design (poc/stream_ingest_redis/, 22/22 checks):
per-org, per-source keys (`kronos:stream:{org_id}:{source_id}`, org first)
make cross-org isolation structural, not app-layer-filtered -- two orgs
with the identical source_id never share a key, confirmed via a real
NOGROUP error when one org's consumer group is used against another org's
key (there is no shared subscription state to even return empty results
from). At-least-once delivery uses Redis Streams' own real consumer-group
primitives (XREADGROUP/XPENDING/XAUTOCLAIM) -- durability lives
server-side (the group's read cursor), not in this adapter's memory, so a
process restart picks up exactly where a crashed consumer left off.

This module is deliberately payload-agnostic (raw bytes) -- turning a
payload into a real `StreamProvenance`/`TimelineRecord` is the continuous
normalization pipeline's job (roadmap D4), not this transport's. Swapping
in Kafka/Redpanda later means a new class implementing this same ABC,
zero changes to any caller.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class StreamMessage:
    """One transport-level message: an opaque id plus its raw payload bytes."""

    message_id: str
    payload: bytes


class StreamIngestAdapter(ABC):
    """Per-org, per-source durable telemetry transport."""

    @abstractmethod
    async def produce(self, org_id: uuid.UUID, source_id: str, payload: bytes) -> str:
        """Durably append *payload* to this (org, source)'s own stream. Returns the new message id."""

    @abstractmethod
    async def ensure_consumer_group(
        self, org_id: uuid.UUID, source_id: str, group: str, *, start: str = "$"
    ) -> None:
        """Idempotently create *group* on this (org, source)'s stream if absent.

        ``start="$"`` (only new entries) is the real default for a normal
        long-lived consumer attaching going forward; pass ``start="0"`` to
        replay from the earliest retained entry instead (see this class's
        module docstring on replay scope: from the group's own start
        cursor, not an arbitrary historical timestamp -- Redis Streams has
        no native timestamp index).
        """

    @abstractmethod
    async def consume(
        self,
        org_id: uuid.UUID,
        source_id: str,
        group: str,
        consumer_name: str,
        *,
        count: int = 10,
        block_ms: int = 1000,
    ) -> list[StreamMessage]:
        """Read up to *count* new messages for *consumer_name* in *group*.

        Messages are delivered but NOT acknowledged -- call :meth:`ack`
        once processing genuinely succeeds (at-least-once: a message that
        is read but never acked will be redelivered, to this or another
        consumer, via :meth:`reclaim_stale`).
        """

    @abstractmethod
    async def ack(self, org_id: uuid.UUID, source_id: str, group: str, *message_ids: str) -> None:
        """Acknowledge successful processing, removing these ids from the group's pending list."""

    @abstractmethod
    async def reclaim_stale(
        self,
        org_id: uuid.UUID,
        source_id: str,
        group: str,
        claiming_consumer: str,
        *,
        min_idle_ms: int,
    ) -> list[StreamMessage]:
        """Reclaim messages pending for at least *min_idle_ms* (real, unacked
        for that long -- almost certainly a crashed/stuck consumer) for
        *claiming_consumer*. This is the real redelivery mechanism at-least-
        once delivery relies on; it does not run automatically -- a caller
        (a future beat task, mirroring this codebase's existing
        `abort_orphan_*` idiom) must invoke it periodically.
        """

    @abstractmethod
    async def approximate_length(self, org_id: uuid.UUID, source_id: str) -> int:
        """Real-time entry count for this (org, source)'s own stream (roadmap M3/D2).

        Deliberately NOT used to trim/drop anything itself -- this adapter
        never trims (see D3's own explicit warning that a MAXLEN trim of
        unsealed events is silent evidence loss, not a backpressure
        mechanism). Callers (CollectorIngestService) use this purely as a
        gauge to decide whether to reject *new* writes with a real,
        observable backpressure signal -- existing data is never touched.
        """


class RedisStreamIngestAdapter(StreamIngestAdapter):
    """Real Redis Streams implementation, verified against Redis 7.4.9.

    Requires a client constructed with ``decode_responses=False`` (the
    default) -- payloads are transported as raw bytes, never decoded as
    text, since this adapter is deliberately payload-agnostic (D4's job to
    interpret the bytes, not this transport's).
    """

    _FIELD = b"payload"

    def __init__(self, redis_client) -> None:  # type: ignore[no-untyped-def]
        # Constructor takes an already-configured redis.asyncio.Redis
        # instance (DB selection, connection pooling, etc. are the
        # caller's concern -- see src/external/startup.py for the real
        # DB-number convention already established for this shared Redis
        # instance: DB 0 step-up tickets, DB 1 Celery broker, DB 2 Celery
        # result backend -- stream data uses its own, separate DB).
        self._redis = redis_client

    def _key(self, org_id: uuid.UUID, source_id: str) -> str:
        return f"kronos:stream:{org_id}:{source_id}"

    async def produce(self, org_id: uuid.UUID, source_id: str, payload: bytes) -> str:
        message_id = await self._redis.xadd(self._key(org_id, source_id), {self._FIELD: payload})
        return message_id.decode() if isinstance(message_id, bytes) else str(message_id)

    async def ensure_consumer_group(
        self, org_id: uuid.UUID, source_id: str, group: str, *, start: str = "$"
    ) -> None:
        from redis.exceptions import ResponseError  # noqa: PLC0415

        try:
            await self._redis.xgroup_create(
                self._key(org_id, source_id), group, id=start, mkstream=True
            )
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def consume(
        self,
        org_id: uuid.UUID,
        source_id: str,
        group: str,
        consumer_name: str,
        *,
        count: int = 10,
        block_ms: int = 1000,
    ) -> list[StreamMessage]:
        key = self._key(org_id, source_id)
        resp = await self._redis.xreadgroup(
            group, consumer_name, {key: ">"}, count=count, block=block_ms
        )
        return [
            StreamMessage(
                message_id=mid.decode() if isinstance(mid, bytes) else str(mid),
                payload=fields[self._FIELD],
            )
            for _stream, entries in (resp or [])
            for mid, fields in entries
        ]

    async def ack(self, org_id: uuid.UUID, source_id: str, group: str, *message_ids: str) -> None:
        if not message_ids:
            return
        await self._redis.xack(self._key(org_id, source_id), group, *message_ids)

    async def reclaim_stale(
        self,
        org_id: uuid.UUID,
        source_id: str,
        group: str,
        claiming_consumer: str,
        *,
        min_idle_ms: int,
    ) -> list[StreamMessage]:
        key = self._key(org_id, source_id)
        _next_cursor, claimed_entries, *_ = await self._redis.xautoclaim(
            key, group, claiming_consumer, min_idle_time=min_idle_ms, start_id="0-0"
        )
        return [
            StreamMessage(
                message_id=mid.decode() if isinstance(mid, bytes) else str(mid),
                payload=fields[self._FIELD],
            )
            for mid, fields in claimed_entries
        ]

    async def approximate_length(self, org_id: uuid.UUID, source_id: str) -> int:
        return int(await self._redis.xlen(self._key(org_id, source_id)))


class InMemoryStreamIngestAdapter(StreamIngestAdapter):
    """Thread-unsafe in-memory stand-in for unit tests -- no real ack/redelivery
    semantics (no pending-entries-list simulation); tests that need to assert
    on those real Redis Streams behaviors belong in poc/stream_ingest_redis/,
    not here (mirrors InMemoryOpenSearchClient/InMemoryTaskQueue's own scope:
    a simple double for callers that just need *a* queue, not a Redis-Streams
    reimplementation)."""

    def __init__(self) -> None:
        self._streams: dict[str, list[StreamMessage]] = {}
        self._groups: dict[tuple[str, str], int] = {}  # (key, group) -> next unread index
        self._seq = 0

    def _key(self, org_id: uuid.UUID, source_id: str) -> str:
        return f"kronos:stream:{org_id}:{source_id}"

    async def produce(self, org_id: uuid.UUID, source_id: str, payload: bytes) -> str:
        self._seq += 1
        message_id = f"{self._seq}-0"
        self._streams.setdefault(self._key(org_id, source_id), []).append(
            StreamMessage(message_id=message_id, payload=payload)
        )
        return message_id

    async def ensure_consumer_group(
        self, org_id: uuid.UUID, source_id: str, group: str, *, start: str = "$"
    ) -> None:
        key = self._key(org_id, source_id)
        if (key, group) not in self._groups:
            existing = len(self._streams.get(key, [])) if start == "$" else 0
            self._groups[(key, group)] = existing

    async def consume(
        self,
        org_id: uuid.UUID,
        source_id: str,
        group: str,
        consumer_name: str,
        *,
        count: int = 10,
        block_ms: int = 1000,
    ) -> list[StreamMessage]:
        key = self._key(org_id, source_id)
        if (key, group) not in self._groups:
            raise KeyError(f"NOGROUP: no such key {key!r} or consumer group {group!r}")
        cursor = self._groups[(key, group)]
        messages = self._streams.get(key, [])[cursor : cursor + count]
        self._groups[(key, group)] = cursor + len(messages)
        return messages

    async def ack(self, org_id: uuid.UUID, source_id: str, group: str, *message_ids: str) -> None:
        pass  # no pending-list simulation in this simple double

    async def reclaim_stale(
        self,
        org_id: uuid.UUID,
        source_id: str,
        group: str,
        claiming_consumer: str,
        *,
        min_idle_ms: int,
    ) -> list[StreamMessage]:
        return []

    async def approximate_length(self, org_id: uuid.UUID, source_id: str) -> int:
        return len(self._streams.get(self._key(org_id, source_id), []))
