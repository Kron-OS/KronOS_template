"""Registry mapping a stream ``source_id`` to the ``StreamSourceNormalizer``
that knows how to turn its raw wire payloads into ECS-shaped fields
(roadmap M3/D4).

Sibling to ``ecs_field_registry.py``'s ``FieldMapping``/``ECSFieldMappingRegistry``,
one layer earlier in the pipeline: ``FieldMapping`` translates an
already-parsed record's raw field *names* to ECS paths; a
``StreamSourceNormalizer`` parses a raw, not-yet-structured telemetry
payload (bytes decoded out of a sealed batch's WORM manifest) into ECS
fields in the first place, since a stream event has no upstream
``ForensicParser`` step to have already done that. Extensible the same way:
a new source registers its own ``StreamSourceNormalizer`` in
``get_default_stream_normalizer_registry()``; no edits to existing
normalizers or to the registry class itself are required.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field

from src.exceptions import ParsingError


class NormalizedStreamEvent(BaseModel):
    """ECS-shaped fields extracted from one raw stream-event payload.

    Mirrors ``TimelineRecord``'s own flattened field set, excluding
    ``document_id`` and ``kronos`` -- ``StreamNormalizationService`` fills
    those in once it knows the owning ``SealedBatch``/``event_offset``, which
    a normalizer (parsing one payload in isolation) cannot know. Fields not
    already a first-class ``TimelineRecord`` column (e.g. ``source.ip``,
    ``network.transport``) go in ``extra`` as ECS-dotted keys, the exact
    convention every existing parser already uses (see
    ``src/external/parsers/suricata.py``).
    """

    model_config = {"frozen": True}

    timestamp: datetime
    message: str | None = None
    event_kind: str | None = None
    event_category: list[str] = Field(default_factory=list)
    event_type: list[str] = Field(default_factory=list)
    event_outcome: str | None = None
    event_original: str | None = None
    host_name: str | None = None
    host_os_name: str | None = None
    user_name: str | None = None
    user_id: str | None = None
    process_pid: int | None = None
    process_name: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)


class StreamSourceNormalizer(ABC):
    """Turns one raw stream-event payload into ECS-shaped fields."""

    @property
    @abstractmethod
    def source_id(self) -> str:
        """The ``StreamProvenance.source_id`` / D1 stream-key component this
        normalizer knows how to parse, e.g. ``'zeek-conn-log'``.

        Documented simplification: the registry keys on this exact string,
        the same one used for the Redis stream key and
        ``SealedBatch.source_id`` (D1/D2's own convention -- their own tests
        already use a plain format name like ``'zeek-conn-log'``, not a
        per-host-suffixed id such as D2's own
        ``'edr-vendor-x-host42'`` example). A deployment running many
        physical collectors of the same *format* under distinct per-host
        ``source_id``s would need a prefix or source-type-field lookup
        instead of this exact match -- flagged as follow-up, not needed for
        this pass's one concrete source.
        """

    @property
    @abstractmethod
    def normalizer_version(self) -> str:
        """Semver string, e.g. ``'1.0.0'`` -- written into ``kronos.parser_version``."""

    @abstractmethod
    def normalize(self, payload: bytes) -> NormalizedStreamEvent:
        """Parse one raw event payload into ECS-shaped fields.

        Raises:
            ParsingError: if the payload cannot be parsed for this source.
        """


class StreamSourceNormalizerRegistry:
    """Collects ``StreamSourceNormalizer`` instances, keyed by ``source_id``.

    DI-registered, not a hardcoded if/elif lookup -- mirrors
    ``ECSFieldMappingRegistry`` exactly.
    """

    def __init__(self) -> None:
        self._normalizers: dict[str, StreamSourceNormalizer] = {}

    def register(self, normalizer: StreamSourceNormalizer) -> None:
        self._normalizers[normalizer.source_id] = normalizer

    def for_source(self, source_id: str) -> StreamSourceNormalizer | None:
        return self._normalizers.get(source_id)


class ZeekConnLogNormalizer(StreamSourceNormalizer):
    """Normalizes Zeek's default JSON ``conn.log`` output (roadmap D4).

    Field reference verified against Zeek's own source
    (``raw.githubusercontent.com/zeek/zeek``,
    ``scripts/base/protocols/conn/main.zeek``'s ``Conn::Info`` record doc
    comments -- see ``poc/stream_normalization/README.md`` for the exact
    fetched text) rather than guessed from memory:

    - ``ts`` (Zeek type ``time``) -> ``@timestamp``. Zeek's JSON writer
      serializes this as a Unix epoch in seconds (float, fractional
      seconds) -- confirmed from the field's own doc comment ("the time of
      the first packet").
    - ``id.orig_h``/``id.orig_p`` -> ``source.ip``/``source.port`` (the
      connection originator's 4-tuple half).
    - ``id.resp_h``/``id.resp_p`` -> ``destination.ip``/``destination.port``
      (the responder's half).
    - ``proto`` (Zeek type ``transport_proto``, e.g. ``"tcp"``/``"udp"``/
      ``"icmp"``) -> ``network.transport``.
    - ``service`` (confirmed application-layer protocol, e.g. ``"dns"``/
      ``"http"``) -> ``network.protocol``.
    - ``duration`` (Zeek type ``interval`` -- JSON-serialized in *seconds*,
      float, per the field's own doc comment about "connection lifetime")
      -> ``event.duration``, which per ECS is nanoseconds (``long``) --
      genuinely converted (``round(duration * 1_000_000_000)``), not just
      renamed; this unit mismatch is exactly the kind of silent bug
      Section F exists to catch.
    - ``orig_bytes``/``resp_bytes`` (Zeek doc: "payload bytes the
      originator/responder sent") -> ``source.bytes``/``destination.bytes``.

    ``uid``, ``conn_state``, ``history``, ``orig_pkts``, ``resp_pkts`` and
    the rest of Zeek's own fields are preserved verbatim under
    ``extra["zeek.conn.*"]`` -- not dropped, just not (yet) promoted to core
    ECS fields (no ECS field for Zeek's own connection-state codes exists).
    """

    @property
    def source_id(self) -> str:
        return "zeek-conn-log"

    @property
    def normalizer_version(self) -> str:
        return "1.0.0"

    def normalize(self, payload: bytes) -> NormalizedStreamEvent:
        try:
            doc = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ParsingError(
                "Zeek conn.log payload is not valid JSON",
                context={"source_id": self.source_id, "error": str(exc)},
            ) from exc

        if not isinstance(doc, dict):
            raise ParsingError(
                "Zeek conn.log payload did not decode to a JSON object",
                context={"source_id": self.source_id, "decoded_type": type(doc).__name__},
            )

        try:
            ts = float(doc["ts"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ParsingError(
                "Zeek conn.log event missing/invalid required 'ts' field",
                context={"source_id": self.source_id, "error": str(exc)},
            ) from exc
        timestamp = datetime.fromtimestamp(ts, tz=UTC)

        # Zeek's JSON writer flattens the nested conn_id record to dotted
        # top-level keys (id.orig_h, id.orig_p, id.resp_h, id.resp_p) by
        # default -- also tolerate a nested {"id": {"orig_h": ...}} shape
        # defensively, since some downstream JSON re-shapers (e.g. Filebeat)
        # un-flatten it.
        nested_id = doc.get("id")
        nested_id = nested_id if isinstance(nested_id, dict) else {}
        orig_h = nested_id.get("orig_h", doc.get("id.orig_h"))
        orig_p = nested_id.get("orig_p", doc.get("id.orig_p"))
        resp_h = nested_id.get("resp_h", doc.get("id.resp_h"))
        resp_p = nested_id.get("resp_p", doc.get("id.resp_p"))

        extra: dict[str, Any] = {}
        if orig_h is not None:
            extra["source.ip"] = orig_h
        if orig_p is not None:
            extra["source.port"] = int(orig_p)
        if resp_h is not None:
            extra["destination.ip"] = resp_h
        if resp_p is not None:
            extra["destination.port"] = int(resp_p)

        proto = doc.get("proto")
        if proto is not None:
            extra["network.transport"] = proto

        service = doc.get("service")
        if service:
            extra["network.protocol"] = service

        duration = doc.get("duration")
        if duration is not None:
            extra["event.duration"] = round(float(duration) * 1_000_000_000)

        orig_bytes = doc.get("orig_bytes")
        if orig_bytes is not None:
            extra["source.bytes"] = int(orig_bytes)
        resp_bytes = doc.get("resp_bytes")
        if resp_bytes is not None:
            extra["destination.bytes"] = int(resp_bytes)

        for zeek_field in (
            "uid",
            "conn_state",
            "history",
            "orig_pkts",
            "resp_pkts",
            "local_orig",
            "local_resp",
            "missed_bytes",
        ):
            if zeek_field in doc:
                extra[f"zeek.conn.{zeek_field}"] = doc[zeek_field]

        message = None
        if orig_h is not None and resp_h is not None:
            message = f"{orig_h}:{orig_p} -> {resp_h}:{resp_p} ({proto})"

        return NormalizedStreamEvent(
            timestamp=timestamp,
            message=message,
            event_kind="event",
            event_category=["network"],
            event_type=["connection"],
            extra=extra,
        )


def get_default_stream_normalizer_registry() -> StreamSourceNormalizerRegistry:
    registry = StreamSourceNormalizerRegistry()
    registry.register(ZeekConnLogNormalizer())
    return registry
