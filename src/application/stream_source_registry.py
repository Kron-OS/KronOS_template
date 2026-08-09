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


class WazuhAlertNormalizer(StreamSourceNormalizer):
    """Normalizes a real Wazuh alert JSON object (roadmap Q2) into ECS-shaped
    fields.

    Field reference verified against a real alert captured from a real,
    running ``wazuh/wazuh-manager:4.14.7`` container (a genuine local
    ``sshd`` failed-login rule match) -- see
    ``poc/integration_source_wazuh/output.txt`` for the exact captured JSON
    this mapping was built from, per CLAUDE.md SS F (never mapped from memory
    or vendor docs alone):

    - ``timestamp`` (ISO-8601 with a numeric UTC offset, e.g.
      ``"2026-08-09T04:02:30.663+0000"``) -> ``@timestamp``.
    - ``full_log`` (the original, pre-decode raw log line Wazuh matched --
      present for syslog-decoded alerts; absent for structural sources like
      SCA summaries) -> ``message``, falling back to ``rule.description``
      when absent so every alert still gets a real, non-empty message.
    - Every real Wazuh alert is, by definition, an already-fired detection
      (there is no "informational, non-alert" telemetry in ``alerts.json`` --
      unmatched log lines never reach it at all) -> ``event_kind = "alert"``,
      mirroring ``SuricataEveParser``'s own identical ``"alert"`` mapping for
      its own analogous ``event_type == "alert"`` case.
    - ``rule.groups`` containing ``"authentication_failed"``/
      ``"authentication_success"`` (Wazuh's own real, documented rule-group
      taxonomy) additionally promotes ``event.category`` to include ECS's
      own ``"authentication"`` value and sets a real ``event.outcome``/
      ``event.type`` accordingly; every other alert gets the safe baseline
      ECS category ``"intrusion_detection"`` (Wazuh is fundamentally a
      HIDS/log-correlation detection engine, the same reasoning
      ``SuricataEveParser`` already applied to its own IDS ``"alert"`` case)
      and ``event.type = ["info"]``.
    - ``agent.name`` -> ``host_name`` (the Wazuh *agent* is the monitored
      host; ``manager.name`` -- the Wazuh server itself -- is preserved
      separately under ``extra["wazuh.manager.name"]``, never conflated with
      the monitored host).
    - ``data.srcuser``/``data.srcip`` (present on decoder-parsed alerts with
      a recognizable actor/source, e.g. the real captured ``sshd`` alert) ->
      ``user_name``/``extra["source.ip"]``. Both are genuinely optional --
      structural alerts (SCA summaries, ``ossec`` lifecycle events) have no
      ``data.srcuser``/``data.srcip`` at all, confirmed by the real captured
      output, so both are only set when present.
    - ``rule.id``/``rule.level``/``rule.groups``/``rule.firedtimes``,
      ``agent.id``, ``decoder.name``, ``location`` preserved verbatim under
      ``extra["wazuh.*"]`` -- not dropped, mirroring every other parser's own
      "no ECS field exists for this, namespace it" convention.
    """

    _AUTH_FAILURE_GROUP = "authentication_failed"
    _AUTH_SUCCESS_GROUP = "authentication_success"

    @property
    def source_id(self) -> str:
        return "wazuh"

    @property
    def normalizer_version(self) -> str:
        return "1.0.0"

    def normalize(self, payload: bytes) -> NormalizedStreamEvent:
        try:
            doc = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ParsingError(
                "Wazuh alert payload is not valid JSON",
                context={"source_id": self.source_id, "error": str(exc)},
            ) from exc

        if not isinstance(doc, dict):
            raise ParsingError(
                "Wazuh alert payload did not decode to a JSON object",
                context={"source_id": self.source_id, "decoded_type": type(doc).__name__},
            )

        rule = doc.get("rule")
        rule = rule if isinstance(rule, dict) else {}

        try:
            timestamp = datetime.fromisoformat(str(doc["timestamp"]))
        except (KeyError, ValueError) as exc:
            raise ParsingError(
                "Wazuh alert missing/invalid required 'timestamp' field",
                context={"source_id": self.source_id, "error": str(exc)},
            ) from exc

        groups: list[str] = [g for g in rule.get("groups", []) if isinstance(g, str)]

        event_category = ["intrusion_detection"]
        event_type = ["info"]
        event_outcome: str | None = None
        if self._AUTH_FAILURE_GROUP in groups:
            event_category.append("authentication")
            event_type = ["denied"]
            event_outcome = "failure"
        elif self._AUTH_SUCCESS_GROUP in groups:
            event_category.append("authentication")
            event_type = ["allowed"]
            event_outcome = "success"

        message = doc.get("full_log") or rule.get("description")

        agent = doc.get("agent")
        agent = agent if isinstance(agent, dict) else {}
        manager = doc.get("manager")
        manager = manager if isinstance(manager, dict) else {}
        data = doc.get("data")
        data = data if isinstance(data, dict) else {}
        decoder = doc.get("decoder")
        decoder = decoder if isinstance(decoder, dict) else {}

        extra: dict[str, Any] = {
            "wazuh.rule.id": rule.get("id"),
            "wazuh.rule.level": rule.get("level"),
            "wazuh.rule.groups": groups,
            "wazuh.rule.firedtimes": rule.get("firedtimes"),
            "wazuh.agent.id": agent.get("id"),
            "wazuh.manager.name": manager.get("name"),
            "wazuh.decoder.name": decoder.get("name"),
            "wazuh.location": doc.get("location"),
        }
        src_ip = data.get("srcip")
        if src_ip is not None:
            extra["source.ip"] = src_ip

        return NormalizedStreamEvent(
            timestamp=timestamp,
            message=str(message) if message is not None else None,
            event_kind="alert",
            event_category=event_category,
            event_type=event_type,
            event_outcome=event_outcome,
            event_original=json.dumps(doc, sort_keys=True)[:32768],
            host_name=agent.get("name"),
            user_name=data.get("srcuser"),
            extra=extra,
        )


class DefenderAlertNormalizer(StreamSourceNormalizer):
    """Normalizes a real Microsoft Graph Security API ``alerts_v2`` alert
    object (roadmap Q4) into ECS-shaped fields.

    Field reference verified against Microsoft's own current documented
    resource shape (`alert resource type
    <https://learn.microsoft.com/en-us/graph/api/resources/security-alert?view=graph-rest-1.0>`_,
    fetched 2026-08-09), including its own full worked JSON example -- see
    ``src/external/integration_sources/defender.py``'s own module docstring
    for the full doc-verification trail (including the real
    ``lastUpdateDateTime`` vs. this roadmap's own originally-assumed
    ``lastUpdateTime`` naming correction) and
    ``poc/integration_source_defender/output.txt`` for the exact captured
    fixture alert this mapping was exercised against:

    - ``lastUpdateDateTime`` (the real, documented cursor property this
      connector polls by -- ``DateTimeOffset``, ISO-8601) -> ``@timestamp``.
      Deliberately not ``createdDateTime``: an alert can be updated
      (reclassified, reassigned, evidence added) long after creation, and
      the timeline record should reflect what changed most recently, the
      same reasoning the connector's own cursor uses.
    - ``title``, falling back to ``description`` when absent -> ``message``,
      mirroring ``WazuhAlertNormalizer``'s own "always produce a real,
      non-empty message" idiom (``full_log`` -> ``rule.description``).
    - Every real ``alerts_v2`` entry is, by definition, an already-fired
      detection (there is no "informational, non-alert" resource under this
      endpoint) -> ``event_kind = "alert"``, ``event_category =
      ["intrusion_detection"]``, ``event_type = ["info"]`` -- the same safe,
      generic EDR/XDR baseline ``WazuhAlertNormalizer`` uses for its own
      analogous case, since Defender's real ``serviceSource`` values
      (``microsoftDefenderForEndpoint``, ``microsoftDefenderForIdentity``,
      ``microsoftDefenderForCloudApps``, ``microsoftSentinel``, etc.) don't
      map to a single more-specific ECS category without a speculative
      per-source-product table this pass does not invent.
    - ``id``, ``providerAlertId``, ``incidentId``, ``status``, ``severity``,
      ``classification``, ``determination``, ``serviceSource``,
      ``detectionSource``, ``categories``, ``mitreTechniques``, ``tenantId``,
      ``alertWebUrl`` preserved verbatim under ``extra["ms_defender.*"]`` --
      not dropped, mirroring every other normalizer's own "no ECS field
      exists for this, namespace it" convention.
    - ``evidence`` (the alert's own device/file/process/registry-key entity
      collection) is preserved verbatim, unflattened, under
      ``extra["ms_defender.evidence"]`` -- deliberately conservative, not an
      oversight: it is genuinely artifact-shaped
      (``StructuredArtifact``-shaped, not timeline-event-shaped), and this
      normalizer's own return type (``NormalizedStreamEvent``) has no
      artifact-shaped counterpart yet (the real, named, still-open gap
      ``src/application/integration_source.py``'s own module docstring
      flags for exactly this connector). ``host_name``/``user_name`` are
      therefore left unset here rather than fragile-parsed out of one
      evidence subtype among several real, heterogeneous ones
      (``deviceEvidence``, ``userEvidence``, ``processEvidence``, ...).
    """

    @property
    def source_id(self) -> str:
        return "ms-defender-alerts"

    @property
    def normalizer_version(self) -> str:
        return "1.0.0"

    def normalize(self, payload: bytes) -> NormalizedStreamEvent:
        try:
            doc = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ParsingError(
                "Defender alert payload is not valid JSON",
                context={"source_id": self.source_id, "error": str(exc)},
            ) from exc

        if not isinstance(doc, dict):
            raise ParsingError(
                "Defender alert payload did not decode to a JSON object",
                context={"source_id": self.source_id, "decoded_type": type(doc).__name__},
            )

        try:
            timestamp = datetime.fromisoformat(str(doc["lastUpdateDateTime"]))
        except (KeyError, ValueError) as exc:
            raise ParsingError(
                "Defender alert missing/invalid required 'lastUpdateDateTime' field",
                context={"source_id": self.source_id, "error": str(exc)},
            ) from exc

        message = doc.get("title") or doc.get("description")

        extra: dict[str, Any] = {
            "ms_defender.id": doc.get("id"),
            "ms_defender.provider_alert_id": doc.get("providerAlertId"),
            "ms_defender.incident_id": doc.get("incidentId"),
            "ms_defender.status": doc.get("status"),
            "ms_defender.severity": doc.get("severity"),
            "ms_defender.classification": doc.get("classification"),
            "ms_defender.determination": doc.get("determination"),
            "ms_defender.service_source": doc.get("serviceSource"),
            "ms_defender.detection_source": doc.get("detectionSource"),
            "ms_defender.categories": doc.get("categories", []),
            "ms_defender.mitre_techniques": doc.get("mitreTechniques", []),
            "ms_defender.tenant_id": doc.get("tenantId"),
            "ms_defender.alert_web_url": doc.get("alertWebUrl"),
            "ms_defender.evidence": doc.get("evidence", []),
        }

        return NormalizedStreamEvent(
            timestamp=timestamp,
            message=str(message) if message is not None else None,
            event_kind="alert",
            event_category=["intrusion_detection"],
            event_type=["info"],
            event_original=json.dumps(doc, sort_keys=True)[:32768],
            extra=extra,
        )


def get_default_stream_normalizer_registry() -> StreamSourceNormalizerRegistry:
    registry = StreamSourceNormalizerRegistry()
    registry.register(ZeekConnLogNormalizer())
    registry.register(WazuhAlertNormalizer())
    registry.register(DefenderAlertNormalizer())
    return registry
