"""SuricataEvePushSource / ZeekJsonPushSource: live-tail source connectors
for Suricata's ``eve.json`` and Zeek's default-JSON per-log-type files
(roadmap Q3), reusing Q1's ``IntegrationSource`` foundation.

**Real mechanism, verified before writing this module (CLAUDE.md SS F).**
Neither Suricata nor Zeek exposes a separate "live alert" API -- their
`eve.json`/per-log-type JSON files (``conn.log``, ``notice.log``, ...) *are*
the real-time stream, and the documented, standard way to forward them in
real time is a log-shipper tailing the file -- this repo's own
``docker/fluent-bit/fluent-bit.conf`` already does exactly this for
KronOS's own logs (``tail`` input -> various outputs), which this connector
reuses as the real forwarding mechanism rather than inventing a second one.

**Real fluent-bit 3.1 wire format, captured not assumed
(``poc/integration_source_suricata_zeek/output.txt``).** A real
``fluent/fluent-bit:3.1`` container, configured with a real ``tail`` input
(``Parser json``, which requires ``Parsers_File`` to be set in
``[SERVICE]`` -- omitting it, as this repo's own existing
``docker/fluent-bit/fluent-bit.conf`` does, makes fluent-bit log
``parser 'json' is not registered`` and silently skip JSON decoding; a real,
previously-unverified gap in that file, flagged here per CLAUDE.md SS F,
not fixed since that file is a different subsystem's dormant config) and a
real ``http`` output with ``Format json_lines``, was pointed at a real
stub HTTP receiver. Captured, real result: the request's
``Content-Type`` is ``application/x-ndjson`` and the body is real
newline-delimited JSON -- **one JSON object per originally-tailed log
line, with fluent-bit's own ``date`` field (its ingestion timestamp,
``json_date_key``'s default name) prepended to each object** -- and when
two lines are appended within one flush window, **both land as two
NDJSON lines in a single POST body**, not a JSON array and not two
separate requests. This is structurally the exact same shape
``SuricataEveParser.parse()`` (``src/external/parsers/suricata.py``)
already parses for the batch-file case (NDJSON, one object per line) --
this module's ``_TailedNdjsonPushSource.parse_push_event`` below reuses
that same split-by-newline logic (independently reimplemented at this
layer, since ``ForensicParser.parse()`` operates on an
``AsyncIterator[bytes]``/``Evidence`` this ABC does not have per
``IntegrationSource``'s own module docstring -- but the underlying
algorithm, "split on ``\\n``, skip blank lines, decode each remainder as
one JSON object," is unchanged and intentionally identical) rather than
assuming a vendor-specific batch envelope the way
``GenericWebhookPushSource`` does.

**Two concrete classes, not one, and why.** Suricata's ``eve.json`` and
Zeek's ``conn.log`` are tailed as two separate files with two separate
``tail`` inputs (different real per-line schemas), forwarded to two
different KronOS push routes (``IntegrationSourceRegistry`` dispatches by
an exact ``source_type`` URL segment, never by sniffing -- see
``IntegrationSource``'s own module docstring) -- so two ``source_type``
values are structurally required regardless of class layout. The two
classes below share the real, verified NDJSON-splitting behavior via a
common private base (`_TailedNdjsonPushSource`) and differ only in their
per-line structural validation, mirroring ``ZipArchiveParser``/
``PlasoParser``'s own precedent of one real shared algorithm, format-
specific validation on top -- not a parallel ABC hierarchy (CLAUDE.md SS
G.1's standing rule is about a second *interface*, not an internal base
class within one).

**ECS mapping is a separate, later step (unchanged from Q1/Q2's own
design).** Neither PUSH-source class below maps to ECS fields -- per
``src/application/integration_source.py``'s own "why fetch is separate
from mapping" argument, that is ``StreamSourceNormalizer``'s job, run
later by ``StreamNormalizationService`` once a real ``SealedBatch`` exists.

**Why ``SuricataEveStreamNormalizer`` lives in this module, not next to
``ZeekConnLogNormalizer``/``WazuhAlertNormalizer`` (a real layering finding,
not a stylistic choice).** Those two normalizers live in
``src/application/stream_source_registry.py`` because they are fully
self-contained (no imports beyond stdlib/pydantic/``src.exceptions``) --
legal in the Application layer per CLAUDE.md SS A.3. Reusing
``SuricataEveParser``'s already-proven ECS mapping (its static
``_build_message``/``_build_extra`` helpers, its
``_ECS_BY_EVENT_TYPE``/``_DEFAULT_ECS`` lookup table) by import -- as this
roadmap item's own brief explicitly directs, rather than re-deriving/
copy-pasting it -- means importing from ``src.external.parsers.suricata``,
which is only legal from *this*, the External layer (CLAUDE.md SS A.3:
Application must not import External). ``SuricataEveStreamNormalizer``
therefore lives here instead, and is wired into a registry via
``register_suricata_zeek_normalizers()`` below rather than by editing
``get_default_stream_normalizer_registry()`` itself (that function is
Application-layer and importing this module into it would reintroduce the
exact same violation) -- callers needing the full normalizer set call both:
``registry = get_default_stream_normalizer_registry()`` then
``register_suricata_zeek_normalizers(registry)``.
Zeek's normalizer needs no such treatment: ``ZeekConnLogNormalizer``
already existed before this pass (roadmap D4) and is already registered by
``get_default_stream_normalizer_registry()`` -- this module's
``ZeekJsonPushSource`` deliberately provisions/expects
``source_id="zeek-conn-log"`` so it resolves to that exact, already-proven
normalizer with zero new normalizer code.
"""

from __future__ import annotations

import json
import logging
from abc import abstractmethod
from datetime import datetime

from src.application.integration_source import IntegrationSource
from src.application.stream_source_registry import (
    NormalizedStreamEvent,
    StreamSourceNormalizer,
    StreamSourceNormalizerRegistry,
)
from src.domain.integration_source import IntegrationDeliveryMode
from src.exceptions import ParsingError
from src.external.parsers.suricata import _DEFAULT_ECS, _ECS_BY_EVENT_TYPE, SuricataEveParser

logger = logging.getLogger(__name__)


class _TailedNdjsonPushSource(IntegrationSource):
    """Shared PUSH behavior for a fluent-bit-tailed, NDJSON-shaped log file.

    Not itself registered under any ``source_type`` -- subclasses supply
    that plus their own per-line structural validation. See this module's
    own docstring for the real, captured fluent-bit 3.1 wire format this
    splitting logic was verified against.
    """

    @property
    def delivery_mode(self) -> IntegrationDeliveryMode:
        return IntegrationDeliveryMode.PUSH

    async def parse_push_event(self, raw_body: bytes) -> list[bytes]:
        """Split one fluent-bit ``http`` output POST body into its
        individual NDJSON lines, validating each is real, well-formed JSON
        for this connector's own format.

        Raises :class:`~src.exceptions.ParsingError` (CLAUDE.md invariant
        #8 -- fail loudly) if the body contains no valid line at all -- a
        misconfigured fluent-bit route pointed at the wrong ``source_type``
        should be a loud, observable failure, not a silently-accepted
        empty batch.
        """
        events: list[bytes] = []
        for raw_line in raw_body.split(b"\n"):
            line = raw_line.strip()
            if not line:
                continue
            self._validate_line(line)
            events.append(line)

        if not events:
            raise ParsingError(
                f"{self.source_type} push body contained no valid NDJSON line",
                context={"source_type": self.source_type, "body_length": len(raw_body)},
            )
        return events

    @abstractmethod
    def _validate_line(self, line: bytes) -> None:
        """Raise :class:`~src.exceptions.ParsingError` if *line* is not a
        real event for this connector's format."""


class SuricataEvePushSource(_TailedNdjsonPushSource):
    """PUSH source for Suricata's ``eve.json`` live-tail (roadmap Q3).

    Every real EVE JSON line, of any ``event_type``, carries a top-level
    ``event_type`` field -- confirmed against Suricata's own userguide
    (``doc/userguide/output/eve/eve-json-format.rst`` at tag
    ``suricata-8.0.6``, the same reference ``SuricataEveParser`` already
    cites) and against the real captured sample this repo already ships
    (``tests/fixtures/samples/real/suricata/eve.json``, six real lines
    spanning ``fileinfo``/``alert``/``http``/``anomaly``/``flow``). Unlike
    ``SuricataEveParser.supports()``'s own header-sniff heuristic (which
    additionally requires ``flow_id`` to disambiguate file *detection* from
    other JSON formats), this connector does not require ``flow_id``:
    periodic ``stats``/``engine`` EVE lines carry no 5-tuple/``flow_id`` at
    all but are still real, valid EVE JSON this connector must accept, not
    reject -- ``event_type`` alone is the one field verified present on
    every real EVE line regardless of type.
    """

    @property
    def source_type(self) -> str:
        return "suricata-eve"

    @property
    def source_version(self) -> str:
        return "1.0.0"

    def _validate_line(self, line: bytes) -> None:
        try:
            decoded = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ParsingError(
                "Suricata eve.json push line is not valid JSON",
                context={"source_type": self.source_type, "error": str(exc)},
            ) from exc
        if not isinstance(decoded, dict) or "event_type" not in decoded:
            raise ParsingError(
                "Suricata eve.json push line is missing required 'event_type' field "
                "-- not a real EVE JSON line",
                context={"source_type": self.source_type},
            )


class ZeekJsonPushSource(_TailedNdjsonPushSource):
    """PUSH source for Zeek's default-JSON log-writer output live-tail
    (roadmap Q3) -- ``conn.log`` in this pass (see this module's own
    docstring for why ``notice.log`` was not additionally built).

    Every real Zeek JSON log line carries a top-level ``ts`` field (Zeek
    type ``time``, the event's own timestamp) regardless of log type --
    confirmed against Zeek's own source
    (``scripts/base/protocols/conn/main.zeek``'s ``Conn::Info`` record doc
    comments, the same reference ``ZeekConnLogNormalizer`` already cites).
    Deliberately provisions/expects ``source_id="zeek-conn-log"`` (see
    ``src/external/middleware/integration_source_auth.py``'s
    ``StaticApiKeyProvisioning`` -- the operator provisioning a real key
    for this connector must set that exact ``source_id``) so
    ``StreamSourceNormalizerRegistry.for_source()`` resolves to the
    already-existing, already-proven ``ZeekConnLogNormalizer``
    (``src/application/stream_source_registry.py``) with zero new
    normalizer code -- reuse, not a rewrite, mirroring this roadmap
    section's own instruction for the Suricata half.
    """

    @property
    def source_type(self) -> str:
        return "zeek-conn-log"

    @property
    def source_version(self) -> str:
        return "1.0.0"

    def _validate_line(self, line: bytes) -> None:
        try:
            decoded = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ParsingError(
                "Zeek JSON push line is not valid JSON",
                context={"source_type": self.source_type, "error": str(exc)},
            ) from exc
        if not isinstance(decoded, dict) or "ts" not in decoded:
            raise ParsingError(
                "Zeek JSON push line is missing required 'ts' field -- not a real "
                "Zeek default-JSON log line",
                context={"source_type": self.source_type},
            )


class SuricataEveStreamNormalizer(StreamSourceNormalizer):
    """Normalizes one real Suricata EVE JSON line (roadmap Q3) into
    ECS-shaped fields, for the live-tail push path.

    **Reuses ``SuricataEveParser``'s own already-proven mapping, not a
    reimplementation.** ``_ECS_BY_EVENT_TYPE``/``_DEFAULT_ECS`` (the
    event_type -> (kind, category, type) table) and the static
    ``_build_message``/``_build_extra`` helpers are imported directly from
    ``src.external.parsers.suricata`` -- the exact same code
    ``SuricataEveParser.parse()`` already uses for the batch-file case,
    field-reference-verified against Suricata's own userguide at tag
    ``suricata-8.0.6`` (see that module's own docstring). See this module's
    own top-level docstring for why this class lives here rather than
    alongside ``ZeekConnLogNormalizer``/``WazuhAlertNormalizer``.

    One deliberate divergence from ``SuricataEveParser._to_timeline_record``:
    that method silently falls back to ``datetime.now(UTC)`` on an
    unparsable ``timestamp`` (acceptable for a best-effort file parse where
    *some* record is better than none); this normalizer instead raises
    ``ParsingError`` on a missing/invalid timestamp, matching
    ``WazuhAlertNormalizer``/``ZeekConnLogNormalizer``'s own stricter
    "fail loudly on a required field" convention for the live stream path
    (CLAUDE.md invariant #8) -- a live connector silently fabricating an
    ingest-time timestamp for a real EVE line would be a real forensic-
    accuracy bug, not a benign fallback.
    """

    @property
    def source_id(self) -> str:
        return "suricata-eve"

    @property
    def normalizer_version(self) -> str:
        return "1.0.0"

    def normalize(self, payload: bytes) -> NormalizedStreamEvent:
        try:
            doc = json.loads(payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ParsingError(
                "Suricata eve.json payload is not valid JSON",
                context={"source_id": self.source_id, "error": str(exc)},
            ) from exc

        if not isinstance(doc, dict):
            raise ParsingError(
                "Suricata eve.json payload did not decode to a JSON object",
                context={"source_id": self.source_id, "decoded_type": type(doc).__name__},
            )

        event_type = str(doc.get("event_type", ""))

        try:
            timestamp = datetime.fromisoformat(str(doc["timestamp"]))
        except (KeyError, ValueError) as exc:
            raise ParsingError(
                "Suricata eve.json event missing/invalid required 'timestamp' field",
                context={"source_id": self.source_id, "error": str(exc)},
            ) from exc

        kind, category, event_type_list = _ECS_BY_EVENT_TYPE.get(event_type, _DEFAULT_ECS)
        message = SuricataEveParser._build_message(event_type, doc)
        extra = SuricataEveParser._build_extra(doc)

        return NormalizedStreamEvent(
            timestamp=timestamp,
            message=message,
            event_kind=kind,
            event_category=list(category),
            event_type=list(event_type_list),
            event_original=json.dumps(doc, sort_keys=True)[:32768],
            extra=extra,
        )


def register_suricata_zeek_normalizers(registry: StreamSourceNormalizerRegistry) -> None:
    """Register this roadmap Q3 pass's own new normalizer into *registry*.

    Deliberately not folded into ``get_default_stream_normalizer_registry()``
    (``src/application/stream_source_registry.py``) -- see this module's own
    top-level docstring for the real layering reason (that function is
    Application-layer and cannot import this, an External-layer module,
    without violating CLAUDE.md SS A.3). Zeek needs no equivalent call here:
    ``ZeekConnLogNormalizer`` is already registered by
    ``get_default_stream_normalizer_registry()`` itself and
    ``ZeekJsonPushSource`` reuses it unchanged.
    """
    registry.register(SuricataEveStreamNormalizer())
