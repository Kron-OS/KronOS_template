"""SplunkHecSink: real Splunk HTTP Event Collector (HEC) transport
(KAFKA_AND_INTEGRATIONS_ROADMAP.md R2 -- "Splunk HEC sink connector").

**Why this is a sibling ``IntegrationSink``, not a subclass/config of
``HttpJsonIntegrationSink`` (the roadmap R2 brief's own explicit
design-decision question).** Real HEC's wire contract, verified against the
official Splunk docs for the pinned Splunk Enterprise 9.3.x doc set
(``docs.splunk.com/Documentation/Splunk/9.3.3/Data/FormateventsforHTTPEventCollector``
and ``.../TroubleshootHTTPEventCollector``, both fetched and read directly
this pass -- see ``poc/integration_sink_splunk_hec/README.md`` for the
captured excerpts), differs from ``HttpJsonIntegrationSink``'s generic
envelope in two structural ways that make a subclass strictly worse than a
sibling:

1. **Batching is NOT a JSON array.** ``HttpJsonIntegrationSink`` sends
   ``{"events": [payload, payload, ...]}`` -- a deliberately generic,
   non-vendor-specific shape (its own module docstring says so explicitly).
   Real HEC's documented batch protocol is the opposite: "event objects
   stacked one after the other, and **not** in a JSON array" -- i.e. the
   real wire body for N events is ``{...}{...}{...}`` (concatenated,
   standalone JSON objects, no commas, no wrapping brackets). Sending a
   real HEC endpoint ``{"events": [...]}`` would not be parsed as N events
   at all.
2. **The real success/failure signal is a single whole-batch
   ``{"text": ..., "code": ...}`` pair, never a per-event "accepted"
   tally.** ``HttpJsonIntegrationSink`` treats a 2xx response with no
   ``accepted`` count (or a mismatched one) as a real failure -- exactly
   the right behavior for ITS OWN generic contract, but HEC's real
   documented response never carries an ``accepted`` field at all (a real
   success body is exactly ``{"text": "Success", "code": 0}``; a real
   auth failure is ``{"text": "Invalid token", "code": 4}`` at HTTP 403,
   per the real, documented status-code table). Reusing
   ``HttpJsonIntegrationSink`` here would either force it to special-case
   Splunk's shape (defeating the point of it being "generic") or silently
   apply HEC's real 2xx to a check that would always fail (no `accepted`
   key ever exists in a real HEC response). A sibling class that asserts
   on Splunk's own real ``code``/``text`` pair is the honest choice --
   nothing meaningful is shared with ``HttpJsonIntegrationSink`` except
   "POST JSON over HTTP with httpx," which is not enough shared behavior
   to justify inheritance (mirrors this same codebase's own precedent of
   preferring composition/sibling classes over inheritance for anything
   past a trivial "is-a" relationship).

**What IS reused unchanged, per the R1 foundation's own design intent:**
``SinkAuthenticator`` (a plain ``StaticTokenAuthenticator(token,
scheme="Splunk")`` produces the real, exact ``Authorization: Splunk
<token>`` header HEC documents -- no Splunk-specific authenticator needed),
``chunk_events()`` (via the ``max_batch_events``/``max_batch_bytes``
properties below), and the ``IntegrationSink``/``SinkAck`` contract itself.

**Real, documented ceilings applied here** (``poc/integration_sink_splunk_hec/README.md``
cites the exact sources): ``max_content_length`` defaults to 838,860,800
bytes (~800MB) in ``limits.conf``'s ``[http_input]`` stanza -- the real
per-*request* ceiling this class exposes via ``max_batch_bytes`` (so
``DetectionSinkPushService``'s ``chunk_events()`` call respects it); and
``maxEventSize`` defaults to 5,242,880 bytes (5MB) in ``inputs.conf`` -- a
real per-*event* ceiling enforced directly in ``push_events()`` (mirrors
``batching.py``'s own documented contract: "a single event that alone
exceeds max_batch_bytes ... the concrete IntegrationSink.push_events() call
... is the correct place to reject" it). Both are constructor-overridable
so PoC/tests can prove chunking against a realistic-but-smaller threshold
without literally sending hundreds of megabytes.

**Not implemented here, flagged as real follow-up, not silently
skipped:** Splunk HEC's optional *indexer acknowledgement* feature
(``ackId`` in the response body + ``X-Splunk-Request-Channel`` header +
polling ``/services/collector/ack``) is a real, more granular confirmation
mechanism documented for HEC, distinct from the basic ``code: 0`` response
this class relies on. It requires the token to have ``useACK`` enabled and
a stateful poll loop this connector does not build in this pass -- the
``code: 0`` synchronous response is still a real, honest, documented
confirmation (Splunk's own basic contract), just a coarser one than
``ackId`` polling would give.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import httpx

from src.adapter.integration_sink.integration_sink import IntegrationSink
from src.adapter.integration_sink.sink_authenticator import SinkAuthenticator
from src.application.detection_sink_mapper import MappedSinkEvent
from src.domain.integration_sink import SinkAck, SinkAckStatus
from src.exceptions import IntegrationSinkError

# Splunk Enterprise real, documented defaults (verified against
# limits.conf's [http_input] max_content_length and inputs.conf's
# maxEventSize -- see poc/integration_sink_splunk_hec/README.md for the
# exact sources cited). Constructor-overridable, never silently assumed
# "unlimited" if a deployment tunes these differently.
_DEFAULT_MAX_CONTENT_BYTES = 838_860_800
_DEFAULT_MAX_EVENT_BYTES = 5_242_880


class SplunkHecSink(IntegrationSink):
    """Real HTTP POST to a Splunk HEC ``/services/collector/event`` endpoint.

    *endpoint_url* is the caller's own full HEC event-endpoint URL (e.g.
    ``https://splunk.example.com:8088/services/collector/event``) -- this
    class never guesses or constructs it from a bare host, since real
    deployments vary the path prefix (Splunk Cloud's own HEC ingress uses a
    different hostname pattern than a self-hosted instance).
    """

    def __init__(
        self,
        endpoint_url: str,
        authenticator: SinkAuthenticator,
        *,
        timeout: float = 15.0,
        max_batch_events: int | None = None,
        max_batch_bytes: int | None = _DEFAULT_MAX_CONTENT_BYTES,
        max_event_bytes: int = _DEFAULT_MAX_EVENT_BYTES,
    ) -> None:
        self._endpoint_url = endpoint_url
        self._authenticator = authenticator
        self._timeout = timeout
        self._max_batch_events = max_batch_events
        self._max_batch_bytes = max_batch_bytes
        self._max_event_bytes = max_event_bytes

    @property
    def max_batch_events(self) -> int | None:
        # HEC documents no per-request EVENT-COUNT ceiling (only byte-size
        # ceilings) -- None here is an honest "not documented," not
        # "unlimited in practice"; callers rely on max_batch_bytes instead.
        return self._max_batch_events

    @property
    def max_batch_bytes(self) -> int | None:
        return self._max_batch_bytes

    async def push_events(self, events: Sequence[MappedSinkEvent]) -> SinkAck:
        if not events:
            raise IntegrationSinkError("push_events called with an empty batch")

        serialized: list[str] = []
        for event in events:
            if event.payload is None:
                raise IntegrationSinkError(
                    "SplunkHecSink requires MappedSinkEvent.payload (HEC's JSON "
                    "envelope family) -- got a raw_text/line-oriented event instead",
                    context={"source_detection_id": event.source_detection_id},
                )
            line = json.dumps(event.payload)
            line_bytes = len(line.encode("utf-8"))
            if line_bytes > self._max_event_bytes:
                raise IntegrationSinkError(
                    "One mapped event exceeds Splunk HEC's real, documented "
                    "maxEventSize ceiling -- rejecting rather than sending a "
                    "request the real target would itself reject",
                    context={
                        "source_detection_id": event.source_detection_id,
                        "event_bytes": line_bytes,
                        "max_event_bytes": self._max_event_bytes,
                    },
                )
            serialized.append(line)

        # Real HEC batch wire format: standalone JSON objects concatenated
        # one after another -- explicitly NOT a JSON array and NOT
        # comma-separated (see this module's own docstring for the exact
        # doc quote). Deliberately built via plain string concatenation,
        # never json.dumps({"events": [...]}) -- that shape is
        # HttpJsonIntegrationSink's own generic contract, not HEC's real one.
        body = "".join(serialized).encode("utf-8")

        auth = await self._authenticator.prepare()
        headers: dict[str, str] = {"Content-Type": "application/json", **auth.headers}

        try:
            async with httpx.AsyncClient(
                timeout=self._timeout, verify=auth.verify, cert=auth.cert
            ) as client:
                response = await client.post(self._endpoint_url, content=body, headers=headers)
        except httpx.HTTPError as exc:
            raise IntegrationSinkError(
                "Real HTTP POST to Splunk HEC failed to complete",
                context={
                    "endpoint_url": self._endpoint_url,
                    "event_count": len(events),
                    "error": str(exc),
                },
            ) from exc

        if not (200 <= response.status_code < 300):
            # Real HEC's own documented status-code table (verified against
            # docs.splunk.com/.../TroubleshootHTTPEventCollector) pairs EVERY
            # status code with a real {"text", "code"} body -- 401/"Token is
            # required", 401/"Invalid authorization", 403/"Invalid token",
            # 400/"Invalid data format", etc. Surfacing that real code/text
            # here (best-effort -- a malformed/non-JSON error body still
            # falls back to the raw status_code/body context) gives a real
            # caller the same specific diagnosis HEC itself provides, not
            # just a generic "non-2xx" fact.
            context: dict[str, Any] = {
                "endpoint_url": self._endpoint_url,
                "status_code": response.status_code,
                "body": response.text[:500],
            }
            try:
                error_body = response.json()
                if isinstance(error_body, dict):
                    context["code"] = error_body.get("code")
                    context["text"] = error_body.get("text")
            except (ValueError, TypeError):
                pass
            raise IntegrationSinkError(
                "Splunk HEC rejected the real push (non-2xx response)", context=context
            )

        try:
            resp_body: dict[str, Any] = response.json()
            code = resp_body["code"]
            text = resp_body["text"]
        except (ValueError, KeyError, TypeError) as exc:
            raise IntegrationSinkError(
                "Splunk HEC returned a 2xx response with no usable real "
                "code/text pair -- never fabricating an ack",
                context={
                    "endpoint_url": self._endpoint_url,
                    "body": response.text[:500],
                    "error": str(exc),
                },
            ) from exc

        # Splunk's own documented contract: code == 0 means "Success" at
        # HTTP 200 (the real status-code table maps every other code to a
        # real, distinct failure reason -- e.g. 4 = "Invalid token"). A 2xx
        # HTTP status with a non-zero code has never been observed to mean
        # success and is treated as a real failure, not a partial ack (HEC
        # gives no per-event breakdown to salvage a "partial" success from).
        if code != 0:
            raise IntegrationSinkError(
                "Splunk HEC's own response code signals the push was not "
                "accepted -- treating as a real failure, never a fabricated ack",
                context={
                    "endpoint_url": self._endpoint_url,
                    "code": code,
                    "text": text,
                },
            )

        return SinkAck(
            status=SinkAckStatus.ACKNOWLEDGED,
            detail={
                "status_code": response.status_code,
                "code": code,
                "text": text,
                "event_count": len(events),
            },
        )
