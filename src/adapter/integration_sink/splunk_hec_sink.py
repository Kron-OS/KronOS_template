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

**Indexer-acknowledgement (``ackId``) polling -- gap audit V6, P1-3, now
implemented, opt-in.** Splunk HEC's optional *indexer acknowledgement*
feature is a real, more granular confirmation than the basic ``code: 0``
response above: a token with ``useACK=1`` set (real, verified this pass --
see ``poc/splunk_hec_ack_polling/README.md`` for the exact real REST call:
``POST .../data/inputs/http/<name>`` with ``useACK=1``, since neither
``docker-splunk``'s own README nor ``splunk-ansible``'s ``getHEC()`` expose
a ``SPLUNK_HEC_*`` env var for it) requires ``X-Splunk-Request-Channel:
<GUID>`` on every push against that token (real, verified: a push without
it against a ``useACK=1`` token returns a real, distinct
``400``/``{"code":10,"text":"Data channel is missing"}``, not silently
accepted); a successful push then returns a real ``ackId`` integer
alongside ``code``/``text``; the ``ackId`` is resolved by a separate,
real ``POST /services/collector/ack`` call, ``{"acks": [ackId, ...]}`` in,
``{"acks": {"<ackId>": true|false}}`` out. Real, previously-undocumented-
in-any-doc-fetched-this-pass behavior confirmed by hand against the real
container: **once an ``ackId`` resolves ``true``, HEC deletes its status
-- a later poll of the SAME ``ackId`` returns ``false`` again** (matches
Splunk's own doc language: "If you query the same ackID again, HEC will
always return false ... because its status information can no longer be
found"). ``check_ack_status()``/the polling loop below are written to
treat this as read-once, never re-polling an already-``true`` id.

**Design decision (this class's own "decide and justify" question,
gap audit V6): synchronous polling with a real, bounded, per-sink-configured
timeout, resolving to a real THIRD ``SinkAck`` status
(``SinkAckStatus.ACK_PENDING``, ``src/domain/integration_sink.py``) on
timeout rather than raising or fabricating ``ACKNOWLEDGED``.** Considered
and rejected: (a) block inside ``push_events()`` with no timeout at all --
rejected, since HEC's own indexing latency is unbounded in principle (a
degraded indexer queue), and ``IntegrationSink.push_events()``'s own ABC
contract is a single bounded call, not an open-ended wait; (b) always
return a bare "accepted" status immediately with no polling at all,
pushing 100% of the confirmation burden onto a separate caller-driven
mechanism -- rejected as the strictly weaker default for what this whole
feature exists to buy (the caller most likely to enable
``enable_indexer_ack`` wants *some* real confirmation attempt before
treating a push as done, this is an already-opt-in feature, not the
common case, so a bounded synchronous wait's added latency is an accepted,
deliberate trade the caller opted into). The chosen shape gets both real
benefits: `push_events()` itself makes one real, bounded attempt to reach
the stronger `ACKNOWLEDGED` confirmation (mirrors this class's own
existing ``code: 0`` synchronous-confirmation idiom, just one layer
deeper), AND a genuine timeout is never silently upgraded to a fabricated
success -- ``ACK_PENDING`` carries the real ``ack_id``/``channel`` in its
``detail`` so a caller can resolve it later via the separate, real
``check_ack_status()`` method (the "SEPARATE method/mechanism to check ack
status later" this item's own brief named as the alternative -- built as
a complement to the synchronous default, not instead of it, since a
caller with its own longer-lived scheduler may prefer to poll out-of-band
rather than block a request thread).

Disabled by default (``enable_indexer_ack=False``) -- the plain ``code: 0``
synchronous response remains a real, honest, documented confirmation on
its own (Splunk's own basic contract) for any deployment that hasn't
opted a token into ``useACK``.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlsplit, urlunsplit

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

# Real, observed-this-pass defaults for indexer-ack polling (opt-in, see
# this module's own docstring) -- no Splunk doc states a "recommended"
# poll interval/timeout, these are KronOS's own reasonable, overridable
# choices, not a documented Splunk value.
_DEFAULT_ACK_POLL_TIMEOUT_SECONDS = 30.0
_DEFAULT_ACK_POLL_INTERVAL_SECONDS = 1.0


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
        enable_indexer_ack: bool = False,
        ack_poll_timeout: float = _DEFAULT_ACK_POLL_TIMEOUT_SECONDS,
        ack_poll_interval: float = _DEFAULT_ACK_POLL_INTERVAL_SECONDS,
        ack_endpoint_url: str | None = None,
    ) -> None:
        self._endpoint_url = endpoint_url
        self._authenticator = authenticator
        self._timeout = timeout
        self._max_batch_events = max_batch_events
        self._max_batch_bytes = max_batch_bytes
        self._max_event_bytes = max_event_bytes
        # Indexer-ack polling (opt-in, disabled by default) -- see this
        # module's own docstring for the real, verified wire contract and
        # the synchronous-with-bounded-timeout design decision.
        self._enable_indexer_ack = enable_indexer_ack
        self._ack_poll_timeout = ack_poll_timeout
        self._ack_poll_interval = ack_poll_interval
        self._ack_url = ack_endpoint_url or self._derive_ack_url(endpoint_url)

    @staticmethod
    def _derive_ack_url(endpoint_url: str) -> str:
        """Real HEC ack endpoint is always ``.../services/collector/ack`` --
        derived from *endpoint_url* (which is always either
        ``.../services/collector/event`` or the bare
        ``.../services/collector``) rather than requiring every caller to
        separately supply it, mirroring this class's own "caller supplies
        one real full endpoint" idiom while keeping ``ack_endpoint_url`` as
        an explicit override for any real deployment whose HEC sits behind
        a proxy/path-rewrite this derivation can't predict."""
        parts = urlsplit(endpoint_url)
        path = parts.path
        if path.endswith("/event"):
            ack_path = path[: -len("event")] + "ack"
        else:
            ack_path = path.rstrip("/") + "/ack"
        return urlunsplit((parts.scheme, parts.netloc, ack_path, "", ""))

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
        # Real, verified-this-pass requirement: a push against a token with
        # useACK=1 enabled MUST carry a channel identifier or HEC rejects it
        # with a real, distinct 400/{"code":10,"text":"Data channel is
        # missing"} -- a fresh GUID per push_events() call (never reused
        # across calls) avoids HEC's own channel-scoped dedup window
        # (poc/splunk_hec_ack_polling/README.md).
        channel = str(uuid.uuid4()) if self._enable_indexer_ack else None
        if channel is not None:
            headers["X-Splunk-Request-Channel"] = channel

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

        if not self._enable_indexer_ack:
            return SinkAck(
                status=SinkAckStatus.ACKNOWLEDGED,
                detail={
                    "status_code": response.status_code,
                    "code": code,
                    "text": text,
                    "event_count": len(events),
                },
            )

        # Indexer-ack enabled: the real response for a useACK=1 token/channel
        # carries a real ackId alongside code/text (verified this pass --
        # poc/splunk_hec_ack_polling/README.md) -- never proceed to poll
        # without one, never silently fall back to the coarser code==0
        # confirmation as if it were the stronger one the caller opted into.
        try:
            ack_id = int(resp_body["ackId"])
        except (KeyError, TypeError, ValueError) as exc:
            raise IntegrationSinkError(
                "enable_indexer_ack=True but Splunk HEC's 2xx response carried "
                "no usable real ackId -- never fabricating a pending ack "
                "(is the token's useACK actually enabled?)",
                context={
                    "endpoint_url": self._endpoint_url,
                    "body": response.text[:500],
                    "error": str(exc),
                },
            ) from exc

        assert channel is not None  # set above whenever _enable_indexer_ack is True
        confirmed, poll_attempts, elapsed_seconds = await self._poll_until_acked_or_timeout(
            channel, ack_id
        )
        return SinkAck(
            status=SinkAckStatus.ACKNOWLEDGED if confirmed else SinkAckStatus.ACK_PENDING,
            detail={
                "status_code": response.status_code,
                "code": code,
                "text": text,
                "event_count": len(events),
                "ack_id": ack_id,
                "channel": channel,
                "indexer_confirmed": confirmed,
                "ack_poll_attempts": poll_attempts,
                "ack_poll_elapsed_seconds": elapsed_seconds,
            },
        )

    async def _poll_until_acked_or_timeout(
        self, channel: str, ack_id: int
    ) -> tuple[bool, int, float]:
        """Real, bounded synchronous poll loop against ``/services/collector/ack``
        (see this class's own module docstring for the design decision this
        implements). Returns ``(confirmed, attempts, elapsed_seconds)`` --
        never raises on a real timeout (a genuine, expected, non-error
        outcome of asynchronous indexing), only on a real transport/auth
        failure while polling (``check_ack_status`` itself raises).
        """
        start = time.monotonic()
        deadline = start + self._ack_poll_timeout
        attempts = 0
        while True:
            attempts += 1
            statuses = await self.check_ack_status(channel, [ack_id])
            if statuses.get(ack_id, False):
                return True, attempts, time.monotonic() - start
            if time.monotonic() >= deadline:
                return False, attempts, time.monotonic() - start
            await asyncio.sleep(min(self._ack_poll_interval, max(0.0, deadline - time.monotonic())))

    async def check_ack_status(self, channel: str, ack_ids: Sequence[int]) -> dict[int, bool]:
        """Real POST to HEC's own ``/services/collector/ack`` endpoint --
        the separate, out-of-band mechanism a caller can use to resolve an
        ``ACK_PENDING`` ``SinkAck`` later, without going through
        ``push_events()`` again (this class's own module docstring explains
        why this exists alongside, not instead of, the synchronous poll
        already built into ``push_events()``).

        *channel* and *ack_ids* are exactly the ``channel``/``ack_id``
        values a prior ``push_events()`` call returned in its ``SinkAck.detail``.
        Real, verified-this-pass behavior: once an ``ackId`` resolves
        ``True`` here, HEC deletes its status -- a later call for the SAME
        id returns ``False`` again (not a regression, just HEC's own
        documented one-shot-readable contract) -- callers should treat a
        ``True`` result as final and stop polling that id, never re-check it.

        Returns a real ``{ack_id: bool}`` mapping (never fabricated -- every
        key/value here is HEC's own real response). Raises
        ``IntegrationSinkError`` on any real transport/auth/malformed-response
        failure, mirroring ``push_events()``'s own "raise, never fabricate"
        contract.
        """
        auth = await self._authenticator.prepare()
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "X-Splunk-Request-Channel": channel,
            **auth.headers,
        }
        body = json.dumps({"acks": list(ack_ids)}).encode("utf-8")

        try:
            async with httpx.AsyncClient(
                timeout=self._timeout, verify=auth.verify, cert=auth.cert
            ) as client:
                response = await client.post(self._ack_url, content=body, headers=headers)
        except httpx.HTTPError as exc:
            raise IntegrationSinkError(
                "Real HTTP POST to Splunk HEC's /services/collector/ack "
                "endpoint failed to complete",
                context={"ack_url": self._ack_url, "channel": channel, "error": str(exc)},
            ) from exc

        if not (200 <= response.status_code < 300):
            context: dict[str, Any] = {
                "ack_url": self._ack_url,
                "channel": channel,
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
                "Splunk HEC rejected the real ack-status poll (non-2xx response)",
                context=context,
            )

        try:
            resp_body: dict[str, Any] = response.json()
            acks = resp_body["acks"]
            if not isinstance(acks, dict):
                raise TypeError(f"'acks' was not a JSON object: {type(acks).__name__}")
        except (ValueError, KeyError, TypeError) as exc:
            raise IntegrationSinkError(
                "Splunk HEC returned a 2xx response with no usable real "
                "'acks' object -- never fabricating ack-status results",
                context={
                    "ack_url": self._ack_url,
                    "body": response.text[:500],
                    "error": str(exc),
                },
            ) from exc

        return {int(ack_id_str): bool(is_acked) for ack_id_str, is_acked in acks.items()}
