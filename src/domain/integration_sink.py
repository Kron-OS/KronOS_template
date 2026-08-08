"""IntegrationSink outcome value objects (roadmap R1, KAFKA_AND_INTEGRATIONS
roadmap, Milestone R -- KronOS -> external SIEM/SOAR sinks).

**The single most important property of this whole abstraction (per the
roadmap's own explicit warning): a caller must never be able to mistake "I
wrote it to a socket" for "the target confirmed receipt."** Real sink
transports fall into two structurally different families:

- HTTP-JSON push-with-ack (Splunk HEC, Microsoft Sentinel, QRadar HTTP
  Receiver, Elastic Bulk, XSOAR, TheHive) -- the caller gets a real response
  code/body it can trust as confirmation the target actually received and
  accepted the event.
- CEF/LEEF-over-syslog fire-and-forget (no application-layer ack at all --
  "the socket write succeeded" is the only signal available, weaker than an
  HTTP 2xx+body by construction, not by omission).

Rather than two ABCs or two differently-named methods on one ABC (both
considered, see ``src/adapter/integration_sink/integration_sink.py``'s own
module docstring for the argument against them), this models the
distinction as a real, first-class field on the *return value* every
``IntegrationSink.push_events()`` implementation produces: ``SinkAck``.
Any caller that treats ``SinkAck`` as a boolean, or greps only for "no
exception raised," gets a type-checked ``SinkAckStatus`` in front of it
before it can call the push "confirmed" -- the honesty is structural, not
just documented.

Zero framework imports (CLAUDE.md SS A.3) -- pure Pydantic, no httpx/socket
here. Producing a ``SinkAck`` (making the real outbound call) is
``IntegrationSink``'s job (adapter layer); composing multiple pushes and
auditing them is ``DetectionSinkPushService``'s job (application layer).
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class SinkAckStatus(StrEnum):
    """Honest, first-class outcome of one real push attempt that did NOT raise.

    A failed attempt (unreachable backend, non-2xx response, malformed
    body) is never represented here -- it raises ``IntegrationSinkError``
    (mirrors ``TicketingSystem``'s own "raise, never fabricate a result"
    contract). ``SinkAck`` only ever describes a real, non-exceptional
    outcome, and even then distinguishes exactly how much confidence that
    outcome deserves.
    """

    # The target system returned a real, structured, application-layer
    # confirmation the event was received/accepted (e.g. Splunk HEC's
    # `{"text": "Success", "code": 0}`, Sentinel's 2xx Logs Ingestion API
    # response, Elastic Bulk's per-item `result` field). Safe to treat as
    # "the target has this event" for reconciliation/retry-suppression
    # purposes.
    ACKNOWLEDGED = "acknowledged"
    # The local write to the transport succeeded (UDP/TCP socket write
    # completed, or TCP connection accepted the bytes) but the transport
    # itself has NO application-layer acknowledgement mechanism (CEF/LEEF-
    # over-syslog, per the roadmap's own verified fact: "no application-
    # layer auth, fire-and-forget -- weaker delivery guarantee than an HTTP
    # 2xx+body ack"). A caller MUST NOT treat this as proof the target
    # ingested the event -- only that KronOS's own local write did not
    # fail.
    UNACKNOWLEDGED = "unacknowledged"


class SinkAck(BaseModel):
    """The real, honest outcome of one non-exceptional ``push_events()`` call.

    ``detail`` is intentionally opaque (mirrors ``StructuredArtifact.content``'s
    "capture now, no per-kind schema yet" precedent, CLAUDE.md SS G.2) --
    an HTTP-family sink puts its real response status/body fragments here,
    a syslog-family sink puts its real transport/byte-count facts here.
    Never used to smuggle a fabricated "success" -- every key present here
    must trace back to something the real transport actually observed.
    """

    model_config = {"frozen": True}

    status: SinkAckStatus
    detail: dict[str, Any] = Field(default_factory=dict)


class SinkPushResult(BaseModel):
    """The full, replayable trace of one ``DetectionSinkPushService.push()``
    call -- one ``SinkAck`` per real batch actually sent, in order.

    Mirrors ``PlaybookExecutionResult``'s own placement/shape reasoning
    (``src/domain/playbook.py``): a pure value object recording exactly
    what happened, so a caller (or a future auditor) never has to re-derive
    "did every batch really get a confirmed ack" from prose. Only
    constructed on a fully successful ``push()`` -- any batch failure
    raises ``IntegrationSinkError`` instead (mirrors
    ``TicketingSystem``/``ContainmentAction``'s own "raise, don't return a
    partial success object" idiom), so ``SinkPushResult`` existing at all
    already means every batch it lists got a real ``SinkAck`` back.
    """

    model_config = {"frozen": True}

    detection_count: int
    batch_count: int
    acks: tuple[SinkAck, ...] = Field(default_factory=tuple)

    @property
    def all_acknowledged(self) -> bool:
        """True only if EVERY batch got a real, confirmed ``ACKNOWLEDGED``
        ack -- False if even one batch was only ``UNACKNOWLEDGED``
        (fire-and-forget). Surfaces the ack-vs-no-ack honesty property at
        the top-level result too, not just per-``SinkAck``, so a caller
        checking only this one property still can't mistake a syslog send
        for a confirmed delivery."""
        return all(ack.status == SinkAckStatus.ACKNOWLEDGED for ack in self.acks)
