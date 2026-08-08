"""IntegrationSink: real outbound calls to an external SIEM/SOAR system
(KAFKA_AND_INTEGRATIONS_ROADMAP.md R1 -- "IntegrationSink foundation").

**Design decision, read before extending (the roadmap brief's own SS4
question #1).** Real sink transports split into two structurally different
families -- HTTP-JSON push-with-ack (Splunk HEC, Sentinel, QRadar HTTP
Receiver, Elastic Bulk, XSOAR, TheHive: a real response code/body to trust)
vs. CEF/LEEF-over-syslog fire-and-forget (no ack, "the socket write
succeeded" is the only signal). Three shapes were considered:

1. Two related-but-distinct ABCs (``HttpAckSink``/``FireAndForgetSink``).
   Rejected: a caller (``DetectionSinkPushService``) would then need an
   ``isinstance`` check or a parallel code path per family, which is
   exactly the kind of "new sink = edit the orchestrator" coupling
   CLAUDE.md SS A.1/A.4 and this roadmap's own invariant #1 forbid. It also
   means every future 5th, 6th transport family (say, a message-queue-
   based sink) forces a 3rd ABC instead of fitting the existing contract.
2. One ABC, two methods (``push_with_ack`` / ``push_fire_and_forget``).
   Rejected for the same reason as #1 one level down: the caller still has
   to know, per sink instance, which method is the "real" one to call --
   the ABC would not actually unify anything, just rename the same
   isinstance-shaped problem into a "which method exists" problem.
3. **One ABC, one method (``push_events``), an honest ``SinkAck`` return
   type that makes ACKNOWLEDGED-vs-UNACKNOWLEDGED a real, first-class,
   type-checked field of the result rather than encoded in which code path
   ran.** Chosen. The orchestrator and every future sink implementation
   share one contract; the ack-vs-no-ack distinction the roadmap calls "the
   single most important design property of this whole abstraction" lives
   in the data every caller already has to look at to know whether the
   push succeeded, not in which method name it happened to call. See
   ``src/domain/integration_sink.py``'s own docstring for ``SinkAck``'s
   full reasoning.

Small, typed ABC (mirrors ``TicketingSystem``/``EvidenceStorage``/
``KeycloakAdminClient``'s own "one small interface, not a raw HTTP
passthrough" idiom): exactly the one operation every sink family needs,
never a generic ``send(method, path, body)`` escape hatch.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence

from src.application.detection_sink_mapper import MappedSinkEvent
from src.domain.integration_sink import SinkAck


class IntegrationSink(ABC):
    """Real outbound push of already-mapped events to one external SIEM/SOAR target.

    New targets = new ``IntegrationSink`` implementations (registered by
    whatever composes ``DetectionSinkPushService`` -- e.g. a future
    ``SyncDetectionToSplunkAction``), never edits here (roadmap invariant
    #1). Raises ``IntegrationSinkError`` on any failure to reach or get a
    usable response from the real backend -- never returns a fabricated
    ``SinkAck`` (CLAUDE.md SS1#8, mirrors ``TicketingSystem.create_ticket``'s
    own "never fabricate a result" contract).
    """

    @property
    def max_batch_events(self) -> int | None:
        """Real per-call event-count ceiling this target enforces, if any.

        ``None`` (the default) means "this sink has no real event-count
        ceiling documented/observed" -- an honest absence, not "unlimited
        in practice." Concrete sinks with a real documented limit (e.g. a
        future Sentinel mapper's own DCR-imposed shape) override this;
        ``DetectionSinkPushService`` uses it to decide batch boundaries
        (see ``src/adapter/integration_sink/batching.py``).
        """
        return None

    @property
    def max_batch_bytes(self) -> int | None:
        """Real per-call byte-size ceiling this target enforces, if any.

        Same "honest ``None`` means not documented/observed, not
        unlimited" contract as ``max_batch_events``. Splunk HEC's real
        ~800MB ``max_content_length``/5MB ``maxEventSize`` and Sentinel's
        real 1MB/call Logs Ingestion API ceiling (roadmap SS0) are exactly
        the kind of real, per-target values a concrete sink sets here --
        R1 does not hardcode either since it targets no named vendor yet.
        """
        return None

    @abstractmethod
    async def push_events(self, events: Sequence[MappedSinkEvent]) -> SinkAck:
        """Push one real batch of already-mapped events to the real target.

        Callers (``DetectionSinkPushService``) are responsible for
        respecting ``max_batch_events``/``max_batch_bytes`` before calling
        this -- an implementation MAY additionally defend its own ceiling
        itself, but is not required to re-chunk an oversized *events* on
        the caller's behalf.

        Returns a real ``SinkAck`` whose ``status`` honestly reflects
        whether the target confirmed receipt (``ACKNOWLEDGED``) or only the
        local transport write succeeded with no confirmation available
        (``UNACKNOWLEDGED``) -- these two outcomes must never be conflated.
        Raises ``IntegrationSinkError`` on any real failure (unreachable,
        rejected, malformed response, or a ``SinkAuthenticator`` failure).
        """
