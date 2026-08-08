"""DetectionEventMapper: per-target schema translation for outbound sink
pushes (KAFKA_AND_INTEGRATIONS_ROADMAP.md R1).

**Why this is a separate, injectable collaborator and not inline
composition like ``SyncDetectionTicketAction`` (roadmap doc SS4, explicit).**
``SyncDetectionTicketAction`` builds its ``TicketingSystem.create_ticket()``
call's ``title``/``description``/``severity`` arguments inline, in the
action's own ``execute()`` body -- and that is the right call THERE,
because every real ITSM's own "generic webhook" feature reduces to the
exact same four-field shape (see ``ticketing_system.py``'s own docstring).
SIEM sinks have no such convergence: Splunk HEC wants a flat envelope
(``{"time","host","source","sourcetype","index","event"}``), Microsoft
Sentinel's Logs Ingestion API wants columns matching a rigid,
pre-provisioned Data Collection Rule schema chosen per-customer, and
CEF/LEEF wants a pipe-delimited header plus key-value "extension" string
with a per-vendor field dictionary. Inlining any ONE of these into a
shared action would force every other target to route through a
shape that fits none of them. Making the mapping step its own class,
injected into ``DetectionSinkPushService`` rather than hand-built per
call site, is what lets R2 (Splunk)/R3 (CEF)/R4 (Sentinel) each plug in
their own real mapper without touching the orchestration or transport
layers at all -- "new target = new ``DetectionEventMapper`` registration,
zero edits elsewhere" (roadmap invariant #1).

Concrete, named-vendor mappers (Splunk/Sentinel/CEF) are explicitly R2-R4's
own scope, not built here. This module's own PoC
(``poc/integration_sink_foundation/``) proves the interface is genuinely
pluggable with two deliberately generic, non-vendor-specific stand-in
mappers exercised end-to-end.

Zero framework imports (CLAUDE.md SS A.3) -- pure dataclass/ABC, no
httpx/socket here.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from src.domain.detection import Detection


@dataclass(frozen=True)
class MappedSinkEvent:
    """One target-shaped event, produced by a per-target ``DetectionEventMapper``.

    Exactly one of ``payload``/``raw_text`` is set, matching which transport
    family the target sink needs (see ``src/adapter/integration_sink/``'s own
    module docstring for the two families):

    - ``payload``: a JSON-serializable dict, for the HTTP-JSON family
      (Splunk HEC, Sentinel, QRadar HTTP Receiver, Elastic Bulk, ...) --
      the mapper decides the envelope shape; the transport only serializes
      and POSTs it, never reshapes it.
    - ``raw_text``: an already-fully-formatted line (e.g. a complete CEF
      string, ``CEF:0|Vendor|Product|...``), for line-oriented
      fire-and-forget transports (CEF/LEEF-over-syslog) -- only the mapper
      knows the target's own field dictionary, so formatting happens here,
      never in the transport.

    ``source_detection_id`` is always set, independent of which field is
    populated -- the orchestration/audit layer's own correlation key back
    to the originating ``Detection``, so an audit row never has to inspect
    an opaque payload to know which Detection it was about.
    """

    source_detection_id: str
    payload: dict[str, Any] | None = None
    raw_text: str | None = None
    # Free-form, mapper-chosen metadata surfaced in audit details (e.g.
    # target index/sourcetype chosen) -- never load-bearing for delivery
    # itself, purely for a court-facing audit trail's own traceability.
    mapper_metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if (self.payload is None) == (self.raw_text is None):
            raise ValueError(
                "MappedSinkEvent requires exactly one of payload/raw_text to be set "
                f"(payload={self.payload!r}, raw_text={self.raw_text!r})"
            )


class DetectionEventMapper(ABC):
    """Translates one ``Detection`` into one target-shaped ``MappedSinkEvent``.

    A new sink target = a new ``DetectionEventMapper`` implementation,
    injected into ``DetectionSinkPushService`` at construction -- zero
    changes to the service, ``IntegrationSink``, or any other mapper
    (roadmap invariant #1). Raising is the correct way to signal "this
    Detection cannot be represented in the target's schema" (e.g. a
    Sentinel mapper hitting a DCR column it cannot populate) --
    ``DetectionSinkPushService`` audits and propagates it exactly like an
    ``IntegrationSink`` failure, never silently drops the Detection from
    the batch.
    """

    @abstractmethod
    def map(self, detection: Detection) -> MappedSinkEvent:
        """Return the target-shaped representation of *detection*.

        Must never mutate *detection* or read anything outside it plus its
        own target-specific configuration (mirrors every other tenant-
        scoped/replayable component in this codebase: same Detection in,
        same MappedSinkEvent out).
        """
