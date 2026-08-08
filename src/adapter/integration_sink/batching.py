"""Batch chunking helper for outbound sink pushes
(KAFKA_AND_INTEGRATIONS_ROADMAP.md R1, SS4 design constraint #4).

**Decision: batching IS this foundation's concern, not each concrete
sink's own.** Splunk HEC and Sentinel both have real, documented per-call
size/rate ceilings (roadmap SS0: HEC's ~800MB ``max_content_length``/5MB
``maxEventSize``, Sentinel's 1MB/call Logs Ingestion API limit) -- but the
*algorithm* for respecting a "max N events and/or max B bytes per call"
ceiling is identical regardless of which vendor's numbers it's fed. Making
every future concrete sink (R2 Splunk, R4 Sentinel, and beyond) re-derive
its own byte-accounting loop would be exactly the kind of duplicated,
easy-to-get-subtly-wrong logic (off-by-one on the boundary event, wrong
newline/comma overhead accounting) CLAUDE.md SS A.1's "delegate to
collaborators" principle exists to avoid. What genuinely differs per
target -- the actual numeric ceilings -- stays a property of each concrete
``IntegrationSink`` (``max_batch_events``/``max_batch_bytes``), not
hardcoded here.

CEF/LEEF-over-syslog transports typically send one line per event with no
real batching concept at all (a syslog message IS one line) -- such a sink
simply reports ``max_batch_events = 1`` and this helper naturally produces
one event per chunk, no special-casing needed here.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from typing import TypeVar

from src.application.detection_sink_mapper import MappedSinkEvent

T = TypeVar("T", bound=MappedSinkEvent)


def _event_size_bytes(event: MappedSinkEvent) -> int:
    """A real, if approximate, byte-size estimate for one mapped event --
    good enough for staying under a documented ceiling with margin, never
    claimed to be the exact wire size after HTTP/syslog framing overhead."""
    if event.raw_text is not None:
        return len(event.raw_text.encode("utf-8"))
    # payload is guaranteed set when raw_text is None (MappedSinkEvent's own
    # __post_init__ invariant) -- str() is a real, if imprecise, stand-in
    # for the eventual json.dumps() size a concrete HTTP sink will compute.
    return len(str(event.payload).encode("utf-8"))


def chunk_events(
    events: Sequence[T],
    *,
    max_batch_events: int | None,
    max_batch_bytes: int | None,
) -> Iterator[list[T]]:
    """Yield *events* split into chunks respecting *max_batch_events*/
    *max_batch_bytes* -- either or both may be ``None`` (no ceiling on that
    dimension). A single event that alone exceeds ``max_batch_bytes`` is
    still yielded alone (in its own one-event chunk) rather than raising or
    silently dropped -- the concrete ``IntegrationSink.push_events()`` call
    for that chunk is the correct place to reject an individual
    oversized event with a real, specific ``IntegrationSinkError``.
    """
    if max_batch_events is not None and max_batch_events < 1:
        raise ValueError(f"max_batch_events must be >= 1, got {max_batch_events}")
    if max_batch_bytes is not None and max_batch_bytes < 1:
        raise ValueError(f"max_batch_bytes must be >= 1, got {max_batch_bytes}")

    current: list[T] = []
    current_bytes = 0
    for event in events:
        size = _event_size_bytes(event)
        would_exceed_count = max_batch_events is not None and len(current) + 1 > max_batch_events
        would_exceed_bytes = (
            max_batch_bytes is not None and current and current_bytes + size > max_batch_bytes
        )
        if current and (would_exceed_count or would_exceed_bytes):
            yield current
            current = []
            current_bytes = 0
        current.append(event)
        current_bytes += size
    if current:
        yield current
