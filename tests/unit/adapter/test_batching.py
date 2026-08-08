"""Unit tests for chunk_events (roadmap R1, SS4 design constraint #4).

Pure logic, no external dependency to mock -- domain-object factories only
(CLAUDE.md SS B.5).
"""

from __future__ import annotations

import pytest

from src.adapter.integration_sink.batching import chunk_events
from src.application.detection_sink_mapper import MappedSinkEvent


def _json_event(detection_id: str, payload_bytes: int = 10) -> MappedSinkEvent:
    return MappedSinkEvent(
        source_detection_id=detection_id,
        payload={"data": "x" * payload_bytes},
    )


class TestChunkEventsByCount:
    def test_no_ceilings_yields_one_chunk_with_everything(self) -> None:
        events = [_json_event(str(i)) for i in range(5)]
        chunks = list(chunk_events(events, max_batch_events=None, max_batch_bytes=None))
        assert len(chunks) == 1
        assert len(chunks[0]) == 5

    def test_max_batch_events_splits_evenly(self) -> None:
        events = [_json_event(str(i)) for i in range(5)]
        chunks = list(chunk_events(events, max_batch_events=2, max_batch_bytes=None))
        assert [len(c) for c in chunks] == [2, 2, 1]

    def test_max_batch_events_of_one_yields_one_event_per_chunk(self) -> None:
        events = [_json_event(str(i)) for i in range(3)]
        chunks = list(chunk_events(events, max_batch_events=1, max_batch_bytes=None))
        assert [len(c) for c in chunks] == [1, 1, 1]

    def test_empty_input_yields_no_chunks(self) -> None:
        chunks = list(chunk_events([], max_batch_events=2, max_batch_bytes=None))
        assert chunks == []


class TestChunkEventsByBytes:
    def test_max_batch_bytes_splits_when_exceeded(self) -> None:
        # Each event's JSON-ish payload string is comfortably measurable --
        # three ~30-byte events with a ~40-byte ceiling should split 2/1 or
        # similar, never silently ignore the ceiling.
        events = [_json_event(str(i), payload_bytes=30) for i in range(3)]
        chunks = list(chunk_events(events, max_batch_events=None, max_batch_bytes=45))
        assert len(chunks) > 1
        assert sum(len(c) for c in chunks) == 3

    def test_single_oversized_event_still_yielded_alone_not_dropped(self) -> None:
        huge = _json_event("huge", payload_bytes=1000)
        small = _json_event("small", payload_bytes=5)
        chunks = list(chunk_events([huge, small], max_batch_events=None, max_batch_bytes=50))
        assert len(chunks) == 2
        assert chunks[0] == [huge]
        assert chunks[1] == [small]


class TestChunkEventsRawText:
    def test_raw_text_events_measured_by_utf8_length(self) -> None:
        events = [
            MappedSinkEvent(source_detection_id=str(i), raw_text="CEF:0|Vendor|Product|" + "x" * 20)
            for i in range(4)
        ]
        chunks = list(chunk_events(events, max_batch_events=1, max_batch_bytes=None))
        # Syslog-family sinks report max_batch_events=1 -- one event per chunk.
        assert [len(c) for c in chunks] == [1, 1, 1, 1]


class TestChunkEventsValidation:
    def test_max_batch_events_below_one_raises(self) -> None:
        with pytest.raises(ValueError):
            list(chunk_events([_json_event("a")], max_batch_events=0, max_batch_bytes=None))

    def test_max_batch_bytes_below_one_raises(self) -> None:
        with pytest.raises(ValueError):
            list(chunk_events([_json_event("a")], max_batch_events=None, max_batch_bytes=0))
