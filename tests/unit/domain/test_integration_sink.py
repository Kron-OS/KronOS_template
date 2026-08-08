"""Unit tests for SinkAck/SinkPushResult value objects (roadmap R1)."""

from __future__ import annotations

from src.domain.integration_sink import SinkAck, SinkAckStatus, SinkPushResult


class TestSinkAck:
    def test_acknowledged_status_and_detail(self) -> None:
        ack = SinkAck(status=SinkAckStatus.ACKNOWLEDGED, detail={"status_code": 200})
        assert ack.status == SinkAckStatus.ACKNOWLEDGED
        assert ack.detail == {"status_code": 200}

    def test_unacknowledged_is_a_distinct_real_status_not_a_bool(self) -> None:
        ack = SinkAck(status=SinkAckStatus.UNACKNOWLEDGED, detail={"transport": "tcp"})
        assert ack.status != SinkAckStatus.ACKNOWLEDGED
        assert ack.status == SinkAckStatus.UNACKNOWLEDGED

    def test_detail_defaults_to_empty_dict(self) -> None:
        ack = SinkAck(status=SinkAckStatus.ACKNOWLEDGED)
        assert ack.detail == {}

    def test_frozen(self) -> None:
        ack = SinkAck(status=SinkAckStatus.ACKNOWLEDGED)
        try:
            ack.status = SinkAckStatus.UNACKNOWLEDGED  # type: ignore[misc]
            raised = False
        except Exception:
            raised = True
        assert raised


class TestSinkPushResult:
    def test_all_acknowledged_true_when_every_batch_confirmed(self) -> None:
        result = SinkPushResult(
            detection_count=2,
            batch_count=2,
            acks=(
                SinkAck(status=SinkAckStatus.ACKNOWLEDGED),
                SinkAck(status=SinkAckStatus.ACKNOWLEDGED),
            ),
        )
        assert result.all_acknowledged is True

    def test_all_acknowledged_false_when_any_batch_is_only_unacknowledged(self) -> None:
        result = SinkPushResult(
            detection_count=2,
            batch_count=2,
            acks=(
                SinkAck(status=SinkAckStatus.ACKNOWLEDGED),
                SinkAck(status=SinkAckStatus.UNACKNOWLEDGED),
            ),
        )
        assert result.all_acknowledged is False

    def test_all_acknowledged_false_when_all_batches_unacknowledged(self) -> None:
        result = SinkPushResult(
            detection_count=1,
            batch_count=1,
            acks=(SinkAck(status=SinkAckStatus.UNACKNOWLEDGED),),
        )
        assert result.all_acknowledged is False
