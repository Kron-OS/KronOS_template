"""Unit tests for the SealedBatch domain model (roadmap M3/D3)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from src.domain.sealed_batch import SealedBatch


def _make_batch(**overrides: object) -> SealedBatch:
    defaults: dict[str, object] = {
        "org_id": uuid.uuid4(),
        "source_id": "zeek-conn",
        "sealed_at": datetime.now(UTC),
        "event_count": 2,
        "leaf_hashes": ("a" * 64, "b" * 64),
        "message_ids": ("1-0", "2-0"),
        "merkle_root": "c" * 64,
        "worm_bucket": "kronos-stream-batches-org",
        "worm_object_key": "zeek-conn/batch.json",
        "first_message_id": "1-0",
        "last_message_id": "2-0",
    }
    defaults.update(overrides)
    return SealedBatch(**defaults)  # type: ignore[arg-type]


class TestSealedBatchConstruction:
    def test_valid_batch_constructs(self) -> None:
        batch = _make_batch()
        assert batch.event_count == 2
        assert batch.tsa_token is None

    def test_is_frozen(self) -> None:
        batch = _make_batch()
        with pytest.raises(ValidationError):
            batch.event_count = 5  # type: ignore[misc]

    def test_tsa_token_bytes_round_trip(self) -> None:
        batch = _make_batch(tsa_token=b"\x30\x82fake-der-token")
        assert batch.tsa_token == b"\x30\x82fake-der-token"


class TestSealedBatchAlignmentValidator:
    def test_mismatched_leaf_hashes_length_rejected(self) -> None:
        with pytest.raises(ValidationError, match="leaf_hashes/message_ids length"):
            _make_batch(event_count=3, leaf_hashes=("a" * 64, "b" * 64))

    def test_mismatched_message_ids_length_rejected(self) -> None:
        with pytest.raises(ValidationError, match="leaf_hashes/message_ids length"):
            _make_batch(event_count=2, message_ids=("1-0",))
