"""Unit tests for build_merkle_root and related Merkle tree logic."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime

import pytest

from src.application.audit_log import build_merkle_root
from src.domain.audit import AuditEvent, AuditEventType


def _event(seq: int, row_hash: str = "") -> AuditEvent:
    return AuditEvent(
        event_id=uuid.uuid4(),
        event_type=AuditEventType.SYSTEM_ERROR,
        sequence_number=seq,
        occurred_at=datetime.now(UTC),
        row_hash=row_hash or hashlib.sha256(str(seq).encode()).hexdigest(),
    )


def test_empty_list_returns_sha256_of_empty() -> None:
    expected = hashlib.sha256(b"empty").hexdigest()
    assert build_merkle_root([]) == expected


def test_single_event_returns_leaf_hash() -> None:
    ev = _event(1, "aabbcc")
    expected = hashlib.sha256(b"aabbcc").hexdigest()
    assert build_merkle_root([ev]) == expected


def test_two_events_returns_hash_of_both_leaves() -> None:
    ev1 = _event(1, "aaaaaa")
    ev2 = _event(2, "bbbbbb")
    leaf1 = hashlib.sha256(b"aaaaaa").digest()
    leaf2 = hashlib.sha256(b"bbbbbb").digest()
    expected = hashlib.sha256(leaf1 + leaf2).hexdigest()
    assert build_merkle_root([ev1, ev2]) == expected


def test_odd_count_duplicates_last_leaf() -> None:
    events = [_event(i, hashlib.sha256(str(i).encode()).hexdigest()) for i in range(3)]
    # Three leaves → last duplicated → 2 pairs
    leaves = [hashlib.sha256((e.row_hash or "").encode()).digest() for e in sorted(events, key=lambda e: e.sequence_number)]
    # Duplicate last
    leaves.append(leaves[-1])
    parent0 = hashlib.sha256(leaves[0] + leaves[1]).digest()
    parent1 = hashlib.sha256(leaves[2] + leaves[3]).digest()
    expected = hashlib.sha256(parent0 + parent1).hexdigest()
    assert build_merkle_root(events) == expected


def test_four_events_balanced_tree() -> None:
    events = [_event(i, hashlib.sha256(str(i).encode()).hexdigest()) for i in range(4)]
    leaves = [hashlib.sha256((e.row_hash or "").encode()).digest() for e in sorted(events, key=lambda e: e.sequence_number)]
    p0 = hashlib.sha256(leaves[0] + leaves[1]).digest()
    p1 = hashlib.sha256(leaves[2] + leaves[3]).digest()
    expected = hashlib.sha256(p0 + p1).hexdigest()
    assert build_merkle_root(events) == expected


def test_order_is_by_sequence_number_not_insertion_order() -> None:
    ev1 = _event(1, "aaaaaa")
    ev2 = _event(2, "bbbbbb")
    # Insert out of order
    result_reversed = build_merkle_root([ev2, ev1])
    result_forward = build_merkle_root([ev1, ev2])
    assert result_reversed == result_forward


def test_deterministic_across_calls() -> None:
    events = [_event(i) for i in range(5)]
    assert build_merkle_root(events) == build_merkle_root(events)
