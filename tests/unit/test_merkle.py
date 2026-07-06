"""Unit tests for build_merkle_root and related Merkle tree logic (AUDIT-04).

The algorithm uses RFC 6962-style domain separation (leaf hashes prefixed
0x00, internal-node hashes prefixed 0x01) and promotes an unpaired node to
the next layer instead of duplicating it — see src/domain/merkle.py for the
canonical implementation and rationale.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime

from src.application.audit_log import build_merkle_root
from src.domain.audit import AuditEvent, AuditEventType
from src.domain.merkle import EMPTY_ROOT, leaf_hash, merkle_proof, verify_proof
from src.domain.merkle import build_merkle_root as domain_build_merkle_root


def _event(seq: int, row_hash: str = "") -> AuditEvent:
    return AuditEvent(
        event_id=uuid.uuid4(),
        event_type=AuditEventType.SYSTEM_ERROR,
        sequence_number=seq,
        occurred_at=datetime.now(UTC),
        row_hash=row_hash or hashlib.sha256(str(seq).encode()).hexdigest(),
    )


def test_empty_list_returns_empty_root_sentinel() -> None:
    assert build_merkle_root([]) == EMPTY_ROOT
    assert EMPTY_ROOT == hashlib.sha256(b"empty").hexdigest()


def test_single_event_returns_domain_separated_leaf_hash() -> None:
    ev = _event(1, "aabbcc")
    expected = hashlib.sha256(b"\x00" + b"aabbcc").hexdigest()
    assert build_merkle_root([ev]) == expected
    # Must NOT match the old (vulnerable) non-domain-separated hash.
    assert build_merkle_root([ev]) != hashlib.sha256(b"aabbcc").hexdigest()


def test_two_events_uses_domain_separated_node_hash() -> None:
    ev1 = _event(1, "aaaaaa")
    ev2 = _event(2, "bbbbbb")
    leaf1 = leaf_hash(b"aaaaaa")
    leaf2 = leaf_hash(b"bbbbbb")
    expected = hashlib.sha256(b"\x01" + leaf1 + leaf2).hexdigest()
    assert build_merkle_root([ev1, ev2]) == expected


def test_odd_count_promotes_last_leaf_instead_of_duplicating() -> None:
    events = [_event(i, hashlib.sha256(str(i).encode()).hexdigest()) for i in range(3)]
    sorted_events = sorted(events, key=lambda e: e.sequence_number)
    leaves = [leaf_hash((e.row_hash or "").encode()) for e in sorted_events]
    # Odd (3) leaves: pair(0,1), promote leaf 2 unchanged to next layer.
    parent0 = hashlib.sha256(b"\x01" + leaves[0] + leaves[1]).digest()
    expected = hashlib.sha256(b"\x01" + parent0 + leaves[2]).hexdigest()
    assert build_merkle_root(events) == expected


def test_four_events_balanced_tree() -> None:
    events = [_event(i, hashlib.sha256(str(i).encode()).hexdigest()) for i in range(4)]
    leaves = [
        leaf_hash((e.row_hash or "").encode())
        for e in sorted(events, key=lambda e: e.sequence_number)
    ]
    p0 = hashlib.sha256(b"\x01" + leaves[0] + leaves[1]).digest()
    p1 = hashlib.sha256(b"\x01" + leaves[2] + leaves[3]).digest()
    expected = hashlib.sha256(b"\x01" + p0 + p1).hexdigest()
    assert build_merkle_root(events) == expected


def test_order_is_by_sequence_number_not_insertion_order() -> None:
    ev1 = _event(1, "aaaaaa")
    ev2 = _event(2, "bbbbbb")
    result_reversed = build_merkle_root([ev2, ev1])
    result_forward = build_merkle_root([ev1, ev2])
    assert result_reversed == result_forward


def test_deterministic_across_calls() -> None:
    events = [_event(i) for i in range(5)]
    assert build_merkle_root(events) == build_merkle_root(events)


def test_odd_tree_cannot_be_confused_with_duplicated_pair() -> None:
    """The promotion fix's whole point: a genuine duplicate pair must produce
    a different root than an odd tree that merely carries one node forward.
    """
    same_twice = [_event(0, "same"), _event(1, "same")]
    single = [_event(0, "same")]
    assert build_merkle_root(same_twice) != build_merkle_root(single)


def test_application_wrapper_matches_domain_implementation() -> None:
    """src.application.audit_log.build_merkle_root must delegate, not diverge."""
    events = [_event(i, hashlib.sha256(str(i).encode()).hexdigest()) for i in range(5)]
    row_hashes = [e.row_hash or "" for e in sorted(events, key=lambda e: e.sequence_number)]
    assert build_merkle_root(events) == domain_build_merkle_root(row_hashes)


def test_merkle_proof_round_trip_for_all_sizes() -> None:
    for n in range(1, 8):
        leaves = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(n)]
        root = domain_build_merkle_root(leaves)
        for i in range(n):
            proof = merkle_proof(leaves, i)
            assert verify_proof(leaves[i], proof, root)


def test_merkle_proof_fails_for_wrong_leaf() -> None:
    leaves = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(4)]
    root = domain_build_merkle_root(leaves)
    proof = merkle_proof(leaves, 0)
    assert not verify_proof(hashlib.sha256(b"wrong").hexdigest(), proof, root)
