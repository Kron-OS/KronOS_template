"""Unit tests for the kronos_attest package (offline chain + Merkle verification)."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from kronos_attest.report import AttestationReport
from kronos_attest.verifier import (
    GENESIS_HASH,
    ChainBreak,
    ChainVerificationResult,
    ChainVerifier,
    MerkleVerifier,
    build_merkle_root,
    compute_row_hash,
    merkle_proof,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(
    seq: int,
    event_type: str = "evidence.upload_finalized",
    prev_hash: str | None = None,
    case_id: str | None = None,
    evidence_id: str | None = None,
    day: str = "2026-06-25",
) -> dict[str, Any]:
    """Build a minimal audit event dict with a valid row_hash."""
    eid = str(uuid.uuid4())
    ph = prev_hash or GENESIS_HASH
    ev: dict[str, Any] = {
        "event_id": eid,
        "event_type": event_type,
        "actor_user_id": str(uuid.uuid4()),
        "actor_username": "tester",
        "org_id": str(uuid.uuid4()),
        "case_id": case_id or str(uuid.uuid4()),
        "evidence_id": evidence_id,
        "details": {},
        "occurred_at": f"{day}T12:00:0{seq}Z",
        "sequence_number": seq,
        "prev_row_hash": ph,
    }
    ev["row_hash"] = compute_row_hash(ph, ev)
    return ev


def _make_chain(n: int, day: str = "2026-06-25") -> list[dict[str, Any]]:
    events = []
    prev = GENESIS_HASH
    for i in range(n):
        ev = _make_event(i, prev_hash=prev, day=day)
        prev = ev["row_hash"]
        events.append(ev)
    return events


# ---------------------------------------------------------------------------
# ChainVerifier
# ---------------------------------------------------------------------------


class TestChainVerifier:
    def test_empty_chain_is_valid(self) -> None:
        result = ChainVerifier().verify([])
        assert result.valid is True
        assert result.event_count == 0
        assert result.breaks == []

    def test_single_event_chain(self) -> None:
        ev = _make_event(0)
        result = ChainVerifier().verify([ev])
        assert result.valid is True
        assert result.event_count == 1

    def test_multi_event_chain(self) -> None:
        events = _make_chain(5)
        result = ChainVerifier().verify(events)
        assert result.valid is True
        assert result.event_count == 5

    def test_tampered_hash_detected(self) -> None:
        events = _make_chain(3)
        tampered = dict(events[1])
        tampered["row_hash"] = "0" * 64  # corrupt
        result = ChainVerifier().verify([events[0], tampered, events[2]])
        assert result.valid is False
        assert len(result.breaks) >= 1
        assert result.breaks[0].sequence_number == 1

    def test_out_of_order_events_sorted(self) -> None:
        events = _make_chain(4)
        shuffled = [events[3], events[0], events[2], events[1]]
        result = ChainVerifier().verify(shuffled)
        assert result.valid is True

    def test_merkle_root_returned(self) -> None:
        events = _make_chain(4)
        result = ChainVerifier().verify(events)
        assert len(result.merkle_root) == 64  # SHA-256 hex


# ---------------------------------------------------------------------------
# Merkle tree
# ---------------------------------------------------------------------------


class TestMerkleVerifier:
    def test_empty_root(self) -> None:
        root = build_merkle_root([])
        assert root == hashlib.sha256(b"empty").hexdigest()

    def test_single_leaf_root(self) -> None:
        h = "abc123"
        root = build_merkle_root([h])
        assert root == hashlib.sha256(h.encode()).hexdigest()

    def test_even_leaves(self) -> None:
        hashes = ["a" * 64, "b" * 64, "c" * 64, "d" * 64]
        root = build_merkle_root(hashes)
        assert len(root) == 64

    def test_odd_leaves(self) -> None:
        hashes = ["a" * 64, "b" * 64, "c" * 64]
        root = build_merkle_root(hashes)
        assert len(root) == 64

    def test_proof_verification(self) -> None:
        events = _make_chain(4)
        hashes = [e["row_hash"] for e in events]
        root = build_merkle_root(hashes)
        verifier = MerkleVerifier()
        for i in range(len(hashes)):
            proof = merkle_proof(hashes, i)
            assert verifier.verify_proof(hashes[i], proof, root, i), f"Proof failed for index {i}"

    def test_invalid_proof_rejected(self) -> None:
        events = _make_chain(4)
        hashes = [e["row_hash"] for e in events]
        root = build_merkle_root(hashes)
        wrong_hash = "f" * 64
        proof = merkle_proof(hashes, 0)
        verifier = MerkleVerifier()
        assert not verifier.verify_proof(wrong_hash, proof, root, 0)

    def test_compute_root_from_events(self) -> None:
        events = _make_chain(4)
        verifier = MerkleVerifier()
        root1 = verifier.compute_root_from_events(events)
        hashes = [e["row_hash"] for e in events]
        root2 = build_merkle_root(hashes)
        assert root1 == root2


# ---------------------------------------------------------------------------
# AttestationReport
# ---------------------------------------------------------------------------


class TestDayReport:
    def test_empty_day(self) -> None:
        reporter = AttestationReport()
        report = reporter.day_report([], "2026-06-25")
        assert report.event_count == 0
        assert report.chain_valid is True
        assert report.break_count == 0
        assert report.tsa_anchored is False

    def test_day_with_events(self) -> None:
        # Use _make_chain so each event's prev_hash chains correctly.
        events = _make_chain(3, day="2026-06-25")
        reporter = AttestationReport()
        report = reporter.day_report(events, "2026-06-25")
        assert report.event_count == 3
        assert report.chain_valid is True

    def test_tsa_anchor_detected(self) -> None:
        events = _make_chain(2)
        tsa_event = _make_event(99, event_type="audit.merkle_anchored", day="2026-06-24")
        tsa_event["details"] = {"day": "2026-06-24", "merkle_root": "abcd"}
        events.append(tsa_event)
        reporter = AttestationReport()
        report = reporter.day_report(events + [tsa_event], "2026-06-24")
        assert report.tsa_anchored is True


class TestCaseReport:
    def test_case_report_filters_by_case(self) -> None:
        case_id = str(uuid.uuid4())
        other_case = str(uuid.uuid4())
        evidence_id = str(uuid.uuid4())
        events = [_make_event(i, case_id=case_id, evidence_id=evidence_id) for i in range(3)]
        events += [_make_event(i + 10, case_id=other_case) for i in range(2)]

        reporter = AttestationReport()
        report = reporter.case_report(events, case_id)
        assert report.event_count == 3
        assert report.case_id == case_id
        assert evidence_id in report.evidence_ids

    def test_empty_case(self) -> None:
        reporter = AttestationReport()
        report = reporter.case_report([], str(uuid.uuid4()))
        assert report.event_count == 0
        assert report.chain_valid is True
