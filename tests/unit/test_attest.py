"""Unit tests for the kronos_attest package (offline chain + Merkle verification)."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any

from kronos_attest.report import AttestationReport
from kronos_attest.verifier import (
    GENESIS_HASH,
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


def _make_multi_case_chain(
    case_ids: list[str | None], day: str = "2026-06-25"
) -> list[dict[str, Any]]:
    """Like ``_make_chain``, but each event may belong to a different
    ``case_id`` -- builds ONE real, contiguous org chain (not independent
    single-genesis links per event), so filtering it down to one case's own
    subset produces a genuinely non-contiguous slice of the real chain --
    exactly the P1-W19 regression scenario."""
    events = []
    prev = GENESIS_HASH
    for i, case_id in enumerate(case_ids):
        ev = _make_event(i, prev_hash=prev, case_id=case_id, day=day)
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
        # Domain-separated leaf hash (0x00 prefix, AUDIT-04), not bare sha256.
        assert root == hashlib.sha256(b"\x00" + h.encode()).hexdigest()

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

    def test_anchor_event_without_tsa_token_is_not_reported_anchored(self) -> None:
        """AUDIT-07: no real tsa_token present -> not cryptographically anchored."""
        events = _make_chain(2)
        tsa_event = _make_event(99, event_type="audit.merkle_anchored", day="2026-06-24")
        tsa_event["details"] = {"day": "2026-06-24", "root_hash": "abcd"}
        events.append(tsa_event)
        reporter = AttestationReport()
        report = reporter.day_report(events + [tsa_event], "2026-06-24")
        assert report.tsa_anchored is False


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


class TestCaseReportMultiCaseRegression:
    """P1-W19: case_report()'s chain_valid must not spuriously break for a
    real multi-case org -- found live via poc/kronos_attest_export/
    verifying the new GET /api/audit/export route against a real
    Postgres-backed org with two interleaved cases. Root cause: the old
    code re-verified the case-filtered subset in isolation from a fixed
    genesis hash, which is not how the real hash chain works -- only the
    org's FULL history is a real, contiguous chain."""

    def test_case_report_chain_valid_true_for_untampered_multi_case_org(self) -> None:
        case_a = str(uuid.uuid4())
        case_b = str(uuid.uuid4())
        # Interleaved, not grouped by case -- the exact shape that exposed
        # the bug (a real org's events are never neatly grouped by case).
        events = _make_multi_case_chain([case_a, case_b, case_a, case_b, case_a])

        reporter = AttestationReport()
        report_a = reporter.case_report(events, case_a)
        report_b = reporter.case_report(events, case_b)

        assert report_a.event_count == 3
        assert (
            report_a.chain_valid is True
        ), "a real, untampered multi-case org must not report chain_valid: false"
        assert report_a.break_count == 0
        assert report_a.org_chain_fully_intact is True

        assert report_b.event_count == 2
        assert report_b.chain_valid is True
        assert report_b.break_count == 0
        assert report_b.org_chain_fully_intact is True

    def test_case_report_detects_real_tamper_within_its_own_case(self) -> None:
        case_a = str(uuid.uuid4())
        case_b = str(uuid.uuid4())
        events = _make_multi_case_chain([case_a, case_b, case_a, case_b])
        # Tamper with case_a's second event (overall index 2).
        tampered = dict(events[2])
        tampered["row_hash"] = "f" * 64
        events[2] = tampered

        reporter = AttestationReport()
        report_a = reporter.case_report(events, case_a)
        report_b = reporter.case_report(events, case_b)

        assert report_a.chain_valid is False, "tamper within case_a's own event must be detected"
        assert report_a.break_count == 1
        assert report_a.org_chain_fully_intact is False

        # case_b's own event at overall index 3 comes AFTER the tamper at
        # index 2 in the real chain, and its real stored hash was computed
        # against index 2's ORIGINAL (pre-tamper) hash -- so it correctly
        # cannot be certified as untampered either, even though case_b's own
        # event content was never touched. This cascading is the correct,
        # conservative security property of a real hash chain (ChainVerifier
        # always advances using the STORED hash, tampered or not, so any
        # break renders everything chained after it unverifiable too) --
        # NOT a bug, and NOT what P1-W19 was about (P1-W19 was isolated
        # subsets reporting spurious breaks with ZERO real tampering
        # anywhere, which the untampered regression test above covers).
        assert report_b.chain_valid is False, (
            "case_b's event chained AFTER the tamper point is correctly "
            "unverifiable too -- a real security property, not a bug"
        )
        assert report_b.break_count == 1
        assert report_b.org_chain_fully_intact is False


class TestDayReportMultiDayRegression:
    """P1-W19: day_report()'s chain_valid must not spuriously break for an
    org whose history spans more than one day -- the identical bug/fix as
    TestCaseReportMultiCaseRegression, for the day-scoped report."""

    def test_day_report_chain_valid_true_for_untampered_multi_day_org(self) -> None:
        day1_events = _make_chain(2, day="2026-06-24")
        # Continue the SAME real chain into day 2 -- not a fresh genesis
        # link, exactly like a real org's audit log spanning multiple days.
        prev = day1_events[-1]["row_hash"]
        day2_events = []
        for i in range(2):
            ev = _make_event(i + 2, prev_hash=prev, day="2026-06-25")
            prev = ev["row_hash"]
            day2_events.append(ev)
        all_events = day1_events + day2_events

        reporter = AttestationReport()
        report_day2 = reporter.day_report(all_events, "2026-06-25")

        assert report_day2.event_count == 2
        assert (
            report_day2.chain_valid is True
        ), "a real, untampered later day must not report chain_valid: false"
        assert report_day2.break_count == 0
        assert report_day2.org_chain_fully_intact is True
