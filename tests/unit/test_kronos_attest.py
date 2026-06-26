"""Unit tests for the kronos_attest standalone package."""
import hashlib
import json
import os
import tempfile

import pytest

from kronos_attest.verifier import (
    GENESIS_HASH,
    ChainVerifier,
    MerkleVerifier,
    build_merkle_root,
    compute_row_hash,
    merkle_proof,
)
from kronos_attest.report import AttestationReport


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_event(seq: int, prev_hash: str, **extra) -> dict:
    ev = {
        "event_id": f"00000000-0000-0000-0000-{seq:012d}",
        "event_type": "evidence.upload.requested",
        "actor_user_id": "user-1",
        "actor_username": "alice",
        "org_id": "org-1",
        "case_id": "case-1",
        "evidence_id": f"ev-{seq}",
        "details": {},
        "occurred_at": f"2026-06-25T0{seq % 24}:00:00+00:00",
        "sequence_number": seq,
        **extra,
    }
    ev["prev_row_hash"] = prev_hash
    ev["row_hash"] = compute_row_hash(prev_hash, ev)
    return ev


def _chain(n: int) -> list[dict]:
    events = []
    prev = GENESIS_HASH
    for i in range(n):
        ev = _make_event(i, prev)
        prev = ev["row_hash"]
        events.append(ev)
    return events


# ---------------------------------------------------------------------------
# compute_row_hash
# ---------------------------------------------------------------------------

class TestComputeRowHash:
    def test_deterministic(self):
        ev = _make_event(0, GENESIS_HASH)
        h1 = compute_row_hash(GENESIS_HASH, ev)
        h2 = compute_row_hash(GENESIS_HASH, ev)
        assert h1 == h2

    def test_changes_with_prev(self):
        ev = _make_event(0, GENESIS_HASH)
        h1 = compute_row_hash(GENESIS_HASH, ev)
        h2 = compute_row_hash("different-prev", ev)
        assert h1 != h2

    def test_changes_with_event(self):
        ev1 = _make_event(0, GENESIS_HASH)
        ev2 = _make_event(1, GENESIS_HASH)
        h1 = compute_row_hash(GENESIS_HASH, ev1)
        h2 = compute_row_hash(GENESIS_HASH, ev2)
        assert h1 != h2


# ---------------------------------------------------------------------------
# build_merkle_root
# ---------------------------------------------------------------------------

class TestBuildMerkleRoot:
    def test_empty_list(self):
        root = build_merkle_root([])
        assert root == hashlib.sha256(b"empty").hexdigest()

    def test_single_element(self):
        hashes = ["abc"]
        root = build_merkle_root(hashes)
        # Single element: layer = [sha256("abc".encode).digest()], no iterations
        assert root == hashlib.sha256(b"abc").hexdigest()

    def test_power_of_two(self):
        hashes = ["a", "b", "c", "d"]
        root = build_merkle_root(hashes)
        assert len(root) == 64  # hex SHA-256

    def test_odd_count(self):
        hashes = ["a", "b", "c"]
        root = build_merkle_root(hashes)
        assert len(root) == 64

    def test_different_inputs_give_different_roots(self):
        r1 = build_merkle_root(["a", "b"])
        r2 = build_merkle_root(["a", "c"])
        assert r1 != r2


# ---------------------------------------------------------------------------
# merkle_proof
# ---------------------------------------------------------------------------

class TestMerkleProof:
    def test_proof_verifies(self):
        hashes = ["a", "b", "c", "d"]
        verifier = MerkleVerifier()
        root = build_merkle_root(hashes)
        for i, h in enumerate(hashes):
            proof = merkle_proof(hashes, i)
            assert verifier.verify_proof(h, proof, root, i)

    def test_wrong_leaf_fails(self):
        hashes = ["a", "b", "c", "d"]
        verifier = MerkleVerifier()
        root = build_merkle_root(hashes)
        proof = merkle_proof(hashes, 0)
        assert not verifier.verify_proof("wrong", proof, root, 0)

    def test_empty_hashes(self):
        assert merkle_proof([], 0) == []


# ---------------------------------------------------------------------------
# ChainVerifier
# ---------------------------------------------------------------------------

class TestChainVerifier:
    def test_valid_chain(self):
        events = _chain(10)
        result = ChainVerifier().verify(events)
        assert result.valid
        assert result.event_count == 10
        assert len(result.breaks) == 0

    def test_empty_chain(self):
        result = ChainVerifier().verify([])
        assert result.valid
        assert result.event_count == 0

    def test_single_event_chain(self):
        events = _chain(1)
        result = ChainVerifier().verify(events)
        assert result.valid

    def test_tampered_row_hash(self):
        events = _chain(5)
        # Tamper the third event's stored hash
        events[2] = {**events[2], "row_hash": "deadbeef" * 8}
        result = ChainVerifier().verify(events)
        assert not result.valid
        assert len(result.breaks) >= 1

    def test_out_of_order_input(self):
        events = _chain(5)
        shuffled = events[::-1]  # reverse
        result = ChainVerifier().verify(shuffled)
        assert result.valid  # should sort by sequence_number

    def test_merkle_root_changes_on_tamper(self):
        events = _chain(5)
        clean_result = ChainVerifier().verify(events)
        events[0] = {**events[0], "row_hash": "00" * 32}
        tampered_result = ChainVerifier().verify(events)
        assert clean_result.merkle_root != tampered_result.merkle_root


# ---------------------------------------------------------------------------
# AttestationReport
# ---------------------------------------------------------------------------

class TestAttestationReport:
    def test_day_report_filters_by_date(self):
        events = _chain(3)
        report = AttestationReport().day_report(events, "2026-06-25")
        assert report.day == "2026-06-25"
        assert report.event_count == 3

    def test_day_report_empty_day(self):
        events = _chain(3)
        report = AttestationReport().day_report(events, "2099-01-01")
        assert report.event_count == 0
        assert report.chain_valid  # empty chain is valid

    def test_case_report(self):
        events = _chain(4)
        # All events have case_id = "case-1"
        report = AttestationReport().case_report(events, "case-1")
        assert report.case_id == "case-1"
        assert report.event_count == 4

    def test_case_report_unknown_case(self):
        events = _chain(4)
        report = AttestationReport().case_report(events, "unknown-case")
        assert report.event_count == 0

    def test_case_report_evidence_ids_deduplicated(self):
        events = _chain(4)
        report = AttestationReport().case_report(events, "case-1")
        # Each event has different evidence_id (ev-0, ev-1, ev-2, ev-3)
        assert len(report.evidence_ids) == 4

    def test_tsa_anchor_detected(self):
        events = _chain(2)
        anchor = {
            "event_id": "anchor-uuid",
            "event_type": "audit.merkle_anchored",
            "occurred_at": "2026-06-25T02:00:00+00:00",
            "sequence_number": 99,
            "details": {"day": "2026-06-25"},
            "case_id": None,
            "evidence_id": None,
            "prev_row_hash": GENESIS_HASH,
            "row_hash": "a" * 64,
        }
        events.append(anchor)
        report = AttestationReport().day_report(events, "2026-06-25")
        assert report.tsa_anchored
        assert report.tsa_gen_time is not None


# ---------------------------------------------------------------------------
# CLI integration (via CliRunner)
# ---------------------------------------------------------------------------

class TestCLI:
    def test_verify_command_success(self, tmp_path):
        from click.testing import CliRunner
        from kronos_attest.cli import cli

        events = _chain(3)
        audit_log = tmp_path / "audit.json"
        audit_log.write_text(json.dumps(events))

        runner = CliRunner()
        result = runner.invoke(cli, ["verify", "--audit-log", str(audit_log), "--event-id", events[1]["event_id"]])
        assert result.exit_code == 0
        assert "Chain intact" in result.output

    def test_verify_command_missing_event(self, tmp_path):
        from click.testing import CliRunner
        from kronos_attest.cli import cli

        events = _chain(3)
        audit_log = tmp_path / "audit.json"
        audit_log.write_text(json.dumps(events))

        runner = CliRunner()
        result = runner.invoke(cli, ["verify", "--audit-log", str(audit_log), "--event-id", "no-such-event"])
        assert result.exit_code == 1

    def test_merkle_root_command(self, tmp_path):
        from click.testing import CliRunner
        from kronos_attest.cli import cli

        events = _chain(2)
        audit_log = tmp_path / "audit.json"
        audit_log.write_text(json.dumps(events))

        runner = CliRunner()
        result = runner.invoke(cli, ["merkle-root", "--audit-log", str(audit_log)])
        assert result.exit_code == 0
        assert len(result.output.strip()) == 64  # hex SHA-256

    def test_day_report_command(self, tmp_path):
        from click.testing import CliRunner
        from kronos_attest.cli import cli

        events = _chain(3)
        audit_log = tmp_path / "audit.json"
        audit_log.write_text(json.dumps(events))

        runner = CliRunner()
        result = runner.invoke(cli, ["day-report", "--audit-log", str(audit_log), "--day", "2026-06-25"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["event_count"] == 3
        assert data["chain_valid"] is True
