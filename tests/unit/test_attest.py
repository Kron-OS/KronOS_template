"""Unit tests for the kronos_attest package (offline chain + Merkle verification)."""

from __future__ import annotations

import hashlib
import json
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


# ---------------------------------------------------------------------------
# CLI: --audit-log / --database-url / --org-id mutual exclusion (Gap Audit
# AA1 / P2-5) -- shared by verify/day-report/case-report via
# ``_live_or_offline_options``/``_resolve_events`` in kronos_attest/cli.py.
#
# Per CLAUDE.md SS B.5 ("mock only external dependencies, not domain
# objects"), the tests here either need no I/O at all (pure Click option
# parsing + validation, exercised via CliRunner), or mock only the one
# external dependency -- the live Postgres fetch itself
# (``kronos_attest.cli._fetch_live_events``) -- never the domain objects
# (ChainVerifier/AttestationReport) it feeds. The real end-to-end run
# against a real Postgres is a separate, required verification step done in
# poc/kronos_attest_live_mode/ (CLAUDE.md SS F), not a substitute for it.
# ---------------------------------------------------------------------------


class TestCLILiveModeValidation:
    def test_verify_neither_source_given(self) -> None:
        from click.testing import CliRunner

        from kronos_attest.cli import cli

        result = CliRunner().invoke(cli, ["verify", "--event-id", "e1"])
        assert result.exit_code == 2
        assert "Provide either --audit-log" in result.output

    def test_verify_both_audit_log_and_org_id_given(self, tmp_path: Any) -> None:
        from click.testing import CliRunner

        from kronos_attest.cli import cli

        audit_log = tmp_path / "audit.json"
        audit_log.write_text(json.dumps(_make_chain(1)))

        result = CliRunner().invoke(
            cli,
            [
                "verify",
                "--audit-log",
                str(audit_log),
                "--org-id",
                str(uuid.uuid4()),
                "--event-id",
                "e1",
            ],
        )
        assert result.exit_code == 2
        assert "not both" in result.output

    def test_day_report_org_id_without_database_url(self) -> None:
        from click.testing import CliRunner

        from kronos_attest.cli import cli

        result = CliRunner().invoke(
            cli, ["day-report", "--org-id", str(uuid.uuid4()), "--day", "2026-06-25"]
        )
        assert result.exit_code == 2
        assert "--org-id given without --database-url" in result.output

    def test_case_report_database_url_without_org_id(self) -> None:
        from click.testing import CliRunner

        from kronos_attest.cli import cli

        result = CliRunner().invoke(
            cli,
            [
                "case-report",
                "--database-url",
                "postgresql+asyncpg://x:x@localhost/x",
                "--case-id",
                "c1",
            ],
        )
        assert result.exit_code == 2
        assert "--database-url given without --org-id" in result.output

    def test_verify_invalid_org_id_uuid(self) -> None:
        from click.testing import CliRunner

        from kronos_attest.cli import cli

        result = CliRunner().invoke(
            cli,
            [
                "verify",
                "--database-url",
                "postgresql+asyncpg://x:x@localhost/x",
                "--org-id",
                "not-a-uuid",
                "--event-id",
                "e1",
            ],
        )
        assert result.exit_code == 2
        assert "--org-id must be a valid UUID" in result.output

    def test_audit_log_explicit_flag_wins_over_ambient_database_url_env(
        self, tmp_path: Any, monkeypatch: Any
    ) -> None:
        """An ambient DATABASE_URL left set in a dev shell (this repo's own
        poc/ scripts export it) must not turn a plain --audit-log
        invocation into a spurious 'both given' error -- --org-id (which
        has no env fallback) is the only thing that selects live mode."""
        from click.testing import CliRunner

        from kronos_attest.cli import cli

        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://ambient:ambient@localhost/ambient")
        audit_log = tmp_path / "audit.json"
        events = _make_chain(1)
        audit_log.write_text(json.dumps(events))

        result = CliRunner().invoke(
            cli,
            ["verify", "--audit-log", str(audit_log), "--event-id", events[0]["event_id"]],
        )
        assert result.exit_code == 0, result.output
        assert "Chain intact" in result.output


class TestCLILiveModeFetch:
    """Live mode's happy path with the Postgres fetch itself mocked out."""

    def test_day_report_uses_live_fetch(self, monkeypatch: Any) -> None:
        from click.testing import CliRunner

        import kronos_attest.cli as cli_module

        events = _make_chain(3, day="2026-06-25")

        async def fake_fetch(database_url: str, org_id: uuid.UUID) -> list[dict[str, Any]]:
            assert database_url == "postgresql+asyncpg://x:x@localhost/x"
            assert isinstance(org_id, uuid.UUID)
            return events

        monkeypatch.setattr(cli_module, "_fetch_live_events", fake_fetch)

        result = CliRunner().invoke(
            cli_module.cli,
            [
                "day-report",
                "--database-url",
                "postgresql+asyncpg://x:x@localhost/x",
                "--org-id",
                str(uuid.uuid4()),
                "--day",
                "2026-06-25",
            ],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert data["event_count"] == 3
        assert data["chain_valid"] is True

    def test_case_report_reads_database_url_from_env_var(self, monkeypatch: Any) -> None:
        """DATABASE_URL env var fallback matches migrations/env.py's own
        convention -- setting it plus --org-id (no --audit-log, no
        explicit --database-url flag) must select live mode."""
        from click.testing import CliRunner

        import kronos_attest.cli as cli_module

        events = _make_chain(2, day="2026-06-25")

        async def fake_fetch(database_url: str, org_id: uuid.UUID) -> list[dict[str, Any]]:
            assert database_url == "postgresql+asyncpg://env:env@localhost/env"
            return events

        monkeypatch.setattr(cli_module, "_fetch_live_events", fake_fetch)
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://env:env@localhost/env")

        result = CliRunner().invoke(
            cli_module.cli,
            ["case-report", "--org-id", str(uuid.uuid4()), "--case-id", events[0]["case_id"]],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert data["case_id"] == events[0]["case_id"]


# ---------------------------------------------------------------------------
# case-report --verify-evidence-hashes (BB1 -- live MinIO evidence-hash
# re-verification, follow-on to AA1's live-Postgres mode).
#
# Same mocking discipline as TestCLILiveModeValidation/TestCLILiveModeFetch
# above: pure Click validation needs no I/O at all, and the happy path mocks
# only the one external-dependency boundary function
# (``kronos_attest.cli._fetch_live_events_and_evidence_integrity``), never
# the domain objects (AttestationReport/ChainVerifier) it feeds. The real
# end-to-end run against real Postgres + real MinIO (including a genuine
# corrupted-object MISMATCH) is the separate, required verification step in
# poc/kronos_attest_evidence_hash_check/ (CLAUDE.md SS F).
# ---------------------------------------------------------------------------


class TestCLIVerifyEvidenceHashesValidation:
    def test_rejects_verify_evidence_hashes_with_audit_log(self, tmp_path: Any) -> None:
        from click.testing import CliRunner

        from kronos_attest.cli import cli

        audit_log = tmp_path / "audit.json"
        audit_log.write_text(json.dumps(_make_chain(1)))

        result = CliRunner().invoke(
            cli,
            [
                "case-report",
                "--audit-log",
                str(audit_log),
                "--case-id",
                "c1",
                "--verify-evidence-hashes",
            ],
        )
        assert result.exit_code == 2
        assert "--verify-evidence-hashes requires live Postgres mode" in result.output

    def test_rejects_verify_evidence_hashes_without_minio_creds(self) -> None:
        from click.testing import CliRunner

        from kronos_attest.cli import cli

        result = CliRunner().invoke(
            cli,
            [
                "case-report",
                "--database-url",
                "postgresql+asyncpg://x:x@localhost/x",
                "--org-id",
                str(uuid.uuid4()),
                "--case-id",
                "c1",
                "--verify-evidence-hashes",
            ],
        )
        assert result.exit_code == 2
        assert "requires --minio-endpoint/--minio-access-key/--minio-secret-key" in result.output

    def test_rejects_verify_evidence_hashes_without_org_id(self) -> None:
        """--verify-evidence-hashes alone (no --org-id/--database-url at all)
        must fail with a clear live-mode-required message, not a confusing
        MinIO-creds message or a silent offline fallback."""
        from click.testing import CliRunner

        from kronos_attest.cli import cli

        result = CliRunner().invoke(
            cli,
            [
                "case-report",
                "--case-id",
                "c1",
                "--verify-evidence-hashes",
                "--minio-endpoint",
                "http://localhost:9000",
                "--minio-access-key",
                "ak",
                "--minio-secret-key",
                "sk",
            ],
        )
        assert result.exit_code == 2
        assert "requires both --database-url and --org-id" in result.output

    def test_rejects_verify_evidence_hashes_invalid_org_id(self) -> None:
        from click.testing import CliRunner

        from kronos_attest.cli import cli

        result = CliRunner().invoke(
            cli,
            [
                "case-report",
                "--database-url",
                "postgresql+asyncpg://x:x@localhost/x",
                "--org-id",
                "not-a-uuid",
                "--case-id",
                "c1",
                "--verify-evidence-hashes",
                "--minio-endpoint",
                "http://localhost:9000",
                "--minio-access-key",
                "ak",
                "--minio-secret-key",
                "sk",
            ],
        )
        assert result.exit_code == 2
        assert "--org-id must be a valid UUID" in result.output


class TestCLIVerifyEvidenceHashesFetch:
    def test_verify_evidence_hashes_happy_path(self, monkeypatch: Any) -> None:
        """The CLI plumbs --minio-* options through to the combined live
        fetch+evidence-check helper and surfaces its result under the new
        top-level "evidence_integrity" JSON key -- the actual re-hashing
        against real MinIO is exercised for real in
        poc/kronos_attest_evidence_hash_check/, not here."""
        from click.testing import CliRunner

        import kronos_attest.cli as cli_module

        case_id = str(uuid.uuid4())
        evidence_id_verified = str(uuid.uuid4())
        evidence_id_mismatch = str(uuid.uuid4())
        evidence_id_pending = str(uuid.uuid4())
        events = [
            _make_event(0, case_id=case_id, evidence_id=evidence_id_verified),
        ]

        expected_integrity = {
            evidence_id_verified: {
                "status": "verified",
                "expected_sha256": "a" * 64,
                "computed_sha256": "a" * 64,
            },
            evidence_id_mismatch: {
                "status": "MISMATCH",
                "expected_sha256": "a" * 64,
                "computed_sha256": "b" * 64,
            },
            evidence_id_pending: {"status": "not_yet_hashed"},
        }

        captured: dict[str, Any] = {}

        async def fake_fetch(
            database_url: str,
            org_id: uuid.UUID,
            case_id_arg: str,
            minio_endpoint: str,
            minio_access_key: str,
            minio_secret_key: str,
            minio_use_tls: bool,
        ) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
            captured["database_url"] = database_url
            captured["org_id"] = org_id
            captured["case_id"] = case_id_arg
            captured["minio_endpoint"] = minio_endpoint
            captured["minio_access_key"] = minio_access_key
            captured["minio_secret_key"] = minio_secret_key
            captured["minio_use_tls"] = minio_use_tls
            return events, expected_integrity

        monkeypatch.setattr(cli_module, "_fetch_live_events_and_evidence_integrity", fake_fetch)

        result = CliRunner().invoke(
            cli_module.cli,
            [
                "case-report",
                "--database-url",
                "postgresql+asyncpg://x:x@localhost/x",
                "--org-id",
                str(uuid.uuid4()),
                "--case-id",
                case_id,
                "--verify-evidence-hashes",
                "--minio-endpoint",
                "http://localhost:9000",
                "--minio-access-key",
                "ak",
                "--minio-secret-key",
                "sk",
                "--minio-use-tls",
                "false",
            ],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert data["case_id"] == case_id
        assert data["evidence_integrity"] == expected_integrity
        assert captured["minio_endpoint"] == "http://localhost:9000"
        assert captured["minio_use_tls"] is False

    def test_verify_evidence_hashes_reads_minio_creds_from_env(self, monkeypatch: Any) -> None:
        """MINIO_ENDPOINT/MINIO_ACCESS_KEY/MINIO_SECRET_KEY env fallback
        mirrors --database-url's own DATABASE_URL convention."""
        from click.testing import CliRunner

        import kronos_attest.cli as cli_module

        case_id = str(uuid.uuid4())
        events = [_make_event(0, case_id=case_id)]

        async def fake_fetch(
            database_url: str,
            org_id: uuid.UUID,
            case_id_arg: str,
            minio_endpoint: str,
            minio_access_key: str,
            minio_secret_key: str,
            minio_use_tls: bool,
        ) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
            assert minio_endpoint == "http://env-minio:9000"
            assert minio_access_key == "env-ak"
            assert minio_secret_key == "env-sk"
            return events, {}

        monkeypatch.setattr(cli_module, "_fetch_live_events_and_evidence_integrity", fake_fetch)
        monkeypatch.setenv("MINIO_ENDPOINT", "http://env-minio:9000")
        monkeypatch.setenv("MINIO_ACCESS_KEY", "env-ak")
        monkeypatch.setenv("MINIO_SECRET_KEY", "env-sk")

        result = CliRunner().invoke(
            cli_module.cli,
            [
                "case-report",
                "--database-url",
                "postgresql+asyncpg://x:x@localhost/x",
                "--org-id",
                str(uuid.uuid4()),
                "--case-id",
                case_id,
                "--verify-evidence-hashes",
            ],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert data["evidence_integrity"] == {}

    def test_case_report_offline_mode_has_no_evidence_integrity_key(self, tmp_path: Any) -> None:
        """Regression guard: the new key must never appear unless
        --verify-evidence-hashes was actually given -- offline mode's output
        shape must stay byte-identical to before this change."""
        from click.testing import CliRunner

        from kronos_attest.cli import cli

        case_id = str(uuid.uuid4())
        events = _make_chain(1)
        events[0]["case_id"] = case_id
        audit_log = tmp_path / "audit.json"
        audit_log.write_text(json.dumps(events))

        result = CliRunner().invoke(
            cli, ["case-report", "--audit-log", str(audit_log), "--case-id", case_id]
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.stdout)
        assert "evidence_integrity" not in data
        assert data["event_count"] == 1


# ---------------------------------------------------------------------------
# Milestone CC finding: --database-url/--minio-secret-key/--minio-access-key
# are real credential-bearing values. Passing them as a literal CLI
# argument (rather than the documented, preferred env-var fallback) leaks
# them into `ps`/`/proc/<pid>/cmdline` and typically shell history. Warn
# loudly on stderr whenever this happens -- never block (CLI-supplied
# secrets remain supported for real scripting use cases), but the risk
# must never be silent.
# ---------------------------------------------------------------------------


class TestCLISecretOptionWarnings:
    def test_warns_when_database_url_given_as_cli_flag(self, monkeypatch: Any) -> None:
        from click.testing import CliRunner

        import kronos_attest.cli as cli_module

        events = _make_chain(1, day="2026-06-25")

        async def fake_fetch(database_url: str, org_id: uuid.UUID) -> list[dict[str, Any]]:
            return events

        monkeypatch.setattr(cli_module, "_fetch_live_events", fake_fetch)

        result = CliRunner().invoke(
            cli_module.cli,
            [
                "day-report",
                "--database-url",
                "postgresql+asyncpg://x:x@localhost/x",
                "--org-id",
                str(uuid.uuid4()),
                "--day",
                "2026-06-25",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "--database-url was passed as a literal command-line argument" in result.stderr

    def test_no_warning_when_database_url_from_env_var(self, monkeypatch: Any) -> None:
        from click.testing import CliRunner

        import kronos_attest.cli as cli_module

        events = _make_chain(1, day="2026-06-25")

        async def fake_fetch(database_url: str, org_id: uuid.UUID) -> list[dict[str, Any]]:
            return events

        monkeypatch.setattr(cli_module, "_fetch_live_events", fake_fetch)
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://env:env@localhost/env")

        result = CliRunner().invoke(
            cli_module.cli,
            ["day-report", "--org-id", str(uuid.uuid4()), "--day", "2026-06-25"],
        )
        assert result.exit_code == 0, result.output
        assert "was passed as a literal command-line argument" not in result.stderr

    def test_no_warning_in_offline_audit_log_mode(self, tmp_path: Any) -> None:
        from click.testing import CliRunner

        from kronos_attest.cli import cli

        audit_log = tmp_path / "audit.json"
        audit_log.write_text(json.dumps(_make_chain(1, day="2026-06-25")))

        result = CliRunner().invoke(
            cli, ["day-report", "--audit-log", str(audit_log), "--day", "2026-06-25"]
        )
        assert result.exit_code == 0, result.output
        assert "was passed as a literal command-line argument" not in result.stderr

    def test_warns_for_minio_secret_and_access_key_cli_flags(self, monkeypatch: Any) -> None:
        from click.testing import CliRunner

        import kronos_attest.cli as cli_module

        events = _make_chain(1, day="2026-06-25")
        case_id = events[0]["case_id"]

        async def fake_fetch(
            database_url: str,
            org_id: uuid.UUID,
            case_id_arg: str,
            minio_endpoint: str,
            minio_access_key: str,
            minio_secret_key: str,
            minio_use_tls: bool,
        ) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
            return events, {}

        monkeypatch.setattr(cli_module, "_fetch_live_events_and_evidence_integrity", fake_fetch)

        result = CliRunner().invoke(
            cli_module.cli,
            [
                "case-report",
                "--database-url",
                "postgresql+asyncpg://x:x@localhost/x",
                "--org-id",
                str(uuid.uuid4()),
                "--case-id",
                case_id,
                "--verify-evidence-hashes",
                "--minio-endpoint",
                "http://localhost:9000",
                "--minio-access-key",
                "ak",
                "--minio-secret-key",
                "sk",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "--minio-secret-key was passed as a literal command-line argument" in result.stderr
        assert "--minio-access-key was passed as a literal command-line argument" in result.stderr

    def test_no_warning_when_minio_creds_from_env_vars(self, monkeypatch: Any) -> None:
        from click.testing import CliRunner

        import kronos_attest.cli as cli_module

        events = _make_chain(1, day="2026-06-25")
        case_id = events[0]["case_id"]

        async def fake_fetch(
            database_url: str,
            org_id: uuid.UUID,
            case_id_arg: str,
            minio_endpoint: str,
            minio_access_key: str,
            minio_secret_key: str,
            minio_use_tls: bool,
        ) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
            return events, {}

        monkeypatch.setattr(cli_module, "_fetch_live_events_and_evidence_integrity", fake_fetch)
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")
        monkeypatch.setenv("MINIO_ENDPOINT", "http://localhost:9000")
        monkeypatch.setenv("MINIO_ACCESS_KEY", "ak")
        monkeypatch.setenv("MINIO_SECRET_KEY", "sk")

        result = CliRunner().invoke(
            cli_module.cli,
            [
                "case-report",
                "--org-id",
                str(uuid.uuid4()),
                "--case-id",
                case_id,
                "--verify-evidence-hashes",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "was passed as a literal command-line argument" not in result.stderr
