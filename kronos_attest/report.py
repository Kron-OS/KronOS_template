"""Attestation reports: day and case summary reports from audit log exports."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from kronos_attest.verifier import ChainVerifier, MerkleVerifier


@dataclass
class DayReport:
    """Attestation report for all events on a single calendar day.

    ``chain_valid``/``break_count`` are scoped to THIS day's own events —
    see ``AttestationReport.day_report()``'s docstring for why they are
    computed as a subset of a full, unfiltered chain verification rather
    than an isolated re-chain over just the day-filtered events.
    ``org_chain_fully_intact`` additionally surfaces whether the org's
    ENTIRE audit history (not just this day) has zero breaks anywhere, so
    an auditor isn't blind to tampering elsewhere in the org while looking
    at one day's own report.
    """

    day: str  # ISO date: 2026-06-25
    event_count: int
    merkle_root: str
    chain_valid: bool
    break_count: int
    org_chain_fully_intact: bool
    tsa_anchored: bool = False
    tsa_gen_time: str | None = None


@dataclass
class CaseReport:
    """Attestation report scoped to a single case_id.

    ``chain_valid``/``break_count`` are scoped to THIS case's own events —
    see ``AttestationReport.case_report()``'s docstring for why they are
    computed as a subset of a full, unfiltered chain verification rather
    than an isolated re-chain over just the case-filtered events.
    ``org_chain_fully_intact`` additionally surfaces whether the org's
    ENTIRE audit history (not just this case) has zero breaks anywhere, so
    an auditor isn't blind to tampering elsewhere in the org while looking
    at one case's own report.
    """

    case_id: str
    event_count: int
    merkle_root: str
    chain_valid: bool
    break_count: int
    org_chain_fully_intact: bool
    evidence_ids: list[str] = field(default_factory=list)


class AttestationReport:
    """Generate attestation reports from exported audit log JSON."""

    def __init__(self) -> None:
        self._chain_verifier = ChainVerifier()
        self._merkle_verifier = MerkleVerifier()

    def day_report(
        self,
        events: list[dict[str, Any]],
        day: str,
        tsa_cert_path: str | None = None,
    ) -> DayReport:
        """Build a DayReport for events on the given ISO date.

        ``tsa_anchored`` now reflects a real, cryptographically verified RFC
        3161 signature (AUDIT-07/AUDIT-08) — it is no longer a string match
        against ``event_type``/``details.day``, which any tampered export
        could trivially fake by adding a plausible-looking JSON object.

        ``chain_valid``/``break_count`` are computed against a full,
        unfiltered ``ChainVerifier.verify(events)`` pass, then scoped down
        to breaks whose ``event_id`` falls within this day — NOT by
        re-running ``ChainVerifier.verify()`` over just the day-filtered
        subset (P1-W19, found 2026-08-16 verifying the new
        ``GET /api/audit/export`` route, `poc/kronos_attest_export/`).
        ``ChainVerifier`` recomputes each event's row hash by chaining
        against the *real, stored* hash of the event immediately before it
        *in the full org history* — a day-filtered subset's first event's
        real ``prev_row_hash`` almost never points at genesis, since it
        points at whatever org-wide event actually preceded it (a
        different day's event, for any org whose history spans more than
        one day). Re-verifying an isolated day-filtered subset from a fixed
        genesis hash spuriously reported ``chain_valid: false`` for any day
        that wasn't the org's very first, even with zero tampering — this
        is why ``day_report`` verifies the FULL chain once and asks "were
        any of THIS day's own events among the breaks," not "does this
        day's own isolated subset form a valid chain in a vacuum" (it never
        was one — only the org's full history is a real hash chain).
        ``merkle_root`` is still this day's own subset-scoped root (a
        distinct concept from chain validity — see ``ChainVerifier.verify``'s
        own docstring on why the Merkle layer always uses stored hashes).

        Note this does NOT make ``chain_valid`` a purely local property:
        ``ChainVerifier`` always advances its running hash using each
        event's *stored* row_hash (tampered or not — see its own docstring),
        so a single tamper at sequence N legitimately renders every event
        chained after it (regardless of which day/case they belong to) also
        unverifiable, until a later, independent re-anchor. A day/case
        report correctly inherits that cascade rather than hiding it — see
        ``org_chain_fully_intact`` for the org-wide picture.
        """
        day_events = [e for e in events if (e.get("occurred_at") or "").startswith(day)]
        day_event_ids = {e.get("event_id") for e in day_events}

        full_result = self._chain_verifier.verify(events)
        scoped_break_count = sum(1 for b in full_result.breaks if b.event_id in day_event_ids)

        # merkle_root is a genuinely day-scoped concept (the root of this
        # day's own leaf hashes) -- re-verifying the day-filtered subset
        # just for its merkle_root is correct and cheap; only chain_valid/
        # break_count must come from the full-chain pass above.
        day_result = self._chain_verifier.verify(day_events)

        tsa_anchored, tsa_gen_time = self._verify_tsa_anchor(day_events, day, tsa_cert_path)
        return DayReport(
            day=day,
            event_count=len(day_events),
            merkle_root=day_result.merkle_root,
            chain_valid=scoped_break_count == 0,
            break_count=scoped_break_count,
            org_chain_fully_intact=full_result.valid,
            tsa_anchored=tsa_anchored,
            tsa_gen_time=tsa_gen_time,
        )

    def case_report(self, events: list[dict[str, Any]], case_id: str) -> CaseReport:
        """Build a CaseReport scoped to a specific case_id.

        See ``day_report``'s docstring for the full rationale — the
        identical fix applies here: ``chain_valid``/``break_count`` come
        from a full, unfiltered chain verification scoped down to this
        case's own event_ids, not an isolated re-chain over just this
        case's events (which is not a real hash chain in isolation; the
        real chain is the org's full, contiguous history).
        """
        case_events = [e for e in events if e.get("case_id") == case_id]
        case_event_ids = {e.get("event_id") for e in case_events}

        full_result = self._chain_verifier.verify(events)
        scoped_break_count = sum(1 for b in full_result.breaks if b.event_id in case_event_ids)

        case_result = self._chain_verifier.verify(case_events)

        evidence_ids = list({e["evidence_id"] for e in case_events if e.get("evidence_id")})
        return CaseReport(
            case_id=case_id,
            event_count=len(case_events),
            merkle_root=case_result.merkle_root,
            chain_valid=scoped_break_count == 0,
            break_count=scoped_break_count,
            org_chain_fully_intact=full_result.valid,
            evidence_ids=sorted(evidence_ids),
        )

    @staticmethod
    def _verify_tsa_anchor(
        events: list[dict[str, Any]], day: str, tsa_cert_path: str | None
    ) -> tuple[bool, str | None]:
        """Find the day's anchor event and cryptographically verify its TSA token.

        Returns (True, gen_time) only if a real ``openssl ts -verify`` check
        against the embedded ``tsa_token``/``root_hash`` succeeds. An anchor
        event that exists but carries no token (TSA was unreachable at
        anchor time — see AuditLogService.anchor_day), or whose signature
        fails to verify, is reported as NOT anchored rather than silently
        trusted.
        """
        from kronos_attest.tsa import verify_merkle_anchor  # noqa: PLC0415

        for ev in events:
            if ev.get("event_type") != "audit.merkle_anchored":
                continue
            details = ev.get("details") or {}
            # AuditLogService.anchor_day() (src/application/audit_log.py)
            # stores this key as "date", not "day" -- confirmed by running
            # a real anchor_day() end to end (poc/chain_of_custody/): this
            # mismatch made day_report()'s tsa_anchored always False, even
            # for a day that was genuinely TSA-anchored, since every anchor
            # event was skipped here and control fell through to the final
            # `return False, None`.
            if details.get("date") != day:
                continue

            root_hash = details.get("root_hash")
            tsa_token_hex = details.get("tsa_token")
            if not root_hash or not tsa_token_hex:
                return False, None

            try:
                token_der = bytes.fromhex(tsa_token_hex)
                if verify_merkle_anchor(token_der, root_hash, tsa_cert_path):
                    return True, ev.get("occurred_at")
            except Exception:  # noqa: BLE001 — any failure means "not verified"
                return False, None
            return False, None
        return False, None
