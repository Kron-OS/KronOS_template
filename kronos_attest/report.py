"""Attestation reports: day and case summary reports from audit log exports."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from kronos_attest.verifier import ChainVerifier, MerkleVerifier


@dataclass
class DayReport:
    """Attestation report for all events on a single calendar day."""

    day: str  # ISO date: 2026-06-25
    event_count: int
    merkle_root: str
    chain_valid: bool
    break_count: int
    tsa_anchored: bool = False
    tsa_gen_time: str | None = None


@dataclass
class CaseReport:
    """Attestation report scoped to a single case_id."""

    case_id: str
    event_count: int
    merkle_root: str
    chain_valid: bool
    break_count: int
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
        """
        day_events = [
            e for e in events if (e.get("occurred_at") or "").startswith(day)
        ]
        result = self._chain_verifier.verify(day_events)
        tsa_anchored, tsa_gen_time = self._verify_tsa_anchor(day_events, day, tsa_cert_path)
        return DayReport(
            day=day,
            event_count=len(day_events),
            merkle_root=result.merkle_root,
            chain_valid=result.valid,
            break_count=len(result.breaks),
            tsa_anchored=tsa_anchored,
            tsa_gen_time=tsa_gen_time,
        )

    def case_report(self, events: list[dict[str, Any]], case_id: str) -> CaseReport:
        """Build a CaseReport scoped to a specific case_id."""
        case_events = [e for e in events if e.get("case_id") == case_id]
        result = self._chain_verifier.verify(case_events)
        evidence_ids = list(
            {e["evidence_id"] for e in case_events if e.get("evidence_id")}
        )
        return CaseReport(
            case_id=case_id,
            event_count=len(case_events),
            merkle_root=result.merkle_root,
            chain_valid=result.valid,
            break_count=len(result.breaks),
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
            if details.get("day") != day:
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
