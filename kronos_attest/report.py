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

    def day_report(self, events: list[dict[str, Any]], day: str) -> DayReport:
        """Build a DayReport for events on the given ISO date."""
        day_events = [
            e for e in events if (e.get("occurred_at") or "").startswith(day)
        ]
        result = self._chain_verifier.verify(day_events)
        tsa_anchor = self._find_tsa_anchor(day_events, day)
        return DayReport(
            day=day,
            event_count=len(day_events),
            merkle_root=result.merkle_root,
            chain_valid=result.valid,
            break_count=len(result.breaks),
            tsa_anchored=tsa_anchor is not None,
            tsa_gen_time=tsa_anchor,
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
    def _find_tsa_anchor(events: list[dict[str, Any]], day: str) -> str | None:
        """Return gen_time of TSA anchor event for the given day, if present."""
        for ev in events:
            if ev.get("event_type") == "audit.merkle_anchored":
                details = ev.get("details") or {}
                if details.get("day") == day:
                    return ev.get("occurred_at")
        return None
