"""Unit tests for OrgQuota and Evidence's quota_held flag."""

from __future__ import annotations

import uuid

from src.domain.evidence import EvidenceState
from src.domain.quota import OrgQuota
from tests.fixtures.factories import make_evidence


class TestOrgQuota:
    def test_defaults_to_unlimited(self) -> None:
        quota = OrgQuota(org_id=uuid.uuid4())
        assert quota.storage_quota_bytes is None

    def test_with_quota_bytes_returns_new_instance(self) -> None:
        quota = OrgQuota(org_id=uuid.uuid4())
        updated = quota.with_quota_bytes(1_000_000)
        assert quota.storage_quota_bytes is None  # frozen; original untouched
        assert updated.storage_quota_bytes == 1_000_000
        assert updated.updated_at >= quota.updated_at

    def test_with_quota_bytes_can_clear_to_unlimited(self) -> None:
        quota = OrgQuota(org_id=uuid.uuid4(), storage_quota_bytes=500)
        cleared = quota.with_quota_bytes(None)
        assert cleared.storage_quota_bytes is None


class TestEvidenceQuotaHeld:
    def test_defaults_to_false(self) -> None:
        evidence = make_evidence(state=EvidenceState.RECEIVED)
        assert evidence.quota_held is False

    def test_with_quota_held_true_does_not_change_fsm_state(self) -> None:
        evidence = make_evidence(state=EvidenceState.RECEIVED)
        held = evidence.with_quota_held(True)
        assert held.quota_held is True
        assert held.state == EvidenceState.RECEIVED  # unchanged -- no FSM transition

    def test_with_quota_held_false_clears_flag(self) -> None:
        evidence = make_evidence(state=EvidenceState.RECEIVED).with_quota_held(True)
        resumed = evidence.with_quota_held(False)
        assert resumed.quota_held is False
        assert resumed.state == EvidenceState.RECEIVED
