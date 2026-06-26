"""Audit-integrity tests for EvidenceIntakeService.delete_evidence (finding M-1).

Originally a bug report: the service wrote ``step_up_verified: True`` into the
immutable chain-of-custody log unconditionally, even when no step-up verification
had occurred. The fix adds a ``step_up_verified`` parameter (default ``False``)
so the audit record reflects what actually happened. These tests assert the
corrected behaviour. See ``docs/SECURITY_AUDIT.md`` (M-1).
"""

from __future__ import annotations

import uuid

from src.application.audit_log import AuditLogService
from src.application.evidence_intake import EvidenceIntakeService
from src.domain.audit import AuditEventType
from src.domain.evidence import EvidenceState
from src.domain.user import Role
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository
from tests.fixtures.factories import make_evidence, make_tenant_context


def _intake(repo: InMemoryEvidenceRepository, audit: AuditLogService) -> EvidenceIntakeService:
    # delete_evidence only touches the repository and the audit log, so the
    # remaining collaborators are irrelevant to this code path.
    return EvidenceIntakeService(
        evidence_repository=repo,
        storage=None,  # type: ignore[arg-type]
        audit_log=audit,
        validator=None,  # type: ignore[arg-type]
        scanner=None,  # type: ignore[arg-type]
        hash_service=None,  # type: ignore[arg-type]
        max_upload_bytes=1,
    )


async def _delete(step_up_verified: bool | None) -> dict:
    audit_repo = InMemoryAuditLogRepository()
    audit = AuditLogService(audit_repo)
    repo = InMemoryEvidenceRepository()

    org_id = uuid.uuid4()
    tenant = make_tenant_context(org_id=org_id, roles={Role.ORG_ADMIN})
    evidence = make_evidence(state=EvidenceState.RECEIVED, org_id=org_id)
    await repo.save(evidence)

    intake = _intake(repo, audit)
    if step_up_verified is None:
        await intake.delete_evidence(evidence_id=evidence.evidence_id, tenant=tenant)
    else:
        await intake.delete_evidence(
            evidence_id=evidence.evidence_id, tenant=tenant, step_up_verified=step_up_verified
        )

    deleted = [e for e in audit_repo.events if e.event_type == AuditEventType.EVIDENCE_DELETED]
    assert len(deleted) == 1
    return deleted[0].details


async def test_direct_call_does_not_assert_unverified_step_up() -> None:
    """A caller that did not verify step-up must not have the log claim it did."""
    # Default (no step-up signal) and explicit False must both record False.
    assert (await _delete(None)).get("step_up_verified") is False
    assert (await _delete(False)).get("step_up_verified") is False


async def test_verified_step_up_is_recorded_truthfully() -> None:
    """When the route consumed a valid aal2 ticket it passes True, and it is logged."""
    assert (await _delete(True)).get("step_up_verified") is True
