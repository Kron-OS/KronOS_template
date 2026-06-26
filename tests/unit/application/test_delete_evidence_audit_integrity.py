"""Audit-integrity bug-report test for EvidenceIntakeService.delete_evidence.

Audit finding M-1 (see docs/SECURITY_AUDIT.md): the service-layer
``delete_evidence`` writes ``details={"step_up_verified": True}`` into the
immutable chain-of-custody log unconditionally.  The value is a hard-coded
constant; the service performs no step-up verification itself and receives no
parameter describing whether step-up actually occurred.

Step-up is currently enforced only at the HTTP route layer.  Any other caller
of this service method (a future endpoint, a Celery task, a script, a test)
will still emit an audit record asserting ``step_up_verified: True`` even
though no MFA / step-up ticket was ever validated.  For a forensic platform
whose audit log is meant to be legally admissible evidence, recording an
unverifiable security assertion is a chain-of-custody integrity defect.

This test demonstrates the defect by invoking the service directly (i.e. the
way a non-HTTP caller would) and showing the fabricated assertion lands in the
audit trail.
"""

from __future__ import annotations

import uuid

import pytest

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


async def test_delete_evidence_records_fabricated_step_up_assertion() -> None:
    """Direct (non-HTTP) deletion still logs step_up_verified=True with no MFA.

    This locks in the current behaviour and flags it: the audit record claims a
    step-up verification that never happened at this layer.
    """
    audit_repo = InMemoryAuditLogRepository()
    audit = AuditLogService(audit_repo)
    repo = InMemoryEvidenceRepository()

    org_id = uuid.uuid4()
    tenant = make_tenant_context(org_id=org_id, roles={Role.ORG_ADMIN})
    evidence = make_evidence(state=EvidenceState.RECEIVED, org_id=org_id)
    await repo.save(evidence)

    intake = _intake(repo, audit)

    # No step-up ticket, no MFA, no acr=aal2 — just a direct service call.
    await intake.delete_evidence(evidence_id=evidence.evidence_id, tenant=tenant)

    deleted_events = [
        e for e in audit_repo.events if e.event_type == AuditEventType.EVIDENCE_DELETED
    ]
    assert len(deleted_events) == 1
    # FINDING M-1: this assertion is fabricated — nothing verified step-up here.
    assert deleted_events[0].details.get("step_up_verified") is True


@pytest.mark.xfail(
    reason="FINDING M-1: step_up_verified should reflect a real verification "
    "signal passed into the service, not a hard-coded constant. Until the "
    "service records the actual step-up outcome, this desired property fails.",
    strict=True,
)
async def test_audit_should_not_assert_unverified_step_up() -> None:
    """Desired behaviour: the service must not assert step-up it did not verify."""
    audit_repo = InMemoryAuditLogRepository()
    audit = AuditLogService(audit_repo)
    repo = InMemoryEvidenceRepository()

    org_id = uuid.uuid4()
    tenant = make_tenant_context(org_id=org_id, roles={Role.ORG_ADMIN})
    evidence = make_evidence(state=EvidenceState.RECEIVED, org_id=org_id)
    await repo.save(evidence)

    await _intake(repo, audit).delete_evidence(evidence_id=evidence.evidence_id, tenant=tenant)

    deleted = [e for e in audit_repo.events if e.event_type == AuditEventType.EVIDENCE_DELETED][0]
    # When no verification signal is supplied, the log must NOT claim True.
    assert deleted.details.get("step_up_verified") is not True
