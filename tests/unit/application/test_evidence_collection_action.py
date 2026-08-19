"""Unit tests for CollectForensicArtifactAction (roadmap M7/H3).

Mirrors test_playbook_actions.py's own idiom: the REAL application service
(here, EvidenceIntakeService) backed by in-memory/local fakes for the
external dependencies it owns (CLAUDE.md SS B.5) -- not a hand-rolled mock of
EvidenceIntakeService itself, since that would prove nothing about whether
this action actually drives the real intake workflow correctly.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from src.adapter.repository.detection import InMemoryDetectionRepository
from src.adapter.storage.local import LocalEvidenceStorage
from src.application.audit_log import AuditLogService
from src.application.evidence_collection_action import CollectForensicArtifactAction
from src.application.evidence_intake import EvidenceIntakeService
from src.application.hashing import HashService
from src.application.scanning import NoOpScanner
from src.application.validation import default_validator_chain
from src.domain.detection import Detection
from src.domain.evidence import EvidenceState
from src.exceptions import PlaybookError
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository
from tests.fixtures.factories import make_tenant_context

# Real CloudTrail-shaped content, same as test_evidence_intake.py.
_LOG_ARTIFACT = b'{"Records": []}'


@pytest.fixture
def local_storage(tmp_path: Path) -> LocalEvidenceStorage:
    return LocalEvidenceStorage(base_dir=tmp_path / "storage")


@pytest.fixture
def audit_service() -> AuditLogService:
    return AuditLogService(InMemoryAuditLogRepository())


@pytest.fixture
def intake(
    local_storage: LocalEvidenceStorage, audit_service: AuditLogService
) -> EvidenceIntakeService:
    return EvidenceIntakeService(
        evidence_repository=InMemoryEvidenceRepository(),
        storage=local_storage,
        audit_log=audit_service,
        validator=default_validator_chain(max_upload_bytes=1_000_000),
        scanner=NoOpScanner(),
        hash_service=HashService(),
        max_upload_bytes=1_000_000,
        # No task_queue -- start_intake() falls back to running
        # process_intake() inline, exactly as EvidenceIntakeService's own
        # docstring says test callers without Celery wired up should expect.
    )


@pytest.fixture
def detection_repo() -> InMemoryDetectionRepository:
    return InMemoryDetectionRepository()


def _make_detection(tenant, case_id: uuid.UUID | None, finding_id: str = "f-1") -> Detection:
    return Detection(
        org_id=tenant.org_id,
        org_alias=tenant.org_alias,
        case_id=case_id,
        finding_id=finding_id,
        detector_name="kronos-testorg-network-detector",
        source_index=f"kronos-{tenant.org_alias}-case-{case_id}-202608",
        finding_timestamp=datetime.now(UTC),
    )


def _artifact_file(tmp_path: Path, name: str = "eve.json", content: bytes = _LOG_ARTIFACT) -> Path:
    path = tmp_path / name
    path.write_bytes(content)
    return path


class TestCollectForensicArtifactAction:
    @pytest.mark.asyncio
    async def test_real_collection_reaches_received_with_correct_custody(
        self, tmp_path, detection_repo, intake, audit_service
    ) -> None:
        tenant = make_tenant_context()
        case_id = uuid.uuid4()
        detection = await detection_repo.save(_make_detection(tenant, case_id))
        artifact_path = _artifact_file(tmp_path)

        action = CollectForensicArtifactAction(detection_repo, intake, staging_dir=tmp_path)
        output = await action.execute(
            {
                "detection_id": str(detection.detection_id),
                "artifact_path": str(artifact_path),
                "artifact_label": "logs",
            },
            tenant,
        )

        assert output["evidence_state"] == EvidenceState.RECEIVED.value
        assert output["case_id"] == str(case_id)
        assert output["source_detection_id"] == str(detection.detection_id)
        assert output["artifact_label"] == "logs"

        stored = await intake._repo.get_by_id(uuid.UUID(output["evidence_id"]), tenant.org_id)
        assert stored is not None
        assert stored.state == EvidenceState.RECEIVED
        # Custody: case_id/org_id on the real, persisted Evidence row came
        # from the Detection/tenant lookup, not anything this test passed
        # directly to the action as an evidence-shaped field.
        assert stored.metadata.case_id == case_id
        assert stored.metadata.org_id == tenant.org_id

    @pytest.mark.asyncio
    async def test_case_id_and_org_id_are_never_read_from_params(
        self, tmp_path, detection_repo, intake
    ) -> None:
        """A params dict that smuggles a different case_id/org_id must be
        silently ignored -- the real Detection's own case_id and the
        caller's own tenant.org_id are the only source (roadmap invariant #3)."""
        tenant = make_tenant_context()
        real_case_id = uuid.uuid4()
        attacker_case_id = uuid.uuid4()
        detection = await detection_repo.save(_make_detection(tenant, real_case_id))
        artifact_path = _artifact_file(tmp_path)

        action = CollectForensicArtifactAction(detection_repo, intake, staging_dir=tmp_path)
        output = await action.execute(
            {
                "detection_id": str(detection.detection_id),
                "artifact_path": str(artifact_path),
                "case_id": str(attacker_case_id),  # must be ignored
                "org_id": str(uuid.uuid4()),  # must be ignored
            },
            tenant,
        )

        assert output["case_id"] == str(real_case_id)
        assert output["case_id"] != str(attacker_case_id)

    @pytest.mark.asyncio
    async def test_unknown_detection_raises_playbook_error(
        self, tmp_path, detection_repo, intake
    ) -> None:
        tenant = make_tenant_context()
        artifact_path = _artifact_file(tmp_path)
        action = CollectForensicArtifactAction(detection_repo, intake, staging_dir=tmp_path)

        with pytest.raises(PlaybookError):
            await action.execute(
                {"detection_id": str(uuid.uuid4()), "artifact_path": str(artifact_path)},
                tenant,
            )

    @pytest.mark.asyncio
    async def test_cross_tenant_detection_id_is_treated_as_not_found(
        self, tmp_path, detection_repo, intake
    ) -> None:
        owner_tenant = make_tenant_context()
        other_tenant = make_tenant_context()
        detection = await detection_repo.save(_make_detection(owner_tenant, uuid.uuid4()))
        artifact_path = _artifact_file(tmp_path)
        action = CollectForensicArtifactAction(detection_repo, intake, staging_dir=tmp_path)

        with pytest.raises(PlaybookError):
            await action.execute(
                {"detection_id": str(detection.detection_id), "artifact_path": str(artifact_path)},
                other_tenant,
            )

    @pytest.mark.asyncio
    async def test_detection_without_case_id_raises_playbook_error(
        self, tmp_path, detection_repo, intake
    ) -> None:
        tenant = make_tenant_context()
        detection = await detection_repo.save(_make_detection(tenant, case_id=None))
        artifact_path = _artifact_file(tmp_path)
        action = CollectForensicArtifactAction(detection_repo, intake, staging_dir=tmp_path)

        with pytest.raises(PlaybookError, match="no associated case_id"):
            await action.execute(
                {"detection_id": str(detection.detection_id), "artifact_path": str(artifact_path)},
                tenant,
            )

    @pytest.mark.asyncio
    async def test_missing_artifact_path_raises_playbook_error_not_fabricated_success(
        self, tmp_path, detection_repo, intake
    ) -> None:
        tenant = make_tenant_context()
        detection = await detection_repo.save(_make_detection(tenant, uuid.uuid4()))
        action = CollectForensicArtifactAction(detection_repo, intake, staging_dir=tmp_path)

        with pytest.raises(PlaybookError, match="does not exist"):
            await action.execute(
                {
                    "detection_id": str(detection.detection_id),
                    "artifact_path": str(tmp_path / "does-not-exist.vmem"),
                },
                tenant,
            )

    @pytest.mark.asyncio
    async def test_malformed_params_raise_playbook_error(
        self, tmp_path, detection_repo, intake
    ) -> None:
        tenant = make_tenant_context()
        action = CollectForensicArtifactAction(detection_repo, intake, staging_dir=tmp_path)

        with pytest.raises(PlaybookError):
            await action.execute({"artifact_path": "/tmp/whatever"}, tenant)

    @pytest.mark.asyncio
    async def test_sha256_matches_real_artifact_bytes(
        self, tmp_path, detection_repo, intake
    ) -> None:
        import hashlib

        tenant = make_tenant_context()
        detection = await detection_repo.save(_make_detection(tenant, uuid.uuid4()))
        artifact_path = _artifact_file(tmp_path)
        action = CollectForensicArtifactAction(detection_repo, intake, staging_dir=tmp_path)

        output = await action.execute(
            {"detection_id": str(detection.detection_id), "artifact_path": str(artifact_path)},
            tenant,
        )

        assert output["sha256"] == hashlib.sha256(_LOG_ARTIFACT).hexdigest()
        assert output["size_bytes"] == len(_LOG_ARTIFACT)

    @pytest.mark.asyncio
    async def test_never_mutates_the_triggering_detection(
        self, tmp_path, detection_repo, intake
    ) -> None:
        """Invariant #5: this action only ever CREATES a new Evidence row --
        it must never write to the Detection it read."""
        tenant = make_tenant_context()
        detection = await detection_repo.save(_make_detection(tenant, uuid.uuid4()))
        before = await detection_repo.get_by_id(detection.detection_id, tenant.org_id)
        artifact_path = _artifact_file(tmp_path)
        action = CollectForensicArtifactAction(detection_repo, intake, staging_dir=tmp_path)

        await action.execute(
            {"detection_id": str(detection.detection_id), "artifact_path": str(artifact_path)},
            tenant,
        )

        after = await detection_repo.get_by_id(detection.detection_id, tenant.org_id)
        assert after == before

    @pytest.mark.asyncio
    async def test_artifact_path_outside_staging_dir_is_rejected(
        self, tmp_path, detection_repo, intake
    ) -> None:
        """Gap Audit Milestone FF: a real, previously-unrestricted local
        file-read -- artifact_path naming a file OUTSIDE staging_dir must
        be rejected, never read, regardless of whether the file exists."""
        tenant = make_tenant_context()
        detection = await detection_repo.save(_make_detection(tenant, uuid.uuid4()))
        staging_dir = tmp_path / "staging"
        staging_dir.mkdir()
        outside_secret = tmp_path / "outside" / "secret.txt"
        outside_secret.parent.mkdir()
        outside_secret.write_bytes(b"not evidence, a real backend secret")
        action = CollectForensicArtifactAction(detection_repo, intake, staging_dir=staging_dir)

        with pytest.raises(PlaybookError, match="staging directory"):
            await action.execute(
                {
                    "detection_id": str(detection.detection_id),
                    "artifact_path": str(outside_secret),
                },
                tenant,
            )

    @pytest.mark.asyncio
    async def test_dotdot_traversal_out_of_staging_dir_is_rejected(
        self, tmp_path, detection_repo, intake
    ) -> None:
        tenant = make_tenant_context()
        detection = await detection_repo.save(_make_detection(tenant, uuid.uuid4()))
        staging_dir = tmp_path / "staging"
        staging_dir.mkdir()
        outside_secret = tmp_path / "secret.txt"
        outside_secret.write_bytes(b"not evidence")
        action = CollectForensicArtifactAction(detection_repo, intake, staging_dir=staging_dir)

        traversal_path = staging_dir / ".." / "secret.txt"
        with pytest.raises(PlaybookError, match="staging directory"):
            await action.execute(
                {
                    "detection_id": str(detection.detection_id),
                    "artifact_path": str(traversal_path),
                },
                tenant,
            )

    @pytest.mark.asyncio
    async def test_symlink_escaping_staging_dir_is_rejected(
        self, tmp_path, detection_repo, intake
    ) -> None:
        """A symlink planted INSIDE staging_dir but pointing OUTSIDE it must
        also be rejected -- resolve() follows the symlink to its real
        target before the containment check, so a literal in-bounds path
        string cannot be used to smuggle an out-of-bounds real file."""
        tenant = make_tenant_context()
        detection = await detection_repo.save(_make_detection(tenant, uuid.uuid4()))
        staging_dir = tmp_path / "staging"
        staging_dir.mkdir()
        outside_secret = tmp_path / "secret.txt"
        outside_secret.write_bytes(b"not evidence, reached via a symlink")
        symlink_path = staging_dir / "innocuous.vmem"
        symlink_path.symlink_to(outside_secret)
        action = CollectForensicArtifactAction(detection_repo, intake, staging_dir=staging_dir)

        with pytest.raises(PlaybookError, match="staging directory"):
            await action.execute(
                {
                    "detection_id": str(detection.detection_id),
                    "artifact_path": str(symlink_path),
                },
                tenant,
            )

    @pytest.mark.asyncio
    async def test_artifact_inside_staging_dir_still_succeeds(
        self, tmp_path, detection_repo, intake
    ) -> None:
        """Regression guard: the containment check must not be so strict it
        breaks the real, legitimate in-bounds case."""
        tenant = make_tenant_context()
        case_id = uuid.uuid4()
        detection = await detection_repo.save(_make_detection(tenant, case_id))
        staging_dir = tmp_path / "staging"
        staging_dir.mkdir()
        artifact_path = _artifact_file(staging_dir)
        action = CollectForensicArtifactAction(detection_repo, intake, staging_dir=staging_dir)

        output = await action.execute(
            {"detection_id": str(detection.detection_id), "artifact_path": str(artifact_path)},
            tenant,
        )

        assert output["evidence_state"] == EvidenceState.RECEIVED.value
