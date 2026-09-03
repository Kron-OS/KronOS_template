"""VolatilityOnDemandService tests: analyst-triggered dumpfiles/registry
extraction orchestration (Milestone EEEEE).

Mirrors test_volatility.py's own idiom (CLAUDE.md SS B.5: mock only the
external dependency -- here, a fake VolatilityLauncher standing in for the
real sandboxed subprocess -- never domain objects). Real, end-to-end
verification against the real worker/volatility3 lives in
poc/volatility_dumpfiles/ and poc/volatility_registry_printkey/.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

import pytest

from src.adapter.repository.artifact_repository import InMemoryArtifactRepository
from src.application.audit_log import AuditLogService
from src.domain.audit import AuditEventType
from src.exceptions import VolatilityScanError
from src.external.parsers.volatility_on_demand import (
    VolatilityOnDemandExtractionError,
    VolatilityOnDemandService,
)
from src.external.sandbox.volatility_launcher import (
    VolatilityDumpFilesResult,
    VolatilityRegistryKeyResult,
)
from tests.conftest import InMemoryAuditLogRepository, InMemoryEvidenceRepository
from tests.fixtures.factories import make_evidence, make_tenant_context

pytestmark = pytest.mark.asyncio


class _FakeEvidenceStorage:
    """Only stream_object is used by VolatilityOnDemandService."""

    def __init__(self, chunks: tuple[bytes, ...] = (b"fake-memory-image-bytes",)) -> None:
        self._chunks = chunks

    async def stream_object(
        self, object_key: str, chunk_size: int = 65536, *, bucket: str = "quarantine"
    ) -> AsyncIterator[bytes]:
        async def _gen() -> AsyncIterator[bytes]:
            for chunk in self._chunks:
                yield chunk

        return _gen()


class _FakeDerivedArtifactStorage:
    def __init__(self) -> None:
        self.put_calls: list[dict[str, Any]] = []

    async def put_object(
        self,
        org_alias: str,
        object_key: str,
        data: bytes,
        *,
        content_type: str = "application/octet-stream",
    ) -> None:
        self.put_calls.append({"org_alias": org_alias, "object_key": object_key, "data": data})

    async def stream_object(self, object_key: str, chunk_size: int = 65536) -> AsyncIterator[bytes]:
        async def _gen() -> AsyncIterator[bytes]:
            yield b""

        return _gen()

    def bucket_for(self, object_key: str) -> str:
        return "kronos-derived-testorg"


class _FakeLauncher:
    def __init__(
        self,
        dumpfile_result: VolatilityDumpFilesResult | None = None,
        registry_result: VolatilityRegistryKeyResult | None = None,
        raise_error: Exception | None = None,
    ) -> None:
        self._dumpfile_result = dumpfile_result
        self._registry_result = registry_result
        self._raise_error = raise_error
        self.dumpfile_calls: list[dict[str, Any]] = []
        self.registry_calls: list[dict[str, Any]] = []

    async def run_dumpfile(self, evidence_path: str, physaddr: int) -> VolatilityDumpFilesResult:
        self.dumpfile_calls.append({"evidence_path": evidence_path, "physaddr": physaddr})
        if self._raise_error is not None:
            raise self._raise_error
        assert self._dumpfile_result is not None
        return self._dumpfile_result

    async def run_registry_key(
        self, evidence_path: str, hive_offset: int, key: str | None = None
    ) -> VolatilityRegistryKeyResult:
        self.registry_calls.append(
            {"evidence_path": evidence_path, "hive_offset": hive_offset, "key": key}
        )
        if self._raise_error is not None:
            raise self._raise_error
        assert self._registry_result is not None
        return self._registry_result


async def _make_service(
    launcher: _FakeLauncher,
) -> tuple[
    VolatilityOnDemandService,
    InMemoryEvidenceRepository,
    InMemoryArtifactRepository,
    AuditLogService,
]:
    evidence_repo = InMemoryEvidenceRepository()
    artifact_repo = InMemoryArtifactRepository()
    audit_log = AuditLogService(InMemoryAuditLogRepository())
    service = VolatilityOnDemandService(
        evidence_repository=evidence_repo,
        evidence_storage=_FakeEvidenceStorage(),  # type: ignore[arg-type]
        derived_artifact_storage=_FakeDerivedArtifactStorage(),  # type: ignore[arg-type]
        artifact_repository=artifact_repo,
        audit_log=audit_log,
        launcher=launcher,  # type: ignore[arg-type]
    )
    return service, evidence_repo, artifact_repo, audit_log


async def test_extract_dump_file_saves_artifact_and_uploads_bytes(tmp_path: Any) -> None:
    tenant = make_tenant_context()
    evidence = make_evidence(org_id=tenant.org_id).with_keys(None, "testorg/case/evidence/test.raw")
    launcher = _FakeLauncher(
        dumpfile_result=VolatilityDumpFilesResult(
            ok=True,
            error=None,
            dumped_files=(_dumped_file(tmp_path, "example.dat", b"real-extracted-bytes"),),
            output_dir=str(tmp_path),
        )
    )
    service, evidence_repo, artifact_repo, _ = await _make_service(launcher)
    await evidence_repo.save(evidence)

    saved = await service.extract_dump_file(evidence.evidence_id, tenant, physaddr=88029040)

    assert len(saved) == 1
    assert saved[0].kind == "volatility.dumpfiles"
    assert saved[0].content["filename"] == "example.dat"
    assert saved[0].content["physaddr"] == 88029040
    assert saved[0].content["enrichment"] == {}
    persisted = await artifact_repo.list_by_evidence(evidence.evidence_id, tenant.org_id)
    assert len(persisted) == 1
    assert launcher.dumpfile_calls[0]["physaddr"] == 88029040


async def test_extract_dump_file_raises_and_audits_failure_when_no_bytes_recoverable(
    tmp_path: Any,
) -> None:
    tenant = make_tenant_context()
    evidence = make_evidence(org_id=tenant.org_id).with_keys(None, "testorg/case/evidence/test.raw")
    launcher = _FakeLauncher(
        dumpfile_result=VolatilityDumpFilesResult(
            ok=False,
            error="No file recoverable at physaddr=1234",
            dumped_files=(),
            output_dir=str(tmp_path),
        )
    )
    service, evidence_repo, artifact_repo, audit_log = await _make_service(launcher)
    await evidence_repo.save(evidence)

    with pytest.raises(VolatilityOnDemandExtractionError, match="No file recoverable"):
        await service.extract_dump_file(evidence.evidence_id, tenant, physaddr=1234)

    assert (await artifact_repo.list_by_evidence(evidence.evidence_id, tenant.org_id)) == []
    events = [e async for e in audit_log._repository.stream_by_org(tenant.org_id)]  # type: ignore[attr-defined]
    assert any(e.event_type == AuditEventType.DERIVED_ARTIFACT_EXTRACTION_FAILED for e in events)


async def test_extract_dump_file_wraps_launcher_scan_error(tmp_path: Any) -> None:
    tenant = make_tenant_context()
    evidence = make_evidence(org_id=tenant.org_id).with_keys(None, "testorg/case/evidence/test.raw")
    launcher = _FakeLauncher(raise_error=VolatilityScanError("worker exited with code 1"))
    service, evidence_repo, _, audit_log = await _make_service(launcher)
    await evidence_repo.save(evidence)

    with pytest.raises(VolatilityOnDemandExtractionError, match="worker exited"):
        await service.extract_dump_file(evidence.evidence_id, tenant, physaddr=1234)

    events = [e async for e in audit_log._repository.stream_by_org(tenant.org_id)]  # type: ignore[attr-defined]
    assert any(e.event_type == AuditEventType.DERIVED_ARTIFACT_EXTRACTION_FAILED for e in events)


async def test_extract_registry_key_saves_one_artifact_with_rows() -> None:
    tenant = make_tenant_context()
    evidence = make_evidence(org_id=tenant.org_id).with_keys(None, "testorg/case/evidence/test.raw")
    launcher = _FakeLauncher(
        registry_result=VolatilityRegistryKeyResult(
            ok=True,
            error=None,
            rows=({"Name": "ControlSet001", "Last Write Time": "2019-08-07T05:05:46+00:00"},),
        )
    )
    service, evidence_repo, artifact_repo, _ = await _make_service(launcher)
    await evidence_repo.save(evidence)

    saved = await service.extract_registry_key(
        evidence.evidence_id, tenant, hive_offset=273366078603280, key="ControlSet001"
    )

    assert saved.kind == "volatility.registry.printkey"
    assert saved.content["hive_offset"] == 273366078603280
    assert saved.content["key"] == "ControlSet001"
    assert len(saved.content["rows"]) == 1
    persisted = await artifact_repo.list_by_evidence(evidence.evidence_id, tenant.org_id)
    assert len(persisted) == 1


async def test_extract_registry_key_raises_on_scan_failure() -> None:
    tenant = make_tenant_context()
    evidence = make_evidence(org_id=tenant.org_id).with_keys(None, "testorg/case/evidence/test.raw")
    launcher = _FakeLauncher(
        registry_result=VolatilityRegistryKeyResult(
            ok=False, error="LayerException: Layer already exists", rows=()
        )
    )
    service, evidence_repo, artifact_repo, _ = await _make_service(launcher)
    await evidence_repo.save(evidence)

    with pytest.raises(VolatilityOnDemandExtractionError, match="Layer already exists"):
        await service.extract_registry_key(evidence.evidence_id, tenant, hive_offset=1234)

    assert (await artifact_repo.list_by_evidence(evidence.evidence_id, tenant.org_id)) == []


async def test_extract_dump_file_raises_when_evidence_not_promoted() -> None:
    """No minio_evidence_key -- the evidence isn't fully ingested yet; this
    is a real, honest precondition failure, not a launcher problem."""
    tenant = make_tenant_context()
    evidence = make_evidence(
        org_id=tenant.org_id
    )  # no with_keys() -- minio_evidence_key stays None
    launcher = _FakeLauncher()
    service, evidence_repo, _, _ = await _make_service(launcher)
    await evidence_repo.save(evidence)

    with pytest.raises(VolatilityOnDemandExtractionError, match="not yet available"):
        await service.extract_dump_file(evidence.evidence_id, tenant, physaddr=1234)

    assert launcher.dumpfile_calls == []


def _dumped_file(tmp_path: Any, filename: str, data: bytes) -> Any:
    from src.external.sandbox.volatility_launcher import DumpedFile

    path = tmp_path / filename
    path.write_bytes(data)
    import hashlib

    return DumpedFile(
        filename=filename,
        path=str(path),
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )
