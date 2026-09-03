"""VolatilityOnDemandService: analyst-triggered, single-target volatility3
extractions (Milestone EEEEE) -- distinct from ``VolatilityModule``'s eager,
per-evidence-file ``parse()``/``extract_artifacts()`` pass.

Two real, on-demand actions, both real-verified in ``poc/volatility_dumpfiles/``
and ``poc/volatility_registry_printkey/`` before this was written (CLAUDE.md
SS F/G.5):

- ``extract_dump_file()``: a real ``windows.dumpfiles`` byte extraction,
  targeted via ``--physaddr`` (a ``windows.filescan`` row's own ``Offset``
  -- the PoC's decisive finding: ``--virtaddr`` does not work for this).
  Bytes go to ``DerivedArtifactStorage`` (a separate, non-WORM bucket --
  poc/minio_derived_artifact/), never the WORM evidence bucket.
- ``extract_registry_key()``: a real, scoped, non-recursive
  ``windows.registry.printkey`` call (hive ``offset`` + optional ``key``).

Both re-fetch and re-write the evidence bytes to a fresh local temp file
per call (mirrors ``VolatilityModule._run_volatility``'s identical
pattern) -- these are infrequent, analyst-initiated clicks, not the hot
eager-parse path, so re-streaming from MinIO each time is the right
tradeoff over holding evidence bytes in a longer-lived cache.
"""

from __future__ import annotations

import logging
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

from src.adapter.repository.artifact_repository import ArtifactRepository
from src.adapter.repository.evidence import EvidenceRepository
from src.adapter.storage.derived_artifact_storage import DerivedArtifactStorage
from src.adapter.storage.storage import EvidenceStorage
from src.application.audit_log import AuditLogService
from src.domain.artifact import StructuredArtifact
from src.domain.audit import AuditEventType
from src.domain.timeline import EvidenceProvenance
from src.domain.user import TenantContext
from src.exceptions import KronOSException, VolatilityScanError
from src.external.sandbox.volatility_launcher import VolatilityLauncher

logger = logging.getLogger(__name__)

_PARSER_NAME = "volatility3"
_PARSER_VERSION = "2.28.0"
_DUMPFILES_PLUGIN = "windows.dumpfiles.DumpFiles"
_DEFAULT_TIMEOUT_SECONDS = 300


class VolatilityOnDemandExtractionError(KronOSException):
    """A real, on-demand extraction request failed (bad target, no bytes
    recoverable, worker failure) -- distinct from VolatilityScanError so
    callers (the Celery task) don't need to know this service's internal
    launcher wiring to catch it."""


class VolatilityOnDemandService:
    """Orchestrates one on-demand volatility3 extraction request end to end:
    fetch evidence bytes -> run the sandboxed worker -> persist result
    (bytes to DerivedArtifactStorage for dumpfiles, rows only for registry)
    -> save a StructuredArtifact -> audit."""

    def __init__(
        self,
        evidence_repository: EvidenceRepository,
        evidence_storage: EvidenceStorage,
        derived_artifact_storage: DerivedArtifactStorage,
        artifact_repository: ArtifactRepository,
        audit_log: AuditLogService,
        launcher: VolatilityLauncher | None = None,
        worker_path: Path | None = None,
        timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._evidence_repository = evidence_repository
        self._evidence_storage = evidence_storage
        self._derived_artifact_storage = derived_artifact_storage
        self._artifact_repository = artifact_repository
        self._audit_log = audit_log
        # Real, live-verified bug (Milestone FFFFF): without an explicit
        # worker_path, VolatilityLauncher's own default (computed relative
        # to its source file) does not match where
        # docker/Dockerfile.plaso-worker actually COPYs the worker script
        # in the real built image (/app/volatility-worker/
        # kronos-volatility-worker.py, not /app/docker/volatility/...).
        # VolatilityModule._run_volatility already reads
        # settings.volatility_worker_path correctly; this on-demand path
        # needs the identical real value threaded through by the caller
        # (celery_runtime.py's _build_task_resources()).
        self._launcher = launcher or VolatilityLauncher(
            worker_path=worker_path, timeout_seconds=timeout_seconds
        )

    async def extract_dump_file(
        self, evidence_id: uuid.UUID, tenant: TenantContext, physaddr: int
    ) -> list[StructuredArtifact]:
        """Run windows.dumpfiles against *physaddr*, upload each real
        extracted file to DerivedArtifactStorage, save one StructuredArtifact
        per file (a single physaddr target occasionally yields more than one
        real file -- e.g. a DataSectionObject and an ImageSectionObject for
        the same target, both genuine), and return the saved artifacts.
        """
        evidence = await self._get_evidence_or_raise(evidence_id, tenant)
        tmp_path = await self._write_evidence_to_temp(evidence)
        result = None
        try:
            result = await self._launcher.run_dumpfile(tmp_path, physaddr)
            if not result.ok or not result.dumped_files:
                error = result.error or f"No file recoverable at physaddr={physaddr}"
                await self._audit_log.log(
                    AuditEventType.DERIVED_ARTIFACT_EXTRACTION_FAILED,
                    org_id=tenant.org_id,
                    case_id=evidence.metadata.case_id,
                    evidence_id=evidence_id,
                    actor_user_id=tenant.user_id,
                    actor_username=tenant.username,
                    details={"plugin": _DUMPFILES_PLUGIN, "physaddr": physaddr, "error": error},
                )
                raise VolatilityOnDemandExtractionError(error, context={"physaddr": physaddr})

            saved: list[StructuredArtifact] = []
            for dumped in result.dumped_files:
                data = Path(dumped.path).read_bytes()
                artifact_id = uuid.uuid4()
                object_key = (
                    f"{evidence.metadata.org_alias}/{evidence.metadata.case_id}"
                    f"/{evidence_id}/{artifact_id}/{dumped.filename}"
                )
                await self._derived_artifact_storage.put_object(
                    evidence.metadata.org_alias, object_key, data
                )
                content = {
                    "plugin": _DUMPFILES_PLUGIN,
                    "physaddr": physaddr,
                    "filename": dumped.filename,
                    "sha256": dumped.sha256,
                    "size_bytes": dumped.size_bytes,
                    "object_key": object_key,
                    # Reserved, additive-only slot for a future VirusTotal
                    # hash-lookup pass (user said "eventually") -- nothing
                    # else populates or reads this yet.
                    "enrichment": {},
                }
                artifact = StructuredArtifact(
                    artifact_id=artifact_id,
                    kind="volatility.dumpfiles",
                    content=content,
                    kronos=self._provenance(evidence, tenant, record_index=len(saved)),
                )
                saved.append(await self._artifact_repository.save(artifact))

            await self._audit_log.log(
                AuditEventType.DERIVED_ARTIFACT_EXTRACTED,
                org_id=tenant.org_id,
                case_id=evidence.metadata.case_id,
                evidence_id=evidence_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                details={
                    "plugin": _DUMPFILES_PLUGIN,
                    "physaddr": physaddr,
                    "artifact_ids": [str(a.artifact_id) for a in saved],
                    "files": [d.filename for d in result.dumped_files],
                },
            )
            return saved
        except VolatilityScanError as exc:
            await self._audit_log.log(
                AuditEventType.DERIVED_ARTIFACT_EXTRACTION_FAILED,
                org_id=tenant.org_id,
                case_id=evidence.metadata.case_id,
                evidence_id=evidence_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                details={"plugin": _DUMPFILES_PLUGIN, "physaddr": physaddr, "error": str(exc)},
            )
            raise VolatilityOnDemandExtractionError(
                str(exc), context={"physaddr": physaddr}
            ) from exc
        finally:
            Path(tmp_path).unlink(missing_ok=True)
            if result is not None:
                import shutil  # noqa: PLC0415

                shutil.rmtree(result.output_dir, ignore_errors=True)

    async def extract_registry_key(
        self,
        evidence_id: uuid.UUID,
        tenant: TenantContext,
        hive_offset: int,
        key: str | None = None,
    ) -> StructuredArtifact:
        """Run a scoped, non-recursive windows.registry.printkey call and
        save the resulting rows as one StructuredArtifact."""
        evidence = await self._get_evidence_or_raise(evidence_id, tenant)
        tmp_path = await self._write_evidence_to_temp(evidence)
        try:
            result = await self._launcher.run_registry_key(tmp_path, hive_offset, key)
            if not result.ok:
                error = result.error or f"printkey failed at offset={hive_offset}"
                await self._audit_log.log(
                    AuditEventType.DERIVED_ARTIFACT_EXTRACTION_FAILED,
                    org_id=tenant.org_id,
                    case_id=evidence.metadata.case_id,
                    evidence_id=evidence_id,
                    actor_user_id=tenant.user_id,
                    actor_username=tenant.username,
                    details={
                        "plugin": "windows.registry.printkey.PrintKey",
                        "hive_offset": hive_offset,
                        "key": key,
                        "error": error,
                    },
                )
                raise VolatilityOnDemandExtractionError(
                    error, context={"hive_offset": hive_offset, "key": key}
                )

            content = {
                "plugin": "windows.registry.printkey.PrintKey",
                "hive_offset": hive_offset,
                "key": key,
                "rows": list(result.rows),
            }
            artifact = StructuredArtifact(
                kind="volatility.registry.printkey",
                content=content,
                kronos=self._provenance(evidence, tenant, record_index=0),
            )
            saved = await self._artifact_repository.save(artifact)

            await self._audit_log.log(
                AuditEventType.DERIVED_ARTIFACT_EXTRACTED,
                org_id=tenant.org_id,
                case_id=evidence.metadata.case_id,
                evidence_id=evidence_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                details={
                    "plugin": "windows.registry.printkey.PrintKey",
                    "hive_offset": hive_offset,
                    "key": key,
                    "artifact_id": str(saved.artifact_id),
                    "row_count": len(result.rows),
                },
            )
            return saved
        except VolatilityScanError as exc:
            await self._audit_log.log(
                AuditEventType.DERIVED_ARTIFACT_EXTRACTION_FAILED,
                org_id=tenant.org_id,
                case_id=evidence.metadata.case_id,
                evidence_id=evidence_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                details={
                    "plugin": "windows.registry.printkey.PrintKey",
                    "hive_offset": hive_offset,
                    "key": key,
                    "error": str(exc),
                },
            )
            raise VolatilityOnDemandExtractionError(
                str(exc), context={"hive_offset": hive_offset, "key": key}
            ) from exc
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _get_evidence_or_raise(self, evidence_id: uuid.UUID, tenant: TenantContext):  # type: ignore[no-untyped-def]
        evidence = await self._evidence_repository.get_by_id(evidence_id, tenant.org_id)
        if evidence is None or evidence.minio_evidence_key is None:
            raise VolatilityOnDemandExtractionError(
                "Evidence not found or not yet available", context={"evidence_id": str(evidence_id)}
            )
        return evidence

    async def _write_evidence_to_temp(self, evidence) -> str:  # type: ignore[no-untyped-def]
        assert evidence.minio_evidence_key is not None
        stream = await self._evidence_storage.stream_object(
            evidence.minio_evidence_key, bucket="evidence"
        )
        suffix = Path(evidence.metadata.original_filename).suffix
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            async for chunk in stream:
                tmp.write(chunk)
            return tmp.name

    def _provenance(
        self, evidence, tenant: TenantContext, *, record_index: int
    ) -> EvidenceProvenance:  # type: ignore[no-untyped-def]
        return EvidenceProvenance(
            evidence_id=evidence.evidence_id,
            case_id=evidence.metadata.case_id,
            org_id=tenant.org_id,
            org_alias=evidence.metadata.org_alias,
            sha256=evidence.sha256 or "",
            parser=_PARSER_NAME,
            parser_version=_PARSER_VERSION,
            record_index=record_index,
            ingest_timestamp=datetime.now(UTC),
        )
