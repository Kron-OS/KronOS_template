"""EvidenceIntakeService: orchestrates upload → validate → scan → hash → RECEIVED."""

from __future__ import annotations

import logging
import uuid

from src.adapter.repository.evidence import EvidenceRepository
from src.adapter.storage.storage import EvidenceStorage, PresignedUploadResponse
from src.application.audit_log import AuditLogService
from src.application.hashing import HashService
from src.application.scanning import AntivirusScanner
from src.application.validation import EvidenceValidator
from src.domain.audit import AuditEventType
from src.domain.evidence import Evidence, EvidenceMetadata, EvidenceState
from src.domain.user import TenantContext
from src.exceptions import ValidationError

logger = logging.getLogger(__name__)

# How many bytes to read from the quarantine object for magic-byte validation.
_HEADER_BYTES = 8192


class EvidenceIntakeService:
    """Orchestrates the full evidence intake workflow.

    Flow:
        request_upload  → Evidence(UPLOADING) + presigned URL
        [client uploads file directly to MinIO]
        finalize_upload → validate → scan → hash → promote → Evidence(RECEIVED)
    """

    def __init__(
        self,
        evidence_repository: EvidenceRepository,
        storage: EvidenceStorage,
        audit_log: AuditLogService,
        validator: EvidenceValidator,
        scanner: AntivirusScanner,
        hash_service: HashService,
        max_upload_bytes: int,
        presigned_url_expiry_seconds: int = 3600,
    ) -> None:
        self._repo = evidence_repository
        self._storage = storage
        self._audit = audit_log
        self._validator = validator
        self._scanner = scanner
        self._hasher = hash_service
        self._max_upload_bytes = max_upload_bytes
        self._presigned_expiry = presigned_url_expiry_seconds

    async def request_upload(
        self,
        filename: str,
        content_type: str,
        size_bytes: int,
        case_id: uuid.UUID,
        tenant: TenantContext,
    ) -> tuple[Evidence, PresignedUploadResponse]:
        """Create an Evidence record and return a presigned upload URL.

        The returned URL allows the client to PUT the file directly to the
        quarantine bucket without routing through the application server.
        """
        metadata = EvidenceMetadata(
            original_filename=filename,
            content_type=content_type,
            size_bytes=size_bytes,
            uploader_user_id=tenant.user_id,
            case_id=case_id,
            org_id=tenant.org_id,
            org_alias=tenant.org_alias,
        )
        evidence = Evidence(metadata=metadata)

        async with self._audit.audit_context(
            AuditEventType.EVIDENCE_UPLOAD_REQUESTED,
            AuditEventType.EVIDENCE_ERROR,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            actor_username=tenant.username,
            case_id=case_id,
            evidence_id=evidence.evidence_id,
            details={
                "filename": filename,
                "size_bytes": size_bytes,
                "content_type": content_type,
            },
        ):
            presigned = await self._storage.request_presigned_upload(
                evidence, expires_in_seconds=self._presigned_expiry
            )
            evidence = evidence.with_keys(quarantine_key=presigned.object_key, evidence_key=None)
            await self._repo.save(evidence)

        logger.info(
            "upload_requested",
            extra={
                "evidence_id": str(evidence.evidence_id),
                "org_id": str(tenant.org_id),
                "filename": filename,
            },
        )
        return evidence, presigned

    async def finalize_upload(
        self,
        evidence_id: uuid.UUID,
        client_sha256: str,
        tenant: TenantContext,
    ) -> Evidence:
        """Validate, scan, hash, and promote the uploaded evidence file.

        Steps (in order — each failure is audited and sets ERROR state):
          1. Validate extension + magic bytes
          2. AV scan
          3. SHA-256 + MD5 hash
          4. Compare server hash vs client-provided SHA-256
          5. Promote quarantine → WORM evidence bucket
          6. Transition to RECEIVED
        """
        evidence = await self._repo.get_by_id(evidence_id, tenant.org_id)
        if evidence is None:
            raise ValidationError(
                "Evidence not found",
                context={"evidence_id": str(evidence_id), "org_id": str(tenant.org_id)},
            )
        if evidence.state != EvidenceState.UPLOADING:
            raise ValidationError(
                f"Evidence is in state {evidence.state.value}, expected UPLOADING",
                context={"evidence_id": str(evidence_id), "state": evidence.state.value},
            )

        quarantine_key = evidence.minio_quarantine_key
        if not quarantine_key:
            raise ValidationError(
                "Evidence has no quarantine key",
                context={"evidence_id": str(evidence_id)},
            )

        # --- Step 1: Validate ---
        evidence = await self._run_validation(evidence, quarantine_key, tenant)

        # --- Step 2: AV scan ---
        evidence = await self._run_scan(evidence, quarantine_key, tenant)

        # --- Step 3 & 4: Hash + compare ---
        evidence = await self._run_hash(evidence, quarantine_key, client_sha256, tenant)

        # --- Step 5: Promote ---
        evidence = await self._promote(evidence, quarantine_key, tenant)

        return evidence

    # ------------------------------------------------------------------
    # Private workflow steps
    # ------------------------------------------------------------------

    async def _run_validation(
        self, evidence: Evidence, quarantine_key: str, tenant: TenantContext
    ) -> Evidence:
        evidence = evidence.with_state(EvidenceState.SCANNING)
        await self._repo.update(evidence)
        await self._audit.log(
            AuditEventType.EVIDENCE_SCAN_STARTED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            actor_username=tenant.username,
            evidence_id=evidence.evidence_id,
        )

        # Fetch just the first 8 KB for magic-byte detection.
        header = b""
        async for chunk in await self._storage.stream_object(quarantine_key):
            header += chunk
            if len(header) >= _HEADER_BYTES:
                break
        header = header[:_HEADER_BYTES]

        try:
            self._validator.validate(
                filename=evidence.metadata.original_filename,
                content_type=evidence.metadata.content_type,
                size_bytes=evidence.metadata.size_bytes,
                header_bytes=header,
            )
        except ValidationError:
            evidence = evidence.with_error("validation_failed")
            await self._repo.update(evidence)
            await self._audit.log(
                AuditEventType.EVIDENCE_ERROR,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                evidence_id=evidence.evidence_id,
                details={"step": "validation"},
            )
            raise

        return evidence

    async def _run_scan(
        self, evidence: Evidence, quarantine_key: str, tenant: TenantContext
    ) -> Evidence:
        stream = await self._storage.stream_object(quarantine_key)
        scan_result = await self._scanner.scan_stream(stream)

        if not scan_result.is_clean:
            evidence = evidence.with_error(f"infected:{scan_result.threat_name}")
            await self._repo.update(evidence)
            await self._audit.log(
                AuditEventType.EVIDENCE_SCAN_FAILED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                evidence_id=evidence.evidence_id,
                details={"threat": scan_result.threat_name},
            )
            raise ValidationError(
                f"File is infected: {scan_result.threat_name}",
                context={
                    "evidence_id": str(evidence.evidence_id),
                    "threat": scan_result.threat_name,
                },
            )

        await self._audit.log(
            AuditEventType.EVIDENCE_SCAN_COMPLETED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            evidence_id=evidence.evidence_id,
        )
        return evidence

    async def _run_hash(
        self,
        evidence: Evidence,
        quarantine_key: str,
        client_sha256: str,
        tenant: TenantContext,
    ) -> Evidence:
        evidence = evidence.with_state(EvidenceState.HASHING)
        await self._repo.update(evidence)

        stream = await self._storage.stream_object(quarantine_key)
        hash_result = await self._hasher.compute_from_stream(stream)

        if hash_result.sha256 != client_sha256.lower():
            evidence = evidence.with_error("hash_mismatch")
            await self._repo.update(evidence)
            await self._audit.log(
                AuditEventType.EVIDENCE_HASH_MISMATCH,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                evidence_id=evidence.evidence_id,
                details={"client_sha256": client_sha256, "server_sha256": hash_result.sha256},
            )
            raise ValidationError(
                "SHA-256 mismatch: client and server hashes differ",
                context={
                    "evidence_id": str(evidence.evidence_id),
                    "client_sha256": client_sha256,
                    "server_sha256": hash_result.sha256,
                },
            )

        evidence = evidence.with_hashes(sha256=hash_result.sha256, md5=hash_result.md5)
        await self._repo.update(evidence)
        await self._audit.log(
            AuditEventType.EVIDENCE_HASH_COMPUTED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            evidence_id=evidence.evidence_id,
            details={"sha256": hash_result.sha256},
        )
        return evidence

    async def _promote(
        self, evidence: Evidence, quarantine_key: str, tenant: TenantContext
    ) -> Evidence:
        evidence = evidence.with_state(EvidenceState.RECEIVED)
        evidence_key = await self._storage.promote_to_evidence_bucket(quarantine_key, evidence)
        await self._storage.delete_from_quarantine(quarantine_key)

        evidence = evidence.with_keys(quarantine_key=None, evidence_key=evidence_key)
        await self._repo.update(evidence)
        await self._audit.log(
            AuditEventType.EVIDENCE_PROMOTED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            evidence_id=evidence.evidence_id,
            details={"evidence_key": evidence_key},
        )
        logger.info(
            "evidence_received",
            extra={"evidence_id": str(evidence.evidence_id), "sha256": evidence.sha256},
        )
        return evidence
