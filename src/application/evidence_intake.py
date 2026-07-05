"""EvidenceIntakeService: orchestrates upload → validate → scan → hash → RECEIVED → parse."""

from __future__ import annotations

import logging
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

from src.adapter.queue.task_queue import TaskQueue
from src.adapter.repository.evidence import EvidenceRepository
from src.adapter.storage.storage import EvidenceStorage, PresignedUploadResponse
from src.application.audit_log import AuditLogService
from src.application.hashing import HashService
from src.application.scanning import AntivirusScanner
from src.application.timestamping import RFC3161TimestampService
from src.application.validation import EvidenceValidator
from src.domain.audit import AuditEventType
from src.domain.evidence import Evidence, EvidenceMetadata, EvidenceState
from src.domain.user import Role, TenantContext
from src.exceptions import AuthorizationError, EvidenceStateError, StorageError, ValidationError

logger = logging.getLogger(__name__)

# How many bytes to read from the quarantine object for magic-byte validation.
_HEADER_BYTES = 8192

# Spec-authoritative default (Project_Specifications.md §2 "Retention Period"):
# 365 days, configurable per case/org via `default_retention_days`.
_DEFAULT_RETENTION_DAYS = 365


async def _cap_stream(
    source: AsyncIterator[bytes], max_bytes: int, evidence_id: uuid.UUID
) -> AsyncIterator[bytes]:
    """Re-yield *source* but abort once more than *max_bytes* have been seen.

    The size limit declared at ``request_upload`` is only the client's claim;
    this enforces the real uploaded byte count while the object is streamed for
    scanning/hashing, so an under-declared upload cannot bypass the cap.
    """
    seen = 0
    async for chunk in source:
        seen += len(chunk)
        if seen > max_bytes:
            raise ValidationError(
                "Uploaded file exceeds the maximum permitted size",
                context={"evidence_id": str(evidence_id), "max_bytes": max_bytes},
            )
        yield chunk


class EvidenceIntakeService:
    """Orchestrates the full evidence intake workflow.

    Flow (fully autonomous after the client PUT to MinIO):
        request_upload  → Evidence(UPLOADING) + presigned URL
        [client uploads file directly to MinIO]
        finalize_upload → validate → scan → hash → promote → Evidence(RECEIVED)
                       → auto-enqueues dispatch_parse (Celery)
        [Celery] dispatch_parse → start_parsing → Evidence(PARSING)
        [Celery] parse_artefact_* → execute_parse → Evidence(COMPLETE)

    The client never needs to call parse/start — the pipeline is self-driving.
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
        presigned_url_expiry_seconds: int = 900,
        task_queue: TaskQueue | None = None,
        timestamp_service: RFC3161TimestampService | None = None,
        default_retention_days: int = _DEFAULT_RETENTION_DAYS,
    ) -> None:
        self._repo = evidence_repository
        self._storage = storage
        self._audit = audit_log
        self._validator = validator
        self._scanner = scanner
        self._hasher = hash_service
        self._max_upload_bytes = max_upload_bytes
        self._presigned_expiry = presigned_url_expiry_seconds
        self._task_queue = task_queue
        self._timestamp_service = timestamp_service
        self._default_retention_days = default_retention_days

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
        prior_state = evidence.state
        evidence = evidence.with_state(EvidenceState.SCANNING)
        await self._repo.update(evidence, expected_state=prior_state)
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
            await self._repo.update(evidence, expected_state=EvidenceState.SCANNING)
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
        raw_stream = await self._storage.stream_object(quarantine_key)
        # Enforce the real uploaded size before trusting the file further.
        stream = _cap_stream(raw_stream, self._max_upload_bytes, evidence.evidence_id)
        try:
            scan_result = await self._scanner.scan_stream(stream)
        except ValidationError:
            evidence = evidence.with_error("size_limit_exceeded")
            await self._repo.update(evidence, expected_state=EvidenceState.SCANNING)
            await self._audit.log(
                AuditEventType.EVIDENCE_ERROR,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                evidence_id=evidence.evidence_id,
                details={"step": "size_enforcement"},
            )
            raise

        if not scan_result.is_clean:
            evidence = evidence.with_error(f"infected:{scan_result.threat_name}")
            await self._repo.update(evidence, expected_state=EvidenceState.SCANNING)
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
        prior_state = evidence.state
        evidence = evidence.with_state(EvidenceState.HASHING)
        await self._repo.update(evidence, expected_state=prior_state)

        stream = await self._storage.stream_object(quarantine_key)
        hash_result = await self._hasher.compute_from_stream(stream)

        if hash_result.sha256 != client_sha256.lower():
            evidence = evidence.with_error("hash_mismatch")
            await self._repo.update(evidence, expected_state=EvidenceState.HASHING)
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
        await self._repo.update(evidence, expected_state=EvidenceState.HASHING)
        await self._audit.log(
            AuditEventType.EVIDENCE_HASH_COMPUTED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            evidence_id=evidence.evidence_id,
            details={"sha256": hash_result.sha256},
        )

        # RFC 3161 trusted timestamping on the evidence.hash.verified transition
        # (Project_Specifications.md §2) — non-repudiable proof of acquisition
        # time.  A TSA outage must not block intake (the file is already
        # hashed and verified); it is logged and left for operational retry,
        # never silently fabricated (see AUDIT-06's fix in timestamping.py).
        if self._timestamp_service is not None:
            evidence = await self._anchor_timestamp(evidence, tenant)

        return evidence

    async def _anchor_timestamp(self, evidence: Evidence, tenant: TenantContext) -> Evidence:
        """Timestamp `evidence.sha256` via the RFC 3161 TSA and persist the token."""
        assert self._timestamp_service is not None  # noqa: S101 — guarded by caller
        try:
            digest = bytes.fromhex(evidence.sha256 or "")
            token = await self._timestamp_service.timestamp(digest)
        except (StorageError, ValueError) as exc:
            logger.warning(
                "tsa_timestamp_failed",
                extra={"evidence_id": str(evidence.evidence_id), "error": str(exc)},
            )
            return evidence

        evidence = evidence.with_rfc3161_token(token)
        await self._repo.update(evidence, expected_state=EvidenceState.HASHING)
        await self._audit.log(
            AuditEventType.EVIDENCE_TSA_ANCHORED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            evidence_id=evidence.evidence_id,
            details={"sha256": evidence.sha256},
        )
        return evidence

    async def delete_evidence(
        self,
        evidence_id: uuid.UUID,
        tenant: TenantContext,
        *,
        step_up_verified: bool = False,
    ) -> None:
        """Soft-delete evidence after verifying org scope, role, retention, and hold.

        Aligns with Project_Specifications.md §2's retention model: Object Lock
        retain-until is set at promotion time, and an object may only be purged
        once that date has passed *and* legal_hold is false.  Even then, the
        platform metadata row is never destroyed — it transitions to the
        terminal ``PURGED`` state so the custodial record survives indefinitely.
        The underlying MinIO object itself is immutable until the same
        conditions hold (WORM enforced at the storage layer regardless).

        Step-up (MFA) is verified by the caller (the route consumes a one-time
        ticket); the caller passes the *actual* outcome via ``step_up_verified``
        so the immutable audit record never asserts a verification that did not
        happen.  The default is ``False``: a caller that did not verify step-up
        will record that truthfully.

        Raises:
            ValidationError: if evidence is not found for this org.
            AuthorizationError: if the tenant lacks the ORG_ADMIN role, or the
                evidence is under legal hold.
            EvidenceStateError: if the Object Lock retention period has not
                yet expired.
        """
        if Role.ORG_ADMIN not in tenant.roles:
            raise AuthorizationError(
                "Only org-admin may delete evidence",
                context={"user_id": str(tenant.user_id), "org_id": str(tenant.org_id)},
            )

        evidence = await self._repo.get_by_id(evidence_id, tenant.org_id)
        if evidence is None:
            raise ValidationError(
                "Evidence not found",
                context={"evidence_id": str(evidence_id), "org_id": str(tenant.org_id)},
            )

        custody_details = {
            "step_up_verified": step_up_verified,
            "sha256": evidence.sha256,
            "bucket": self._bucket_for_audit(evidence),
            "object_key": evidence.minio_evidence_key,
        }

        if evidence.legal_hold:
            await self._audit.log(
                AuditEventType.EVIDENCE_DELETE_DENIED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                evidence_id=evidence_id,
                details={**custody_details, "reason": "legal_hold"},
            )
            raise AuthorizationError(
                "Evidence is under legal hold and cannot be deleted",
                context={"evidence_id": str(evidence_id)},
            )

        now = datetime.now(UTC)
        if evidence.object_lock_until is not None and evidence.object_lock_until > now:
            await self._audit.log(
                AuditEventType.EVIDENCE_DELETE_DENIED,
                org_id=tenant.org_id,
                actor_user_id=tenant.user_id,
                actor_username=tenant.username,
                evidence_id=evidence_id,
                details={
                    **custody_details,
                    "reason": "retention_period_active",
                    "object_lock_until": evidence.object_lock_until.isoformat(),
                },
            )
            raise EvidenceStateError(
                "Evidence retention period has not expired",
                context={
                    "evidence_id": str(evidence_id),
                    "object_lock_until": evidence.object_lock_until.isoformat(),
                },
            )

        purged = evidence.with_purge()
        await self._repo.update(purged, expected_state=evidence.state)

        await self._audit.log(
            AuditEventType.EVIDENCE_DELETED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            actor_username=tenant.username,
            evidence_id=evidence_id,
            details=custody_details,
        )

        logger.info(
            "evidence_purged",
            extra={"evidence_id": str(evidence_id), "org_id": str(tenant.org_id)},
        )

    async def set_legal_hold(
        self,
        evidence_id: uuid.UUID,
        hold: bool,
        tenant: TenantContext,
    ) -> Evidence:
        """Set or clear a legal hold, mirrored onto the WORM object in storage.

        Restricted to org-admin / case-lead (Project_Specifications.md §2).
        A held object cannot be purged by ``delete_evidence`` regardless of
        Object Lock retention expiry.

        Raises:
            AuthorizationError: if the tenant lacks org-admin/case-lead.
            ValidationError: if evidence is not found, or has not yet been
                promoted to the WORM evidence bucket.
        """
        if not tenant.roles.intersection({Role.ORG_ADMIN, Role.CASE_LEAD}):
            raise AuthorizationError(
                "Only org-admin or case-lead may set legal hold",
                context={"user_id": str(tenant.user_id), "org_id": str(tenant.org_id)},
            )

        evidence = await self._repo.get_by_id(evidence_id, tenant.org_id)
        if evidence is None:
            raise ValidationError(
                "Evidence not found",
                context={"evidence_id": str(evidence_id), "org_id": str(tenant.org_id)},
            )
        if evidence.minio_evidence_key is None:
            raise ValidationError(
                "Legal hold can only be set on evidence promoted to the WORM bucket",
                context={"evidence_id": str(evidence_id), "state": evidence.state.value},
            )

        await self._storage.set_legal_hold(evidence.minio_evidence_key, hold, bucket="evidence")

        updated = evidence.with_legal_hold(hold)
        await self._repo.update(updated, expected_state=evidence.state)

        event_type = (
            AuditEventType.EVIDENCE_LEGAL_HOLD_SET
            if hold
            else AuditEventType.EVIDENCE_LEGAL_HOLD_CLEARED
        )
        await self._audit.log(
            event_type,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            actor_username=tenant.username,
            evidence_id=evidence_id,
            details={"hold": hold, "object_key": evidence.minio_evidence_key},
        )
        logger.info(
            "legal_hold_updated",
            extra={"evidence_id": str(evidence_id), "hold": hold},
        )
        return updated

    def _bucket_for_audit(self, evidence: Evidence) -> str | None:
        """Best-effort bucket name for a custody audit entry; never raises."""
        if evidence.minio_evidence_key is None:
            return None
        try:
            return self._storage.bucket_for(evidence.minio_evidence_key, bucket="evidence")
        except Exception:  # noqa: BLE001 — audit trail must never block on this
            return None

    async def _promote(
        self, evidence: Evidence, quarantine_key: str, tenant: TenantContext
    ) -> Evidence:
        prior_state = evidence.state
        evidence = evidence.with_state(EvidenceState.RECEIVED)
        evidence_key = await self._storage.promote_to_evidence_bucket(quarantine_key, evidence)
        await self._storage.delete_from_quarantine(quarantine_key)

        # Object Lock retain-until is set at promotion time (Project_Specifications.md
        # §2 "Retention Period"); mirrored on the domain row so delete_evidence can
        # enforce it without a round-trip to MinIO.
        retain_until = datetime.now(UTC) + timedelta(days=self._default_retention_days)
        evidence = evidence.with_keys(quarantine_key=None, evidence_key=evidence_key)
        evidence = evidence.with_object_lock_until(retain_until)
        await self._repo.update(evidence, expected_state=prior_state)
        await self._audit.log(
            AuditEventType.EVIDENCE_PROMOTED,
            org_id=tenant.org_id,
            actor_user_id=tenant.user_id,
            evidence_id=evidence.evidence_id,
            details={"evidence_key": evidence_key, "object_lock_until": retain_until.isoformat()},
        )
        logger.info(
            "evidence_received",
            extra={"evidence_id": str(evidence.evidence_id), "sha256": evidence.sha256},
        )

        # Auto-trigger the parsing pipeline.  If the queue is unavailable the
        # evidence remains safely in RECEIVED state; the auto_dispatch_received
        # beat task (runs every hour) will pick it up for retry.
        if self._task_queue is not None:
            try:
                task_id = await self._task_queue.enqueue_dispatch(evidence.evidence_id, tenant)
                logger.info(
                    "parse_dispatch_enqueued",
                    extra={"evidence_id": str(evidence.evidence_id), "task_id": task_id},
                )
            except Exception as exc:
                logger.warning(
                    "parse_dispatch_failed",
                    extra={"evidence_id": str(evidence.evidence_id), "error": str(exc)},
                )

        return evidence
