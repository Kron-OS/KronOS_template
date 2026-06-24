"""MinIO/S3-compatible object storage implementation."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from src.adapter.storage.storage import EvidenceStorage, PresignedUploadResponse
from src.domain.evidence import Evidence
from src.exceptions import StorageError

logger = logging.getLogger(__name__)

# Thread pool for boto3 blocking calls — kept small since uploads are client-direct.
_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="s3-worker")


class S3EvidenceStorage(EvidenceStorage):
    """MinIO/S3 storage using presigned URLs for direct client uploads.

    Evidence lands first in a per-org quarantine bucket (no Object Lock),
    then is promoted to the WORM evidence bucket (Object Lock Compliance).
    """

    HEADER_BYTES = 8192  # bytes fetched for magic-byte validation

    def __init__(
        self,
        endpoint_url: str,
        access_key: str,
        secret_key: str,
        quarantine_bucket_prefix: str,
        evidence_bucket_prefix: str,
        retention_days: int = 2555,
        use_tls: bool = True,
    ) -> None:
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=Config(
                signature_version="s3v4",
                connect_timeout=10,
                read_timeout=60,
                retries={"max_attempts": 3},
            ),
        )
        self._quarantine_prefix = quarantine_bucket_prefix
        self._evidence_prefix = evidence_bucket_prefix
        self._retention_days = retention_days
        self._use_tls = use_tls

    # ------------------------------------------------------------------
    # EvidenceStorage interface
    # ------------------------------------------------------------------

    async def request_presigned_upload(
        self, evidence: Evidence, expires_in_seconds: int = 3600
    ) -> PresignedUploadResponse:
        bucket = self._quarantine_bucket(evidence.metadata.org_alias)
        key = self._object_key(evidence)
        url = await self._run(
            self._client.generate_presigned_url,
            "put_object",
            Params={"Bucket": bucket, "Key": key},
            ExpiresIn=expires_in_seconds,
        )
        logger.info(
            "presigned_url_generated",
            extra={"evidence_id": str(evidence.evidence_id), "bucket": bucket, "key": key},
        )
        return PresignedUploadResponse(
            url=url, object_key=key, expires_in_seconds=expires_in_seconds
        )

    async def stream_object(self, object_key: str, chunk_size: int = 65536) -> AsyncIterator[bytes]:
        # Determine which bucket holds the key based on path convention.
        bucket = self._bucket_for_key(object_key)
        return self._s3_stream(bucket, object_key, chunk_size)

    async def promote_to_evidence_bucket(self, quarantine_key: str, evidence: Evidence) -> str:
        q_bucket = self._quarantine_bucket(evidence.metadata.org_alias)
        ev_bucket = self._evidence_bucket(evidence.metadata.org_alias)
        ev_key = self._object_key(evidence)

        try:
            await self._run(
                self._client.copy_object,
                Bucket=ev_bucket,
                Key=ev_key,
                CopySource={"Bucket": q_bucket, "Key": quarantine_key},
                MetadataDirective="COPY",
            )
        except ClientError as exc:
            raise StorageError(
                "Failed to promote evidence to WORM bucket",
                context={"quarantine_key": quarantine_key, "error": str(exc)},
            ) from exc

        logger.info(
            "evidence_promoted",
            extra={"evidence_id": str(evidence.evidence_id), "ev_key": ev_key},
        )
        return ev_key

    async def delete_from_quarantine(self, quarantine_key: str) -> None:
        # Derive org_alias from key convention: <org_alias>/<case_id>/<evidence_id>
        org_alias = quarantine_key.split("/")[0]
        bucket = self._quarantine_bucket(org_alias)
        try:
            await self._run(self._client.delete_object, Bucket=bucket, Key=quarantine_key)
        except ClientError as exc:
            raise StorageError(
                "Failed to delete from quarantine",
                context={"quarantine_key": quarantine_key, "error": str(exc)},
            ) from exc

    async def object_exists(self, object_key: str) -> bool:
        bucket = self._bucket_for_key(object_key)
        try:
            await self._run(self._client.head_object, Bucket=bucket, Key=object_key)
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("404", "NoSuchKey"):
                return False
            raise StorageError(
                "Error checking object existence",
                context={"object_key": object_key, "error": str(exc)},
            ) from exc

    # ------------------------------------------------------------------
    # Bucket management helpers (called at startup)
    # ------------------------------------------------------------------

    async def ensure_quarantine_bucket(self, org_alias: str) -> None:
        """Create the quarantine bucket if it does not exist."""
        bucket = self._quarantine_bucket(org_alias)
        await self._ensure_bucket(bucket, object_lock=False)

    async def ensure_evidence_bucket(self, org_alias: str) -> None:
        """Create the WORM evidence bucket with Object Lock if it does not exist."""
        bucket = self._evidence_bucket(org_alias)
        await self._ensure_bucket(bucket, object_lock=True)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _quarantine_bucket(self, org_alias: str) -> str:
        return f"{self._quarantine_prefix}-{org_alias}-quarantine"

    def _evidence_bucket(self, org_alias: str) -> str:
        return f"{self._evidence_prefix}-{org_alias}"

    def _bucket_for_key(self, key: str) -> str:
        # Keys are prefixed with org_alias; evidence keys have no "-quarantine" suffix.
        org_alias = key.split("/")[0]
        return self._quarantine_bucket(org_alias)

    @staticmethod
    def _object_key(evidence: Evidence) -> str:
        return (
            f"{evidence.metadata.org_alias}"
            f"/{evidence.metadata.case_id}"
            f"/{evidence.evidence_id}"
            f"/{evidence.metadata.original_filename}"
        )

    async def _run(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_EXECUTOR, lambda: fn(*args, **kwargs))

    async def _ensure_bucket(self, bucket: str, object_lock: bool) -> None:
        try:
            await self._run(self._client.head_bucket, Bucket=bucket)
        except ClientError:
            kwargs: dict[str, Any] = {"Bucket": bucket}
            if object_lock:
                kwargs["ObjectLockEnabledForBucket"] = True
            await self._run(self._client.create_bucket, **kwargs)
            logger.info("bucket_created", extra={"bucket": bucket, "object_lock": object_lock})

    async def _s3_stream(  # type: ignore[misc]
        self, bucket: str, key: str, chunk_size: int
    ) -> AsyncIterator[bytes]:
        loop = asyncio.get_event_loop()
        try:
            response = await self._run(self._client.get_object, Bucket=bucket, Key=key)
        except ClientError as exc:
            raise StorageError(
                f"Object not found: {key}",
                context={"bucket": bucket, "key": key, "error": str(exc)},
            ) from exc

        body = response["Body"]
        while True:
            chunk = await loop.run_in_executor(_EXECUTOR, body.read, chunk_size)
            if not chunk:
                break
            yield chunk
