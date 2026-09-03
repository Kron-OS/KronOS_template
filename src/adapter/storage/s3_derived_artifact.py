"""MinIO/S3-compatible storage for derived (non-evidentiary) artifact bytes.

Real-verified against live MinIO (``poc/minio_derived_artifact/``): a
bucket created WITHOUT ``ObjectLockEnabledForBucket`` genuinely has no
Object Lock (confirmed via a real ``get_object_lock_configuration`` call
returning ``ObjectLockConfigurationNotFoundError``) -- delete/regenerate
works, unlike ``S3EvidenceStorage``'s WORM evidence bucket. Deliberately a
separate class/bucket namespace (``kronos-derived-{org_alias}``), not a
mode flag on ``S3EvidenceStorage``, so a WORM/non-WORM choice can never be
accidentally toggled by a caller passing the wrong flag.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from src.adapter.storage.derived_artifact_storage import DerivedArtifactStorage
from src.exceptions import StorageError

logger = logging.getLogger(__name__)

_EXECUTOR = ThreadPoolExecutor(max_workers=8, thread_name_prefix="s3-derived-worker")


class S3DerivedArtifactStorage(DerivedArtifactStorage):
    """MinIO/S3 storage for derived artifact bytes, no Object Lock."""

    def __init__(
        self,
        endpoint_url: str,
        access_key: str,
        secret_key: str,
        bucket_prefix: str,
        use_tls: bool = True,
    ) -> None:
        client_config = Config(
            signature_version="s3v4",
            connect_timeout=10,
            read_timeout=60,
            retries={"max_attempts": 3},
        )
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            config=client_config,
        )
        self._bucket_prefix = bucket_prefix
        self._use_tls = use_tls

    async def put_object(
        self,
        org_alias: str,
        object_key: str,
        data: bytes,
        *,
        content_type: str = "application/octet-stream",
    ) -> None:
        bucket = self._bucket(org_alias)
        await self._ensure_bucket(bucket)
        try:
            await self._run(
                self._client.put_object,
                Bucket=bucket,
                Key=object_key,
                Body=data,
                ContentType=content_type,
            )
        except ClientError as exc:
            raise StorageError(
                "Failed to store derived artifact",
                context={"bucket": bucket, "key": object_key, "error": str(exc)},
            ) from exc
        logger.info(
            "derived_artifact_stored",
            extra={"bucket": bucket, "key": object_key, "size_bytes": len(data)},
        )

    async def stream_object(self, object_key: str, chunk_size: int = 65536) -> AsyncIterator[bytes]:
        bucket = self.bucket_for(object_key)
        return self._s3_stream(bucket, object_key, chunk_size)

    def bucket_for(self, object_key: str) -> str:
        org_alias = object_key.split("/")[0]
        return self._bucket(org_alias)

    def _bucket(self, org_alias: str) -> str:
        return f"{self._bucket_prefix}-{org_alias}"

    async def _run(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_EXECUTOR, lambda: fn(*args, **kwargs))

    async def _ensure_bucket(self, bucket: str) -> None:
        try:
            await self._run(self._client.head_bucket, Bucket=bucket)
        except ClientError:
            try:
                # Deliberately NO ObjectLockEnabledForBucket -- real-verified
                # (poc/minio_derived_artifact/) this is what makes the
                # difference between a WORM and non-WORM bucket.
                await self._run(self._client.create_bucket, Bucket=bucket)
            except self._client.exceptions.BucketAlreadyOwnedByYou:
                # Same check-then-act race S3EvidenceStorage._ensure_bucket
                # already documents -- concurrent first-uses of an org's
                # derived bucket all see the 404, only one create_bucket
                # call wins.
                logger.debug("derived_bucket_already_exists_race", extra={"bucket": bucket})
                return
            logger.info("derived_bucket_created", extra={"bucket": bucket})

    async def _s3_stream(self, bucket: str, key: str, chunk_size: int) -> AsyncIterator[bytes]:
        loop = asyncio.get_event_loop()
        try:
            response = await self._run(self._client.get_object, Bucket=bucket, Key=key)
        except ClientError as exc:
            raise StorageError(
                f"Derived artifact not found: {key}",
                context={"bucket": bucket, "key": key, "error": str(exc)},
            ) from exc

        body = response["Body"]
        while True:
            chunk = await loop.run_in_executor(_EXECUTOR, body.read, chunk_size)
            if not chunk:
                break
            yield chunk
