"""SealedBatchStorage: one WORM object per sealed stream batch (roadmap M3/D3).

A sealed batch is conceptually another kind of WORM-protected artifact, not a
new storage mechanism -- this reuses the exact real mechanism
``S3EvidenceStorage`` (``src/adapter/storage/s3.py``) already proves against
real MinIO: a dedicated bucket with ``ObjectLockEnabledForBucket`` +
``COMPLIANCE``-mode default retention. It is a *separate*, small adapter
rather than a new method bolted onto ``S3EvidenceStorage`` because that
class's whole surface (``request_presigned_upload``, ``promote_to_evidence_bucket``,
...) is keyed on a real ``Evidence`` domain object (org_alias/case_id/
evidence_id/filename) -- a sealed batch has none of those; it belongs to an
``org_id`` (UUID, the real D1 stream key component, not a human-readable
alias) and a ``source_id``. Retrofitting ``Evidence``-shaped parameters onto
a stream-telemetry artifact would be exactly the "papering over with
sentinel values" anti-pattern ``StreamProvenance``'s own docstring already
rejected for this same reason.
"""

from __future__ import annotations

import asyncio
import uuid
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from src.exceptions import StorageError

_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="sealed-batch-s3-worker")


class SealedBatchStorage(ABC):
    """WORM object storage for sealed stream batches."""

    @abstractmethod
    async def put_batch(
        self, org_id: uuid.UUID, source_id: str, batch_id: uuid.UUID, manifest: bytes
    ) -> tuple[str, str]:
        """Write *manifest* as one WORM object. Returns (bucket, object_key)."""

    @abstractmethod
    async def get_batch(self, bucket: str, object_key: str) -> bytes:
        """Read back a sealed batch's manifest bytes (verification/audit use only --
        the sealing/inclusion-proof path never needs this, see SealedBatch's
        own docstring: leaf_hashes are stored in Postgres precisely so a proof
        never has to round-trip through object storage)."""


class S3SealedBatchStorage(SealedBatchStorage):
    """Real MinIO/S3 implementation -- one Object-Lock-Compliance bucket per org."""

    def __init__(
        self,
        endpoint_url: str,
        access_key: str,
        secret_key: str,
        bucket_prefix: str = "kronos-stream-batches",
        retention_days: int = 2555,
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
        self._retention_days = retention_days

    async def put_batch(
        self, org_id: uuid.UUID, source_id: str, batch_id: uuid.UUID, manifest: bytes
    ) -> tuple[str, str]:
        bucket = self._bucket_for(org_id)
        key = f"{source_id}/{batch_id}.json"
        await self._ensure_bucket(bucket)
        try:
            await self._run(self._client.put_object, Bucket=bucket, Key=key, Body=manifest)
        except ClientError as exc:
            raise StorageError(
                "Failed to write sealed batch WORM object",
                context={"bucket": bucket, "key": key, "error": str(exc)},
            ) from exc
        return bucket, key

    async def get_batch(self, bucket: str, object_key: str) -> bytes:
        try:
            resp = await self._run(self._client.get_object, Bucket=bucket, Key=object_key)
        except ClientError as exc:
            raise StorageError(
                "Failed to read sealed batch WORM object",
                context={"bucket": bucket, "key": object_key, "error": str(exc)},
            ) from exc
        return await self._run(resp["Body"].read)

    def _bucket_for(self, org_id: uuid.UUID) -> str:
        return f"{self._bucket_prefix}-{org_id}"

    async def _ensure_bucket(self, bucket: str) -> None:
        try:
            await self._run(self._client.head_bucket, Bucket=bucket)
            return
        except ClientError:
            pass
        try:
            await self._run(
                self._client.create_bucket,
                Bucket=bucket,
                ObjectLockEnabledForBucket=True,
            )
        except self._client.exceptions.BucketAlreadyOwnedByYou:
            # Same concurrent-first-use race S3EvidenceStorage._ensure_bucket
            # documents and handles -- two sealers for the same org racing on
            # bucket creation is the identical shape, same fix.
            return
        await self._run(
            self._client.put_object_lock_configuration,
            Bucket=bucket,
            ObjectLockConfiguration={
                "ObjectLockEnabled": "Enabled",
                "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": self._retention_days}},
            },
        )

    async def _run(self, fn: Any, *args: Any, **kwargs: Any) -> Any:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(_EXECUTOR, lambda: fn(*args, **kwargs))
