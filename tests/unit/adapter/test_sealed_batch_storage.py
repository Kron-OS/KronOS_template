"""Unit test for S3SealedBatchStorage's bucket-naming logic.

boto3 client construction performs no network I/O (same fixture pattern as
tests/unit/adapter/test_s3_storage_bugs.py) -- the real WORM write/Object
Lock behavior against a real MinIO is verified in poc/batch_sealing/, not
re-mocked here.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from src.adapter.storage.sealed_batch_storage import S3SealedBatchStorage
from src.exceptions import StorageError


def test_bucket_name_is_prefix_plus_org_id() -> None:
    storage = S3SealedBatchStorage(
        endpoint_url="http://minio:9000",
        access_key="key",
        secret_key="secret",
        bucket_prefix="kronos-stream-batches",
    )
    org_id = uuid.uuid4()

    assert storage._bucket_for(org_id) == f"kronos-stream-batches-{org_id}"


def test_bucket_prefix_is_configurable() -> None:
    storage = S3SealedBatchStorage(
        endpoint_url="http://minio:9000",
        access_key="key",
        secret_key="secret",
        bucket_prefix="custom-prefix",
    )
    org_id = uuid.uuid4()

    assert storage._bucket_for(org_id) == f"custom-prefix-{org_id}"


# ---------------------------------------------------------------------------
# Gap Audit Milestone WW: _ensure_bucket() used to trust an already-existing
# bucket (head_bucket succeeds) was automatically WORM-protected, without
# ever checking. Real shapes verified live against MinIO
# RELEASE.2025-09-07T16-13-09Z (poc/minio_object_lock_verification/) --
# mirrors test_s3_storage_bugs.py's own equivalent coverage for
# S3EvidenceStorage, added in the same pass.
# ---------------------------------------------------------------------------


def _make_storage() -> S3SealedBatchStorage:
    return S3SealedBatchStorage(
        endpoint_url="http://minio:9000",
        access_key="key",
        secret_key="secret",
        bucket_prefix="kronos-stream-batches",
    )


def _not_found() -> ClientError:
    return ClientError(
        error_response={"Error": {"Code": "404", "Message": "Not Found"}},
        operation_name="HeadBucket",
    )


async def test_ensure_bucket_reapplies_missing_retention_on_pre_existing_bucket() -> None:
    storage = _make_storage()
    mock_client = MagicMock()
    mock_client.get_object_lock_configuration.return_value = {
        "ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}  # no Rule
    }
    storage._client = mock_client

    await storage._ensure_bucket("kronos-stream-batches-org1")

    mock_client.head_bucket.assert_called_once_with(Bucket="kronos-stream-batches-org1")
    mock_client.get_object_lock_configuration.assert_called_once_with(
        Bucket="kronos-stream-batches-org1"
    )
    mock_client.put_object_lock_configuration.assert_called_once()
    mock_client.create_bucket.assert_not_called()


async def test_ensure_bucket_pre_existing_healthy_bucket_is_a_true_no_op() -> None:
    storage = _make_storage()
    mock_client = MagicMock()
    mock_client.get_object_lock_configuration.return_value = {
        "ObjectLockConfiguration": {
            "ObjectLockEnabled": "Enabled",
            "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 2555}},
        }
    }
    storage._client = mock_client

    await storage._ensure_bucket("kronos-stream-batches-org1")

    mock_client.put_object_lock_configuration.assert_not_called()


async def test_ensure_bucket_pre_existing_never_object_locked_fails_loudly() -> None:
    storage = _make_storage()
    mock_client = MagicMock()
    mock_client.get_object_lock_configuration.side_effect = ClientError(
        error_response={
            "Error": {
                "Code": "ObjectLockConfigurationNotFoundError",
                "Message": "Object Lock configuration does not exist for this bucket",
            },
            "ResponseMetadata": {"HTTPStatusCode": 404},
        },
        operation_name="GetObjectLockConfiguration",
    )
    storage._client = mock_client

    with pytest.raises(StorageError):
        await storage._ensure_bucket("kronos-stream-batches-org1")

    mock_client.put_object_lock_configuration.assert_not_called()


async def test_ensure_bucket_creates_fresh_bucket_when_missing() -> None:
    """Unchanged happy path: a genuinely new bucket still gets created with
    Object Lock enabled and its retention rule applied in one pass, no
    extra get_object_lock_configuration call needed (nothing to verify on
    a bucket this same call just created)."""
    storage = _make_storage()
    mock_client = MagicMock()
    mock_client.head_bucket.side_effect = _not_found()
    storage._client = mock_client

    await storage._ensure_bucket("kronos-stream-batches-org1")

    mock_client.create_bucket.assert_called_once_with(
        Bucket="kronos-stream-batches-org1", ObjectLockEnabledForBucket=True
    )
    mock_client.put_object_lock_configuration.assert_called_once()
    mock_client.get_object_lock_configuration.assert_not_called()
