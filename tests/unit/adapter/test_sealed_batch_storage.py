"""Unit test for S3SealedBatchStorage's bucket-naming logic.

boto3 client construction performs no network I/O (same fixture pattern as
tests/unit/adapter/test_s3_storage_bugs.py) -- the real WORM write/Object
Lock behavior against a real MinIO is verified in poc/batch_sealing/, not
re-mocked here.
"""

from __future__ import annotations

import uuid

from src.adapter.storage.sealed_batch_storage import S3SealedBatchStorage


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
