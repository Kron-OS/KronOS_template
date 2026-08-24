"""Gap Audit Milestone WW: real MinIO Object Lock verification.

Reproduces, against the real, running docker-minio-1 container (MinIO
RELEASE.2025-09-07T16-13-09Z, boto3/botocore 1.43.46 -- the exact versions
this repo runs), the three bucket states
S3EvidenceStorage._ensure_bucket()/S3SealedBatchStorage._ensure_bucket()
need to distinguish:

  (a) A bucket created with ObjectLockEnabledForBucket=True but where
      put_object_lock_configuration was never applied (the real partial-
      failure state this milestone's finding is about) -- what does
      get_object_lock_configuration actually return for it?
  (b) A bucket created WITHOUT ObjectLockEnabledForBucket at all (the
      unrecoverable case) -- same question, plus: does retroactively
      calling put_object_lock_configuration on it really fail?
  (c) A bucket created the normal, complete way (both steps) -- the
      healthy baseline to compare against.

Creates and deletes its own throwaway buckets only (kronos-poc-objlock-*),
never touches any real evidence/sealed-batch bucket.
"""

from __future__ import annotations

import sys
import uuid

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

ENDPOINT_URL = "http://localhost:9000"
ACCESS_KEY = "kronos_minio"
SECRET_KEY = "kronos_minio_dev_password"

_RUN_ID = uuid.uuid4().hex[:8]


def _client():
    return boto3.client(
        "s3",
        endpoint_url=ENDPOINT_URL,
        aws_access_key_id=ACCESS_KEY,
        aws_secret_access_key=SECRET_KEY,
        config=Config(signature_version="s3v4"),
    )


def _print_header(title: str) -> None:
    print("\n" + "=" * 80)
    print(title)
    print("=" * 80)


def _try_get_object_lock_configuration(client, bucket: str) -> None:
    try:
        resp = client.get_object_lock_configuration(Bucket=bucket)
        resp.pop("ResponseMetadata", None)
        print(f"get_object_lock_configuration({bucket}) SUCCEEDED, body:")
        print(f"  {resp!r}")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        http_status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        print(f"get_object_lock_configuration({bucket}) RAISED ClientError:")
        print(f"  HTTPStatusCode={http_status} Code={code!r} Message={message!r}")


def scenario_a_partial_failure(client) -> str:
    """Object-lock enabled at creation, but put_object_lock_configuration
    deliberately never called -- simulates a crash/transient-failure
    between the two real calls _ensure_bucket() makes."""
    bucket = f"kronos-poc-objlock-{_RUN_ID}-a"
    _print_header(f"SCENARIO (a): partial failure -- {bucket}")
    client.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)
    print(f"create_bucket(Bucket={bucket!r}, ObjectLockEnabledForBucket=True) -- OK")
    print("(deliberately NOT calling put_object_lock_configuration)")
    _try_get_object_lock_configuration(client, bucket)
    print("\nNow attempting the RECOVERY put_object_lock_configuration call "
          "(what a fixed _ensure_bucket() would do):")
    try:
        client.put_object_lock_configuration(
            Bucket=bucket,
            ObjectLockConfiguration={
                "ObjectLockEnabled": "Enabled",
                "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 2555}},
            },
        )
        print("  put_object_lock_configuration RECOVERY call SUCCEEDED")
        _try_get_object_lock_configuration(client, bucket)
    except ClientError as exc:
        print(f"  put_object_lock_configuration RECOVERY call FAILED: {exc}")
    return bucket


def scenario_b_never_enabled(client) -> str:
    """A bucket created WITHOUT ObjectLockEnabledForBucket at all -- the
    real 'wrong bucket, unrecoverable' case."""
    bucket = f"kronos-poc-objlock-{_RUN_ID}-b"
    _print_header(f"SCENARIO (b): object-lock never enabled -- {bucket}")
    client.create_bucket(Bucket=bucket)
    print(f"create_bucket(Bucket={bucket!r}) [no ObjectLockEnabledForBucket] -- OK")
    _try_get_object_lock_configuration(client, bucket)
    print("\nNow attempting to retroactively enable Object Lock on it "
          "(confirming this really is unrecoverable, not assumed):")
    try:
        client.put_object_lock_configuration(
            Bucket=bucket,
            ObjectLockConfiguration={
                "ObjectLockEnabled": "Enabled",
                "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 2555}},
            },
        )
        print("  put_object_lock_configuration SUCCEEDED (unexpected!)")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
        print(f"  put_object_lock_configuration FAILED as expected: Code={code!r} Message={message!r}")
    return bucket


def scenario_c_healthy(client) -> str:
    """The normal, complete two-step sequence _ensure_bucket() performs on
    a genuinely fresh bucket -- the healthy baseline."""
    bucket = f"kronos-poc-objlock-{_RUN_ID}-c"
    _print_header(f"SCENARIO (c): healthy, complete setup -- {bucket}")
    client.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)
    client.put_object_lock_configuration(
        Bucket=bucket,
        ObjectLockConfiguration={
            "ObjectLockEnabled": "Enabled",
            "Rule": {"DefaultRetention": {"Mode": "COMPLIANCE", "Days": 2555}},
        },
    )
    print(f"create_bucket + put_object_lock_configuration on {bucket!r} -- both OK")
    _try_get_object_lock_configuration(client, bucket)
    return bucket


def cleanup(client, buckets: list[str]) -> None:
    _print_header("CLEANUP")
    for bucket in buckets:
        try:
            # Object-locked buckets with real retention can't have their
            # objects deleted before retention expires, but these buckets
            # have zero objects in them (only bucket-level config was
            # exercised), so a bare delete_bucket is sufficient.
            client.delete_bucket(Bucket=bucket)
            print(f"deleted {bucket}")
        except ClientError as exc:
            print(f"WARNING: could not delete {bucket}: {exc}")


def main() -> int:
    client = _client()
    buckets: list[str] = []
    try:
        buckets.append(scenario_a_partial_failure(client))
        buckets.append(scenario_b_never_enabled(client))
        buckets.append(scenario_c_healthy(client))
    finally:
        cleanup(client, buckets)
    return 0


if __name__ == "__main__":
    sys.exit(main())
