"""PoC: verify a DERIVED-artifact bucket pattern against the real, live
dev-stack MinIO (docker-minio-1, minio/minio:latest, port 9000) -- bucket
creation WITHOUT Object Lock, put, stream-back byte-for-byte, and confirm
that (unlike the WORM evidence bucket) delete actually succeeds -- proving
these are regenerable, non-evidentiary objects as the plan requires.

Uses a distinct kronos-poc-* bucket name per CLAUDE.md's PoC-naming
convention -- does not touch any real org's quarantine/evidence bucket.

Run for real inside docker-kronos-backend-1 (has boto3==1.43.56 already
installed, real MINIO_ENDPOINT/ACCESS_KEY/SECRET_KEY env vars already
present in that container's real environment from docker-compose.dev.yml).
"""

from __future__ import annotations

import hashlib
import json

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

ENDPOINT = "http://minio:9000"
ACCESS_KEY = "kronos_minio"
SECRET_KEY = "kronos_minio_dev_password"
BUCKET = "kronos-poc-derived-artifacts"
KEY = "poc-org/case-1234/evidence-5678/artifact-9/dumpfiles/example.dat"

results: dict = {}

client = boto3.client(
    "s3",
    endpoint_url=ENDPOINT,
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    config=Config(signature_version="s3v4", connect_timeout=10, read_timeout=30),
)

# 1. Clean slate: delete the PoC bucket if a prior run left it behind.
try:
    objs = client.list_objects_v2(Bucket=BUCKET)
    for obj in objs.get("Contents", []):
        client.delete_object(Bucket=BUCKET, Key=obj["Key"])
    client.delete_bucket(Bucket=BUCKET)
    results["pre_cleanup"] = "removed pre-existing PoC bucket"
except ClientError as exc:
    results["pre_cleanup"] = f"nothing to clean ({exc.response['Error']['Code']})"

# 2. Create the bucket WITHOUT ObjectLockEnabledForBucket -- this is the
# entire point of the DerivedArtifactStorage design: derived/regenerable
# content does NOT get WORM protection, unlike the evidence bucket.
client.create_bucket(Bucket=BUCKET)
results["bucket_created"] = BUCKET

# 3. Confirm real Object Lock status on the new bucket -- must be
# genuinely absent, not just "not configured by us" (verify, don't assume,
# same discipline as poc/minio_object_lock_verification/).
try:
    lock_cfg = client.get_object_lock_configuration(Bucket=BUCKET)
    results["object_lock_configuration"] = lock_cfg.get("ObjectLockConfiguration", {})
except ClientError as exc:
    results["object_lock_configuration_error"] = exc.response["Error"]["Code"]

# 4. Put a real object -- simulates a dumped file's bytes.
payload = b"KronOS PoC: simulated extracted-file bytes for DerivedArtifactStorage\n" * 500
sha256 = hashlib.sha256(payload).hexdigest()
client.put_object(Bucket=BUCKET, Key=KEY, Body=payload)
results["put_object"] = {"key": KEY, "size_bytes": len(payload), "sha256": sha256}

# 5. Stream it back and confirm byte-for-byte + hash match.
resp = client.get_object(Bucket=BUCKET, Key=KEY)
body = resp["Body"].read()
results["get_object"] = {
    "size_bytes": len(body),
    "sha256": hashlib.sha256(body).hexdigest(),
    "matches_original_bytes": body == payload,
}

# 6. Confirm delete actually succeeds (would be BLOCKED on the real
# evidence WORM bucket during its retention period -- this is the
# functional contrast that justifies a separate storage class).
client.delete_object(Bucket=BUCKET, Key=KEY)
try:
    client.head_object(Bucket=BUCKET, Key=KEY)
    results["delete_confirmed"] = False
except ClientError as exc:
    results["delete_confirmed"] = exc.response["Error"]["Code"] in ("404", "NoSuchKey")

# 7. Cleanup: remove the PoC bucket entirely.
client.delete_bucket(Bucket=BUCKET)
results["post_cleanup"] = "PoC bucket removed"

print(json.dumps(results, indent=2, default=str))
