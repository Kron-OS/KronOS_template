"""
Real-dependency PoC: S3EvidenceStorage (src/adapter/storage/s3.py) against a
real MinIO server.

Per CLAUDE.md Section F: exercises the REAL S3EvidenceStorage class (no
reimplementation of its logic) against a real, pinned MinIO container.

Pinned versions (do not deviate without re-checking the repo):
  - docker/docker-compose.dev.yml: image: minio/minio:latest
  - pyproject.toml: boto3>=1.34, aiobotocore>=2.13

Container (this PoC, not the repo's dev compose):
  docker run -d --name kronos-poc-minio-server \
    -p 19100:9000 -p 19101:9001 \
    -e MINIO_ROOT_USER=kronosadmin -e MINIO_ROOT_PASSWORD=kronossecret123 \
    minio/minio:latest server /data --console-address ":9001"

Run:
  ~/venv/bin/python3 poc/minio/run_poc.py
"""
from __future__ import annotations

import asyncio
import sys
import uuid
from pathlib import Path

import boto3
import requests
from botocore.config import Config
from botocore.exceptions import ClientError

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.adapter.storage.s3 import S3EvidenceStorage  # noqa: E402
from src.exceptions import StorageError  # noqa: E402
from tests.fixtures.factories import make_evidence  # noqa: E402

ENDPOINT = "http://127.0.0.1:19100"
ACCESS_KEY = "kronosadmin"
SECRET_KEY = "kronossecret123"
ORG_ALIAS = "testorg"

# Raw boto3 client used ONLY for out-of-band verification (checking what
# MinIO actually did), never for exercising S3EvidenceStorage's own logic.
_raw = boto3.client(
    "s3",
    endpoint_url=ENDPOINT,
    aws_access_key_id=ACCESS_KEY,
    aws_secret_access_key=SECRET_KEY,
    config=Config(signature_version="s3v4"),
)


def section(title: str) -> None:
    print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")


async def main() -> None:
    storage = S3EvidenceStorage(
        endpoint_url=ENDPOINT,
        access_key=ACCESS_KEY,
        secret_key=SECRET_KEY,
        quarantine_bucket_prefix="kronos-quarantine",
        evidence_bucket_prefix="kronos-evidence",
        retention_days=1,  # short retention for the PoC; still COMPLIANCE mode
        use_tls=False,
    )

    section("1. request_presigned_upload -> lazily creates quarantine bucket")
    evidence = make_evidence()
    presigned = await storage.request_presigned_upload(evidence, expires_in_seconds=600)
    q_bucket = storage._quarantine_bucket(ORG_ALIAS)
    ev_bucket = storage._evidence_bucket(ORG_ALIAS)
    print(f"quarantine bucket: {q_bucket}")
    print(f"evidence bucket:   {ev_bucket}")
    print(f"presigned URL: {presigned.url[:110]}...")
    print(f"object_key: {presigned.object_key}")

    section("2. Real HTTP PUT of bytes to the presigned URL")
    payload = b"MZ\x90\x00fake-evidence-bytes-for-poc-" + uuid.uuid4().bytes
    put_resp = requests.put(presigned.url, data=payload)
    print(f"real HTTP PUT status: {put_resp.status_code}")
    assert put_resp.status_code == 200, f"PUT failed: {put_resp.status_code} {put_resp.text}"

    section("3. object_exists() on the quarantine key (default bucket='quarantine')")
    exists = await storage.object_exists(presigned.object_key)
    print(f"object_exists(quarantine_key) = {exists}")
    assert exists is True

    section("4. Verify quarantine bucket has NO Object Lock (out-of-band check)")
    try:
        _raw.get_object_lock_configuration(Bucket=q_bucket)
        print("UNEXPECTED: quarantine bucket has Object Lock enabled")
    except ClientError as exc:
        print(f"Confirmed (expected): {exc.response['Error']['Code']} - quarantine bucket has no lock config")

    section("5. promote_to_evidence_bucket() -> lazily creates evidence bucket w/ Object Lock")
    ev_key = await storage.promote_to_evidence_bucket(presigned.object_key, evidence)
    print(f"promoted to evidence key: {ev_key}")

    section("6. Verify evidence bucket really has Object Lock + COMPLIANCE default retention")
    lock_cfg = _raw.get_object_lock_configuration(Bucket=ev_bucket)["ObjectLockConfiguration"]
    print(f"ObjectLockConfiguration: {lock_cfg}")
    assert lock_cfg["ObjectLockEnabled"] == "Enabled"
    assert lock_cfg["Rule"]["DefaultRetention"]["Mode"] == "COMPLIANCE"
    print("PASS: evidence bucket has Object Lock ENABLED with COMPLIANCE default retention"
          f" ({lock_cfg['Rule']['DefaultRetention']['Days']} day(s))")

    section("7. THE KEY QUESTION: did the promoted (copy_object'd) object actually "
            "inherit the bucket's default retention, or does MinIO's CopyObject "
            "skip default-retention inheritance the way some S3-compatible stores do?")
    try:
        retention = _raw.get_object_retention(Bucket=ev_bucket, Key=ev_key)["Retention"]
        print(f"get_object_retention(promoted object) = {retention}")
        assert retention["Mode"] == "COMPLIANCE"
        print("PASS: promoted object really carries COMPLIANCE retention "
              f"until {retention['RetainUntilDate']} (real MinIO response, not assumed)")
        retention_applied = True
    except ClientError as exc:
        print(f"get_object_retention FAILED: {exc.response['Error']['Code']}: "
              f"{exc.response['Error']['Message']}")
        retention_applied = False

    section("8. object_exists()/stream_object() with bucket='evidence' (post-promotion "
            "contract used by parsing_orchestration.py against evidence.minio_evidence_key) "
            "-- run BEFORE any destructive delete tests below")
    exists_ev = await storage.object_exists(ev_key, bucket="evidence")
    print(f"object_exists(ev_key, bucket='evidence') = {exists_ev}")
    assert exists_ev is True
    stream = await storage.stream_object(ev_key, bucket="evidence")
    data = b"".join([c async for c in stream])
    print(f"stream_object(ev_key, bucket='evidence') read {len(data)} bytes; "
          f"matches originally uploaded payload: {data == payload}")
    assert data == payload

    section("9. delete_from_quarantine() -- confirm quarantine copy actually removed")
    await storage.delete_from_quarantine(presigned.object_key)
    try:
        _raw.head_object(Bucket=q_bucket, Key=presigned.object_key)
        print("FAIL: quarantine object still present after delete_from_quarantine")
    except ClientError:
        print("PASS: quarantine object confirmed gone after delete_from_quarantine")

    section("10. Bucket versioning check -- Object Lock requires versioning; does "
            "create_bucket(ObjectLockEnabledForBucket=True) really auto-enable it on MinIO?")
    versioning = _raw.get_bucket_versioning(Bucket=ev_bucket)
    print(f"get_bucket_versioning(evidence bucket) = {versioning.get('Status')}")
    assert versioning.get("Status") == "Enabled"
    print("PASS: MinIO auto-enabled versioning for the Object-Lock bucket (matches AWS S3 "
          "semantics: ObjectLockEnabledForBucket=True implies versioning).")

    versions = _raw.list_object_versions(Bucket=ev_bucket, Prefix=ev_key)
    locked_version_id = versions["Versions"][0]["VersionId"]
    print(f"retained version id of the promoted object: {locked_version_id}")

    section("11. Unqualified delete_object() (no VersionId) -- versioned-bucket semantics "
            "predict this only adds a delete marker, it must NOT destroy the locked version "
            "(this is a deliberately destructive probe against the object created above; "
            "everything of interest was already verified in steps 8-9)")
    _raw.delete_object(Bucket=ev_bucket, Key=ev_key)
    still_there = _raw.list_object_versions(Bucket=ev_bucket, Prefix=ev_key)
    surviving_ids = [v["VersionId"] for v in still_there.get("Versions", [])]
    print(f"versions surviving after unqualified delete: {surviving_ids}")
    assert locked_version_id in surviving_ids
    print("Confirmed: unqualified delete only added a delete-marker; the retained, "
          "compliance-locked version is untouched (expected S3 versioned-bucket behavior, "
          "not a bug in itself).")

    section("12. THE HIGH-VALUE CHECK: try to permanently delete the SPECIFIC locked "
            "VersionId -- this is the real test of compliance-mode WORM enforcement")
    try:
        _raw.delete_object(Bucket=ev_bucket, Key=ev_key, VersionId=locked_version_id)
        print("!!! BUG CONFIRMED: delete_object(VersionId=<locked>) SUCCEEDED -- the "
              "compliance-locked version was permanently destroyed before its retention "
              "date. Zero real WORM enforcement.")
        delete_blocked = False
    except ClientError as exc:
        print(f"delete_object(VersionId=<locked>) REJECTED by real MinIO: "
              f"{exc.response['Error']['Code']}: {exc.response['Error']['Message']}")
        print("PASS: MinIO's compliance-mode retention genuinely blocks permanent removal "
              "of the specific locked version before its RetainUntilDate.")
        delete_blocked = True

    section("13. Confirm the locked version's bytes are still byte-for-byte intact/fetchable")
    got = _raw.get_object(Bucket=ev_bucket, Key=ev_key, VersionId=locked_version_id)
    recovered = got["Body"].read()
    print(f"fetched {len(recovered)} bytes via VersionId; matches original upload: "
          f"{recovered == payload}")
    assert recovered == payload

    section("14. set_legal_hold() -- on a SECOND, untouched evidence object (evidence #1's "
            "'latest' pointer is now a delete-marker from step 11's destructive probe, which "
            "would make put_object_legal_hold target the marker instead of a real object -- "
            "that's a test-ordering artifact, not an app bug, so use a clean object here)")
    evidence2 = make_evidence()
    presigned2 = await storage.request_presigned_upload(evidence2, expires_in_seconds=600)
    payload2 = b"MZ\x90\x00second-evidence-object-for-legal-hold-poc"
    put2 = requests.put(presigned2.url, data=payload2)
    assert put2.status_code == 200
    ev_key2 = await storage.promote_to_evidence_bucket(presigned2.object_key, evidence2)
    print(f"second evidence object promoted: {ev_key2}")

    await storage.set_legal_hold(ev_key2, True, bucket="evidence")
    hold_status = _raw.get_object_legal_hold(Bucket=ev_bucket, Key=ev_key2)["LegalHold"]
    print(f"get_object_legal_hold after set_legal_hold(True) = {hold_status}")
    assert hold_status["Status"] == "ON"
    print("PASS: legal hold really set to ON in real MinIO")

    section("15. With legal hold ON: confirm delete of this version is rejected "
            "(independent of / in addition to compliance retention)")
    v2 = _raw.list_object_versions(Bucket=ev_bucket, Prefix=ev_key2)["Versions"][0]["VersionId"]
    try:
        _raw.delete_object(Bucket=ev_bucket, Key=ev_key2, VersionId=v2)
        print("!!! BUG: delete succeeded despite legal hold ON")
        legal_hold_blocks = False
    except ClientError as exc:
        print(f"delete_object(VersionId=<v2>) REJECTED with legal hold ON: "
              f"{exc.response['Error']['Code']}: {exc.response['Error']['Message']}")
        legal_hold_blocks = True

    section("16. Clear legal hold (set_legal_hold(False)) and verify")
    await storage.set_legal_hold(ev_key2, False, bucket="evidence")
    hold_status = _raw.get_object_legal_hold(Bucket=ev_bucket, Key=ev_key2)["LegalHold"]
    print(f"get_object_legal_hold after set_legal_hold(False) = {hold_status}")
    assert hold_status["Status"] == "OFF"
    print("PASS: legal hold cleared in real MinIO")

    section("17. bucket_for() sanity check (used for chain-of-custody audit entries)")
    resolved = storage.bucket_for(ev_key, bucket="evidence")
    print(f"bucket_for(ev_key, bucket='evidence') = {resolved}")
    assert resolved == ev_bucket

    section("SUMMARY")
    print(f"retention actually inherited by promoted (copy_object) evidence object: {retention_applied}")
    print(f"delete of the exact locked VersionId blocked under COMPLIANCE retention: {delete_blocked}")
    print(f"legal hold independently blocks delete of the exact version: {legal_hold_blocks}")


if __name__ == "__main__":
    asyncio.run(main())
