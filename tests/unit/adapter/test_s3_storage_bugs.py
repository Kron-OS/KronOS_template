"""Regression tests for S3EvidenceStorage bucket routing & naming.

Originally written as executable bug reports during the 2026-06 security audit
(findings C-1 and C-2); the defects have since been fixed, so these now assert
the corrected behaviour and guard against regressions.

See ``docs/SECURITY_AUDIT.md`` for the write-ups.
"""

from __future__ import annotations

import uuid

from src.adapter.storage.s3 import S3EvidenceStorage
from src.domain.evidence import Evidence, EvidenceMetadata, EvidenceState


def _make_storage(quarantine_prefix: str, evidence_prefix: str) -> S3EvidenceStorage:
    # boto3 client construction performs no network I/O, so this is a safe,
    # deterministic unit-level fixture.
    return S3EvidenceStorage(
        endpoint_url="http://minio:9000",
        access_key="key",
        secret_key="secret",
        quarantine_bucket_prefix=quarantine_prefix,
        evidence_bucket_prefix=evidence_prefix,
    )


def _evidence(org_alias: str = "acme") -> Evidence:
    meta = EvidenceMetadata(
        original_filename="security.evtx",
        content_type="application/octet-stream",
        size_bytes=1024,
        uploader_user_id=uuid.uuid4(),
        case_id=uuid.uuid4(),
        org_id=uuid.uuid4(),
        org_alias=org_alias,
    )
    return Evidence(metadata=meta, state=EvidenceState.RECEIVED)


# ---------------------------------------------------------------------------
# C-1: reads are now bucket-aware. A quarantine key resolves to the quarantine
#      bucket; the SAME key resolves to the evidence bucket when the caller asks
#      for it (parsing reads post-promotion evidence with bucket="evidence").
# ---------------------------------------------------------------------------


def test_quarantine_read_resolves_to_quarantine_bucket() -> None:
    storage = _make_storage("kronos-evidence", "kronos-evidence")
    ev = _evidence("acme")
    key = f"{ev.metadata.org_alias}/{ev.metadata.case_id}/{ev.evidence_id}"
    assert storage._bucket_for(key, "quarantine") == storage._quarantine_bucket("acme")


def test_evidence_read_resolves_to_evidence_bucket() -> None:
    """After promotion, reads must target the WORM evidence bucket (fix C-1)."""
    storage = _make_storage("kronos-evidence", "kronos-evidence")
    ev = _evidence("acme")
    evidence_key = f"{ev.metadata.org_alias}/{ev.metadata.case_id}/{ev.evidence_id}/security.evtx"
    assert storage._bucket_for(evidence_key, "evidence") == storage._evidence_bucket("acme")
    # ...and the two buckets are genuinely distinct.
    assert storage._evidence_bucket("acme") != storage._quarantine_bucket("acme")


# ---------------------------------------------------------------------------
# C-2: bucket names match the canonical convention in Project_Specifications.md
#      §2 and scripts/provision_buckets.sh:
#        quarantine -> "kronos-evidence-<org>-quarantine"
#        evidence   -> "kronos-evidence-<org>"
# ---------------------------------------------------------------------------

_PROVISIONED_QUARANTINE = "kronos-evidence-acme-quarantine"
_PROVISIONED_EVIDENCE = "kronos-evidence-acme"


def test_default_prefix_matches_provisioned_buckets() -> None:
    # config.py default prefix is "kronos-evidence" for both buckets.
    storage = _make_storage("kronos-evidence", "kronos-evidence")
    assert storage._quarantine_bucket("acme") == _PROVISIONED_QUARANTINE
    assert storage._evidence_bucket("acme") == _PROVISIONED_EVIDENCE
