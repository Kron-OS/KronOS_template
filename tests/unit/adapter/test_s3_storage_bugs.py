"""Regression / bug-report tests for S3EvidenceStorage bucket routing.

These tests were written during the 2026-06 security & deployment audit.
They are executable bug reports: each asserts the *correct* behaviour and is
marked ``xfail`` because the current implementation is defective.  When a bug
is fixed the corresponding test flips to XPASS, signalling that the xfail
marker should be removed.

See ``docs/SECURITY_AUDIT.md`` (findings C-1 and C-2) for full write-ups.
"""

from __future__ import annotations

import uuid

import pytest

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
# C-1: stream_object() / object_exists() always resolve to the quarantine
#      bucket, so a *promoted* evidence object (which has been deleted from
#      quarantine) can never be read.  This silently breaks parsing in
#      production; it is masked in the test-suite because LocalEvidenceStorage
#      searches both buckets.
# ---------------------------------------------------------------------------


def test_bucket_for_key_resolves_quarantine_correctly() -> None:
    """A quarantine key must resolve to the quarantine bucket (sanity)."""
    storage = _make_storage("kronos", "kronos")
    ev = _evidence("acme")
    quarantine_key = f"{ev.metadata.org_alias}/{ev.metadata.case_id}/{ev.evidence_id}"
    assert storage._bucket_for_key(quarantine_key) == storage._quarantine_bucket("acme")


@pytest.mark.xfail(
    reason="BUG C-1: _bucket_for_key() ignores the evidence/quarantine "
    "distinction and always returns the quarantine bucket. After promotion the "
    "object lives ONLY in the evidence bucket, so parsing's stream_object() on "
    "the evidence key fails with 'Object not found' in production.",
    strict=True,
)
def test_evidence_key_must_resolve_to_evidence_bucket() -> None:
    """After promotion, reads must target the WORM evidence bucket, not quarantine."""
    storage = _make_storage("kronos", "kronos")
    ev = _evidence("acme")
    # promote_to_evidence_bucket / LocalEvidenceStorage produce identical key
    # layouts for both buckets, so the key alone is ambiguous.
    evidence_key = f"{ev.metadata.org_alias}/{ev.metadata.case_id}/{ev.evidence_id}/security.evtx"
    assert storage._bucket_for_key(evidence_key) == storage._evidence_bucket("acme")


# ---------------------------------------------------------------------------
# C-2: The bucket names the application computes do not match the bucket names
#      created by scripts/provision_buckets.sh, so a freshly provisioned
#      deployment cannot find its buckets.
#
#      provision_buckets.sh creates:   kronos-<org>-quarantine
#                                       kronos-<org>-evidence
#      S3EvidenceStorage computes:     <q_prefix>-<org>-quarantine
#                                       <e_prefix>-<org>            (no -evidence suffix!)
#
#      With the documented default config prefix "kronos-evidence" the app looks
#      for "kronos-evidence-<org>-quarantine" / "kronos-evidence-<org>" — neither
#      of which exists.  No single prefix value can make both names line up,
#      because the evidence bucket helper omits the "-evidence" suffix entirely.
# ---------------------------------------------------------------------------

_PROVISIONED_QUARANTINE = "kronos-acme-quarantine"
_PROVISIONED_EVIDENCE = "kronos-acme-evidence"


@pytest.mark.xfail(
    reason="BUG C-2: default config prefix 'kronos-evidence' yields bucket names "
    "that do not match scripts/provision_buckets.sh.",
    strict=True,
)
def test_default_config_prefix_matches_provisioned_buckets() -> None:
    # config.py default: minio_quarantine_bucket_prefix == minio_evidence_bucket_prefix
    #                    == "kronos-evidence"
    storage = _make_storage("kronos-evidence", "kronos-evidence")
    assert storage._quarantine_bucket("acme") == _PROVISIONED_QUARANTINE
    assert storage._evidence_bucket("acme") == _PROVISIONED_EVIDENCE


@pytest.mark.xfail(
    reason="BUG C-2: even with prefix 'kronos' the evidence-bucket helper omits "
    "the '-evidence' suffix, so it cannot match the provisioned bucket name.",
    strict=True,
)
def test_no_prefix_value_can_align_both_bucket_names() -> None:
    storage = _make_storage("kronos", "kronos")
    # Quarantine lines up with prefix "kronos"...
    assert storage._quarantine_bucket("acme") == _PROVISIONED_QUARANTINE
    # ...but the evidence bucket is "kronos-acme", never "kronos-acme-evidence".
    assert storage._evidence_bucket("acme") == _PROVISIONED_EVIDENCE
