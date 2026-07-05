"""Round-trip RFC 3161 anchor -> verify test (AUDIT-07/AUDIT-08).

Builds a throwaway CA + TSA certificate with `openssl req`/`openssl x509`,
issues a real timestamp response for a digest with `openssl ts -reply`
(exercising the exact code path `RFC3161TimestampService.timestamp()` talks
to over HTTP), then verifies it via `kronos_attest.tsa.verify_merkle_anchor`
— proving the digest-encoding fix (AUDIT-08: no double-hash) against a real
TSA response, not just a mocked one, and that the CLI's `day-report`
`tsa_anchored` field only turns True on a genuinely valid signature
(AUDIT-07).

Skipped automatically if the `openssl ts` subcommand is unavailable.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from kronos_attest.report import AttestationReport
from kronos_attest.tsa import TSAVerifier, verify_merkle_anchor

def _openssl_ts_available() -> bool:
    result = subprocess.run(  # noqa: S603
        ["openssl", "ts", "-help"], capture_output=True, text=True
    )
    return "Usage: ts" in (result.stdout + result.stderr)


pytestmark = pytest.mark.skipif(
    shutil.which("openssl") is None or not _openssl_ts_available(),
    reason="openssl ts subcommand not available",
)


@pytest.fixture(scope="module")
def tsa_fixture(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """Build a throwaway CA + TSA cert/key and return their paths."""
    d = tmp_path_factory.mktemp("tsa")

    ca_key, ca_pem = d / "ca.key", d / "ca.pem"
    tsa_key, tsa_csr, tsa_pem = d / "tsa.key", d / "tsa.csr", d / "tsa.pem"
    ext_cnf = d / "tsa_ext.cnf"
    ext_cnf.write_text("extendedKeyUsage=critical,timeStamping\n")

    def _run(*args: str) -> None:
        result = subprocess.run(args, capture_output=True, text=True)  # noqa: S603
        assert result.returncode == 0, result.stderr

    _run(
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(ca_key), "-out", str(ca_pem),
        "-days", "2", "-nodes", "-subj", "/CN=Test CA",
    )
    _run(
        "openssl", "req", "-newkey", "rsa:2048",
        "-keyout", str(tsa_key), "-out", str(tsa_csr),
        "-nodes", "-subj", "/CN=Test TSA",
    )
    _run(
        "openssl", "x509", "-req", "-in", str(tsa_csr),
        "-CA", str(ca_pem), "-CAkey", str(ca_key), "-CAcreateserial",
        "-out", str(tsa_pem), "-days", "2", "-extfile", str(ext_cnf),
    )

    tsa_cnf = d / "tsa.cnf"
    tsa_cnf.write_text(
        f"""\
[tsa]
default_tsa = tsa_config1

[tsa_config1]
dir = {d}
serial = {d}/tsaserial
crypto_device = builtin
signer_cert = {tsa_pem}
certs = {ca_pem}
signer_key = {tsa_key}
signer_digest = sha256
ess_cert_id_alg = sha256
default_policy = 1.2.3.4.5.6.7.8.1
digests = sha256
accuracy = secs:1
clock_precision_digits = 0
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
"""
    )
    return {"ca_pem": ca_pem, "tsa_cnf": tsa_cnf, "dir": d}


def _issue_timestamp(tsa_fixture: dict[str, Path], digest_hex: str) -> bytes:
    """Issue a real RFC 3161 TimeStampToken over digest_hex via openssl ts -reply."""
    d = tsa_fixture["dir"]
    req_path = d / f"{digest_hex}.tsq"
    resp_path = d / f"{digest_hex}.tsr"

    subprocess.run(  # noqa: S603
        [
            "openssl", "ts", "-query",
            "-digest", digest_hex, "-sha256", "-cert",
            "-out", str(req_path),
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(  # noqa: S603
        [
            "openssl", "ts", "-reply",
            "-config", str(tsa_fixture["tsa_cnf"]),
            "-queryfile", str(req_path),
            "-out", str(resp_path),
        ],
        check=True,
        capture_output=True,
    )
    return resp_path.read_bytes()


def test_verify_digest_succeeds_on_genuine_anchor(tsa_fixture: dict[str, Path]) -> None:
    root_hash = hashlib.sha256(b"merkle-root-of-the-day").hexdigest()
    token_der = _issue_timestamp(tsa_fixture, root_hash)

    assert verify_merkle_anchor(token_der, root_hash, str(tsa_fixture["ca_pem"])) is True


def test_verify_digest_fails_for_wrong_root(tsa_fixture: dict[str, Path]) -> None:
    root_hash = hashlib.sha256(b"merkle-root-of-the-day").hexdigest()
    token_der = _issue_timestamp(tsa_fixture, root_hash)

    wrong_root = hashlib.sha256(b"a-different-root").hexdigest()
    with pytest.raises(RuntimeError):
        verify_merkle_anchor(token_der, wrong_root, str(tsa_fixture["ca_pem"]))


def test_old_double_hash_encoding_would_have_failed(tsa_fixture: dict[str, Path]) -> None:
    """Proves AUDIT-08 was real: the pre-fix `-data sha256(root_hex)` path
    does not match a token anchored over the raw root bytes."""
    root_hash = hashlib.sha256(b"merkle-root-of-the-day").hexdigest()
    token_der = _issue_timestamp(tsa_fixture, root_hash)

    double_hashed_message = hashlib.sha256(root_hash.encode()).digest()
    verifier = TSAVerifier(tsa_cert_path=str(tsa_fixture["ca_pem"]))
    with pytest.raises(RuntimeError, match="message imprint mismatch|TSA verification failed"):
        verifier.verify(token_der, double_hashed_message)


def test_day_report_tsa_anchored_true_for_genuine_token(tsa_fixture: dict[str, Path]) -> None:
    """End-to-end: AttestationReport.day_report() must report tsa_anchored=True
    only when the embedded token genuinely verifies against the CA (AUDIT-07)."""
    root_hash = hashlib.sha256(b"merkle-root-of-the-day").hexdigest()
    token_der = _issue_timestamp(tsa_fixture, root_hash)

    day = "2026-06-25"
    events = [
        {
            "event_id": "anchor-1",
            "event_type": "audit.merkle_anchored",
            "occurred_at": f"{day}T02:00:00+00:00",
            "sequence_number": 1,
            "case_id": None,
            "evidence_id": None,
            "prev_row_hash": "genesis",
            "row_hash": "a" * 64,
            "details": {
                "day": day,
                "root_hash": root_hash,
                "tsa_token": token_der.hex(),
            },
        }
    ]

    report = AttestationReport().day_report(events, day, str(tsa_fixture["ca_pem"]))
    assert report.tsa_anchored is True
    assert report.tsa_gen_time is not None


def test_day_report_tsa_anchored_false_for_tampered_root(tsa_fixture: dict[str, Path]) -> None:
    """A root_hash edited after anchoring must fail verification, not pass."""
    root_hash = hashlib.sha256(b"merkle-root-of-the-day").hexdigest()
    token_der = _issue_timestamp(tsa_fixture, root_hash)
    tampered_root = hashlib.sha256(b"tampered").hexdigest()

    day = "2026-06-25"
    events = [
        {
            "event_id": "anchor-1",
            "event_type": "audit.merkle_anchored",
            "occurred_at": f"{day}T02:00:00+00:00",
            "sequence_number": 1,
            "case_id": None,
            "evidence_id": None,
            "prev_row_hash": "genesis",
            "row_hash": "a" * 64,
            "details": {
                "day": day,
                "root_hash": tampered_root,
                "tsa_token": token_der.hex(),
            },
        }
    ]

    report = AttestationReport().day_report(events, day, str(tsa_fixture["ca_pem"]))
    assert report.tsa_anchored is False
