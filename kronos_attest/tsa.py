"""RFC 3161 timestamp token offline verification for kronos-attest.

Verifies TSA tokens attached to daily Merkle anchors without network access.
Uses pyasn1 for DER parsing; falls back to openssl subprocess if unavailable.
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TSATokenInfo:
    """Parsed RFC 3161 timestamp token metadata."""

    gen_time: str          # ISO-8601 generation time
    policy: str            # TSA policy OID
    serial: int            # Token serial number
    hash_algorithm: str    # e.g. "sha256"
    message_imprint: str   # Hex of the hashed message
    tsa_name: str          # TSA issuer name (if present)


class TSAVerifier:
    """Offline verifier for RFC 3161 timestamp tokens.

    Wraps openssl ts -verify; can be used without network access once the
    TSA certificate chain is cached locally.
    """

    def __init__(self, tsa_cert_path: str | None = None) -> None:
        self._tsa_cert_path = tsa_cert_path

    def verify(
        self,
        token_der: bytes,
        message: bytes,
    ) -> bool:
        """Verify that token_der is a valid RFC 3161 token over sha256(message).

        Uses ``openssl ts -verify -data`` — openssl hashes *message* itself
        and compares that to the token's messageImprint.  Use this only when
        you have the original pre-image; when you already hold the digest
        that was anchored (as with a Merkle root — see ``verify_merkle_anchor``),
        use ``verify_digest`` instead so the digest isn't hashed a second time.

        Returns True on success. Raises RuntimeError on verification failure
        or missing openssl.
        """
        with tempfile.NamedTemporaryFile(suffix=".tsr", delete=False) as tf:
            tf.write(token_der)
            token_path = tf.name

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as mf:
            mf.write(message)
            msg_path = mf.name

        try:
            cmd = ["openssl", "ts", "-verify", "-data", msg_path, "-in", token_path]
            if self._tsa_cert_path:
                cmd += ["-CAfile", self._tsa_cert_path]
            result = subprocess.run(cmd, capture_output=True, text=True)  # noqa: S603
            if result.returncode != 0:
                raise RuntimeError(
                    f"TSA verification failed: {result.stderr.strip()}"
                )
            return True
        finally:
            Path(token_path).unlink(missing_ok=True)
            Path(msg_path).unlink(missing_ok=True)

    def verify_digest(self, token_der: bytes, digest_hex: str) -> bool:
        """Verify that token_der's messageImprint equals *digest_hex* exactly.

        Uses ``openssl ts -verify -digest <hex>``, which compares the given
        hex digest directly against the token's messageImprint with no
        additional hashing (AUDIT-08 fix) — matches how
        ``RFC3161TimestampService.timestamp()`` embeds the raw Merkle-root
        bytes as the messageImprint at anchor time, rather than
        ``sha256(digest)`` which ``verify()``'s ``-data`` path would compute.

        Returns True on success. Raises RuntimeError on verification failure
        or missing openssl.
        """
        with tempfile.NamedTemporaryFile(suffix=".tsr", delete=False) as tf:
            tf.write(token_der)
            token_path = tf.name

        try:
            cmd = ["openssl", "ts", "-verify", "-digest", digest_hex, "-in", token_path]
            if self._tsa_cert_path:
                cmd += ["-CAfile", self._tsa_cert_path]
            result = subprocess.run(cmd, capture_output=True, text=True)  # noqa: S603
            if result.returncode != 0:
                raise RuntimeError(f"TSA verification failed: {result.stderr.strip()}")
            return True
        finally:
            Path(token_path).unlink(missing_ok=True)

    def parse_info(self, token_der: bytes) -> TSATokenInfo | None:
        """Parse basic metadata from a DER-encoded TSA response.

        Returns None if pyasn1 is not installed (graceful degradation).
        """
        try:
            from pyasn1.codec.der import decoder as der_decoder  # type: ignore[import]
            from pyasn1_modules import rfc3161  # type: ignore[import]

            tst, _ = der_decoder.decode(token_der, asn1Spec=rfc3161.TimeStampToken())
            tst_info = tst["content"]["encapContentInfo"]["eContent"]
            info, _ = der_decoder.decode(tst_info, asn1Spec=rfc3161.TSTInfo())

            gen_time_raw = info["genTime"]
            serial = int(info["serialNumber"])
            policy = str(info["policy"])
            hash_algo = str(info["messageImprint"]["hashAlgorithm"]["algorithm"])
            message_imprint = bytes(info["messageImprint"]["hashedMessage"]).hex()

            return TSATokenInfo(
                gen_time=str(gen_time_raw),
                policy=policy,
                serial=serial,
                hash_algorithm=hash_algo,
                message_imprint=message_imprint,
                tsa_name="",
            )
        except ImportError:
            return None


def verify_merkle_anchor(
    token_der: bytes,
    merkle_root_hex: str,
    tsa_cert_path: str | None = None,
) -> bool:
    """Verify a TSA token anchors the given Merkle root.

    ``RFC3161TimestampService.timestamp()`` (src/application/timestamping.py)
    embeds ``bytes.fromhex(root_hash)`` directly as the messageImprint — it
    does not hash the root again.  Verification must therefore compare
    against that same raw digest via ``-digest``, not re-hash
    ``merkle_root_hex`` and feed it through ``-data`` (which would make
    openssl hash it a second time — the AUDIT-08 double-hash bug).
    """
    verifier = TSAVerifier(tsa_cert_path=tsa_cert_path)
    return verifier.verify_digest(token_der, merkle_root_hex)
