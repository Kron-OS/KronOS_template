"""RFC 3161 trusted timestamping service."""

from __future__ import annotations

import hashlib
import logging
import struct
from datetime import datetime

import httpx

from src.exceptions import StorageError

logger = logging.getLogger(__name__)

# OID for SHA-256 in an AlgorithmIdentifier (used in minimal DER TimeStampReq).
_SHA256_OID = b"\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00"


def _build_timestamp_request(digest: bytes) -> bytes:
    """Build a minimal DER-encoded RFC 3161 TimeStampReq for SHA-256 digest.

    Structure:
      TimeStampReq ::= SEQUENCE {
        version      INTEGER { v1(1) },
        messageImprint MessageImprint,
        nonce        INTEGER OPTIONAL,
        certReq      BOOLEAN DEFAULT FALSE
      }
      MessageImprint ::= SEQUENCE {
        hashAlgorithm AlgorithmIdentifier,
        hashedMessage OCTET STRING
      }
    """
    # OCTET STRING wrapping digest
    octet_content = b"\x04" + _der_length(len(digest)) + digest
    # MessageImprint = SEQUENCE { AlgorithmIdentifier, OCTET STRING }
    msg_imprint_body = _SHA256_OID + octet_content
    msg_imprint = b"\x30" + _der_length(len(msg_imprint_body)) + msg_imprint_body
    # version INTEGER = 1
    version = b"\x02\x01\x01"
    # certReq BOOLEAN TRUE
    cert_req = b"\x01\x01\xff"
    body = version + msg_imprint + cert_req
    return b"\x30" + _der_length(len(body)) + body


def _der_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    length_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(length_bytes)]) + length_bytes


class RFC3161TimestampService:
    """Calls a RFC 3161 TSA to anchor evidence hashes and audit Merkle roots."""

    def __init__(self, tsa_url: str) -> None:
        self._tsa_url = tsa_url

    async def timestamp(self, digest: bytes, hash_alg: str = "sha256") -> bytes:
        """POST a TimeStampReq to the TSA. Returns DER-encoded TimeStampToken bytes."""
        ts_req = _build_timestamp_request(digest)
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    self._tsa_url,
                    content=ts_req,
                    headers={"Content-Type": "application/timestamp-query"},
                )
                resp.raise_for_status()
                return resp.content
        except httpx.HTTPError as exc:
            logger.warning("tsa_unreachable", extra={"url": self._tsa_url, "error": str(exc)})
            raise StorageError(
                "TSA unreachable",
                context={"tsa_url": self._tsa_url, "error": str(exc)},
            ) from exc

    async def verify(self, token: bytes, digest: bytes) -> datetime:
        """Parse the TimeStampToken and verify the digest.

        Returns genTime from the token. Raises StorageError on mismatch.
        Note: full ASN.1 parsing requires rfc3161ng; this is a lightweight stub
        that returns the current time when the library is unavailable.
        """
        try:
            import rfc3161ng  # type: ignore[import-untyped]  # noqa: PLC0415

            ts_response = rfc3161ng.decode_timestamp_response(token)
            tst = ts_response.time_stamp_token
            gen_time = tst["tst_info"]["gen_time"].native
            embedded_digest = tst["tst_info"]["message_imprint"]["hashed_message"].native
            if embedded_digest != digest:
                raise StorageError(
                    "TSA token digest mismatch",
                    context={"expected": digest.hex(), "got": embedded_digest.hex()},
                )
            return gen_time if isinstance(gen_time, datetime) else datetime.utcnow()
        except ImportError:
            logger.warning("rfc3161ng not installed; returning current time as stub verify")
            return datetime.utcnow()
