"""Hash service: SHA-256 + MD5 computation over streaming byte sources."""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from dataclasses import dataclass


@dataclass(frozen=True)
class HashResult:
    """SHA-256 and MD5 digests of a byte sequence."""

    sha256: str
    md5: str


class HashService:
    """Compute cryptographic hashes over async byte streams or in-memory bytes.

    Both SHA-256 (forensic fingerprint) and MD5 (legacy compatibility) are
    computed in a single pass to avoid re-reading large files.
    """

    async def compute_from_stream(self, stream: AsyncIterator[bytes]) -> HashResult:
        """Consume the byte stream and return both digests."""
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()  # noqa: S324 — MD5 kept for chain-of-custody legacy compat
        async for chunk in stream:
            sha256.update(chunk)
            md5.update(chunk)
        return HashResult(sha256=sha256.hexdigest(), md5=md5.hexdigest())

    async def compute_from_bytes(self, data: bytes) -> HashResult:
        """Compute both digests from an in-memory byte buffer."""
        sha256 = hashlib.sha256(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()  # noqa: S324
        return HashResult(sha256=sha256, md5=md5)
