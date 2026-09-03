"""Abstract storage interface for derived (non-evidentiary) artifact bytes.

See ``src/adapter/storage/storage.py`` (EvidenceStorage) for the WORM
evidence-bucket contract this deliberately does NOT share.
``poc/minio_derived_artifact/`` real-verified that a bucket created without
``ObjectLockEnabledForBucket`` is genuinely non-WORM (delete/regenerate
works) -- derived bytes (e.g. a ``windows.dumpfiles``-extracted file) are
regenerable from the source evidence at any time, so they get no Object
Lock protection and their own, separate bucket namespace
(``kronos-derived-{org_alias}``, never the evidence/quarantine buckets).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator


class DerivedArtifactStorage(ABC):
    """Abstract non-WORM object storage for derived artifact bytes."""

    @abstractmethod
    async def put_object(
        self,
        org_alias: str,
        object_key: str,
        data: bytes,
        *,
        content_type: str = "application/octet-stream",
    ) -> None:
        """Upload *data* to *object_key*, creating the org's derived bucket if needed."""

    @abstractmethod
    async def stream_object(self, object_key: str, chunk_size: int = 65536) -> AsyncIterator[bytes]:
        """Yield *object_key*'s contents as a stream of byte chunks."""

    @abstractmethod
    def bucket_for(self, object_key: str) -> str:
        """Return the fully-qualified bucket name that *object_key* lives in."""
