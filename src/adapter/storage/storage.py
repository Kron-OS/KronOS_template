"""Abstract storage interface for evidence object storage."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import Literal

from src.domain.evidence import Evidence

# Which logical bucket a read targets.  Quarantine and evidence object keys are
# byte-for-byte identical, so the key alone cannot disambiguate them; callers
# must say which bucket they mean.
BucketKind = Literal["quarantine", "evidence"]


class PresignedUploadResponse:
    """Returned by request_presigned_upload; contains the URL and key."""

    __slots__ = ("url", "object_key", "expires_in_seconds")

    def __init__(self, url: str, object_key: str, expires_in_seconds: int) -> None:
        self.url = url
        self.object_key = object_key
        self.expires_in_seconds = expires_in_seconds


class EvidenceStorage(ABC):
    """Abstract evidence object storage.

    Implementations wrap MinIO/S3-compatible APIs; LocalEvidenceStorage
    provides an in-process implementation for unit tests.
    """

    @abstractmethod
    async def request_presigned_upload(
        self,
        evidence: Evidence,
        expires_in_seconds: int = 3600,
    ) -> PresignedUploadResponse:
        """Return a presigned URL for direct client-to-storage upload."""

    @abstractmethod
    async def stream_object(
        self,
        object_key: str,
        chunk_size: int = 65536,
        *,
        bucket: BucketKind = "quarantine",
    ) -> AsyncIterator[bytes]:
        """Yield object contents as a stream of byte chunks from *bucket*."""

    @abstractmethod
    async def promote_to_evidence_bucket(self, quarantine_key: str, evidence: Evidence) -> str:
        """Copy from quarantine to WORM evidence bucket; return the new object key."""

    @abstractmethod
    async def delete_from_quarantine(self, quarantine_key: str) -> None:
        """Remove an object from the quarantine bucket after promotion or rejection."""

    @abstractmethod
    async def object_exists(self, object_key: str, *, bucket: BucketKind = "quarantine") -> bool:
        """Return True if the object key exists in *bucket*."""
