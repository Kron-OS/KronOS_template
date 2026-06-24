"""In-process local filesystem storage — for unit tests only."""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

from src.adapter.storage.storage import EvidenceStorage, PresignedUploadResponse
from src.domain.evidence import Evidence
from src.exceptions import StorageError


class LocalEvidenceStorage(EvidenceStorage):
    """Stores evidence files on the local filesystem.

    Never use in production.  Provides a deterministic, zero-dependency
    implementation for unit tests that exercise the full intake workflow.
    """

    CHUNK_SIZE = 65536

    def __init__(self, base_dir: Path | None = None) -> None:
        self._base = base_dir or Path("/tmp/kronos-local-storage")  # noqa: S108
        self._base.mkdir(parents=True, exist_ok=True)
        self._quarantine: dict[str, Path] = {}
        self._evidence: dict[str, Path] = {}

    # ------------------------------------------------------------------
    # EvidenceStorage interface
    # ------------------------------------------------------------------

    async def request_presigned_upload(
        self, evidence: Evidence, expires_in_seconds: int = 3600
    ) -> PresignedUploadResponse:
        key = self._quarantine_key(evidence)
        path = self._base / "quarantine" / key
        path.parent.mkdir(parents=True, exist_ok=True)
        self._quarantine[key] = path
        # "URL" is the local path — callers in tests write directly to it.
        return PresignedUploadResponse(
            url=f"file://{path}",
            object_key=key,
            expires_in_seconds=expires_in_seconds,
        )

    async def stream_object(self, object_key: str, chunk_size: int = 65536) -> AsyncIterator[bytes]:
        path = self._quarantine.get(object_key) or self._evidence.get(object_key)
        if path is None or not path.exists():
            raise StorageError(
                f"Object not found: {object_key}",
                context={"object_key": object_key},
            )
        return self._file_stream(path, chunk_size)

    async def promote_to_evidence_bucket(self, quarantine_key: str, evidence: Evidence) -> str:
        src = self._quarantine.get(quarantine_key)
        if src is None or not src.exists():
            raise StorageError(
                f"Quarantine object not found: {quarantine_key}",
                context={"quarantine_key": quarantine_key},
            )
        ev_key = self._evidence_key(evidence)
        dst = self._base / "evidence" / ev_key
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())
        self._evidence[ev_key] = dst
        return ev_key

    async def delete_from_quarantine(self, quarantine_key: str) -> None:
        path = self._quarantine.pop(quarantine_key, None)
        if path and path.exists():
            path.unlink()

    async def object_exists(self, object_key: str) -> bool:
        path = self._quarantine.get(object_key) or self._evidence.get(object_key)
        return path is not None and path.exists()

    # ------------------------------------------------------------------
    # Test helpers
    # ------------------------------------------------------------------

    def write_quarantine(self, object_key: str, data: bytes) -> None:
        """Write bytes directly to a quarantine key (used by tests)."""
        path = self._base / "quarantine" / object_key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        self._quarantine[object_key] = path

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    @staticmethod
    def _quarantine_key(evidence: Evidence) -> str:
        return f"{evidence.metadata.org_alias}/{evidence.metadata.case_id}/{evidence.evidence_id}"

    @staticmethod
    def _evidence_key(evidence: Evidence) -> str:
        return f"{evidence.metadata.org_alias}/{evidence.metadata.case_id}/{evidence.evidence_id}"

    @staticmethod
    async def _file_stream(path: Path, chunk_size: int) -> AsyncIterator[bytes]:  # type: ignore[misc]
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                yield chunk
