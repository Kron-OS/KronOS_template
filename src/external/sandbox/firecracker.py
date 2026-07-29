"""Firecracker microVM launcher for heavy forensic parsers (Plaso).

In production this would call the Firecracker API to spin up a microVM,
copy the evidence file in via vsock, and receive JSONL records back.

In the current implementation we spawn the Plaso worker as a subprocess,
which is sandboxed at the container level (Chainguard/Wolfi + Seccomp).
The interface is intentionally identical to the full Firecracker path so
switching is a one-line change to the process launch command.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.domain.timeline import KronosProvenance, TimelineRecord

logger = logging.getLogger(__name__)

_PLASO_WORKER_PATH = (
    Path(__file__).parent.parent.parent.parent / "docker" / "plaso" / "kronos-plaso-worker.py"
)

# dfVFS path-spec type-indicator prefixes psort's display_name carries ahead
# of the real in-image path (e.g. "FAT:\C\Windows\..."). "OS:" (a raw local
# file, not a real filesystem inside an image) is deliberately excluded --
# see _plaso_source_path's docstring for why that distinction is load-bearing.
_DFVFS_TYPE_PREFIXES = ("FAT:", "NTFS:", "EXT:", "HFS:", "APFS:", "TSK:", "EWF:")


def _plaso_source_path(raw: dict[str, Any]) -> str | None:
    """Return the real in-image path Plaso recorded for this event, or None.

    ``display_name`` is always prefixed with the dfVFS path-spec type
    indicator. For a *single-file* parse (a bare registry hive/prefetch/
    SQLite file uploaded directly) that prefix is always "OS:" and the path
    itself is our own ephemeral local temp file (e.g. "OS:/tmp/tmpXXXX.pf")
    -- confirmed against a real run (poc/full_ingestion_test/documents.json).
    That is not a meaningful evidence path and must NOT be surfaced.

    For a *multi-file image* parse (E01/raw/etc, see PlasoParser's EWF
    routing) the prefix is a real filesystem type (FAT/NTFS/EXT/...) and the
    path is the genuine in-image location -- verified against a real E01
    image (tests/fixtures/samples/real/kape/): 414/414 real events
    correctly attributed, including directory ``fs:stat`` entries whose
    ``pathspec`` field is null even though ``display_name`` still carries a
    real "FAT:" path (an earlier, less robust version of this check keyed
    on ``pathspec`` nesting and missed exactly those 18 records).
    """
    display_name = raw.get("display_name")
    if not isinstance(display_name, str):
        return None
    matched_prefix = next((p for p in _DFVFS_TYPE_PREFIXES if display_name.startswith(p)), None)
    if matched_prefix is None:
        return None  # "OS:" (local temp file) or an unrecognized type indicator

    raw_path = raw.get("filename") or display_name[len(matched_prefix) :]
    if not isinstance(raw_path, str):
        return None
    return raw_path.replace("\\", "/").lstrip("/")


class FirecrackerLauncher:
    """Run a Plaso parse job and stream TimelineRecord objects.

    Spawns the Plaso worker subprocess, feeds it the evidence file path via
    stdin/environment, and reads JSONL output from stdout.
    """

    def __init__(
        self,
        worker_path: Path | None = None,
        python_bin: str = sys.executable,
        timeout_seconds: int = 600,
    ) -> None:
        self._worker_path = worker_path or _PLASO_WORKER_PATH
        self._python_bin = python_bin
        self._timeout = timeout_seconds

    async def run(
        self,
        evidence_path: str,
        evidence_id: str,
        case_id: str,
        org_id: str,
        org_alias: str,
        sha256: str,
        parser_name: str = "plaso",
        parser_version: str = "20260512",
    ) -> AsyncIterator[TimelineRecord]:
        """Yield TimelineRecord objects from Plaso parsing of evidence_path."""
        cmd = [
            self._python_bin,
            str(self._worker_path),
            "--evidence-path",
            evidence_path,
            "--evidence-id",
            evidence_id,
            "--case-id",
            case_id,
            "--org-id",
            org_id,
            "--org-alias",
            org_alias,
            "--sha256",
            sha256,
        ]

        logger.info(
            "firecracker_launch",
            extra={"evidence_id": evidence_id, "worker": str(self._worker_path)},
        )

        try:
            proc = subprocess.Popen(  # noqa: S603
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        except FileNotFoundError as exc:
            logger.error("firecracker_worker_not_found", extra={"path": str(self._worker_path)})
            raise RuntimeError(f"Plaso worker not found: {self._worker_path}") from exc

        return self._stream_records(
            proc,
            evidence_id=evidence_id,
            case_id=case_id,
            org_id=org_id,
            org_alias=org_alias,
            sha256=sha256,
            parser_name=parser_name,
            parser_version=parser_version,
        )

    async def _stream_records(
        self,
        proc: subprocess.Popen[str],
        *,
        evidence_id: str,
        case_id: str,
        org_id: str,
        org_alias: str,
        sha256: str,
        parser_name: str,
        parser_version: str,
    ) -> AsyncIterator[TimelineRecord]:
        """Read JSONL from subprocess stdout and yield TimelineRecord objects."""
        import uuid as _uuid

        if proc.stdout is None:
            raise RuntimeError("Plaso worker subprocess stdout pipe is not available")
        record_index = 0
        ingest_ts = datetime.now(UTC)

        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                raw: dict[str, Any] = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("plaso_invalid_jsonl", extra={"line": line[:200]})
                continue

            try:
                ts_raw = raw.get("datetime") or raw.get("@timestamp") or raw.get("timestamp")
                if isinstance(ts_raw, str):
                    try:
                        ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                    except ValueError:
                        ts = ingest_ts
                elif isinstance(ts_raw, int | float):
                    # psort's json_line "timestamp" field (and the worker's
                    # own normalized "datetime" when it fell back to that
                    # key) is Plaso's internal epoch representation:
                    # microseconds since 1970-01-01, regardless of the
                    # original DateTimeValues subclass (Filetime, PosixTime,
                    # etc — psort itself resolves those to this one int
                    # convention). Verified against a real log2timeline +
                    # psort run on a Windows Prefetch sample
                    # (poc/plaso/README.md): every event carried this as a
                    # plain int, and treating it as "not a str" and silently
                    # replacing it with wall-clock ingest time discarded the
                    # actual forensic timestamp on every single record.
                    try:
                        ts = datetime.fromtimestamp(ts_raw / 1_000_000, tz=UTC)
                    except (ValueError, OverflowError, OSError):
                        ts = ingest_ts
                else:
                    ts = ingest_ts

                source_path = _plaso_source_path(raw)
                record = TimelineRecord(
                    **{"@timestamp": ts},
                    message=raw.get("message") or raw.get("description"),
                    event_original=raw.get("message") or raw.get("description"),
                    extra={
                        k: v
                        for k, v in raw.items()
                        if k
                        not in {"datetime", "@timestamp", "timestamp", "message", "description"}
                    },
                    kronos=KronosProvenance(
                        evidence_id=_uuid.UUID(evidence_id),
                        case_id=_uuid.UUID(case_id),
                        org_id=_uuid.UUID(org_id),
                        org_alias=org_alias,
                        sha256=sha256,
                        parser=parser_name,
                        parser_version=parser_version,
                        record_index=record_index,
                        ingest_timestamp=ingest_ts,
                        source_path=source_path,
                        # The Plaso-parsed evidence file itself is the
                        # "container" for whole-image sources (E01/raw/etc)
                        # -- same semantics as ZipArchiveParser's
                        # container_sha256, just one level instead of N.
                        container_sha256=sha256 if source_path else None,
                    ),
                )
                yield record
                record_index += 1

            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "plaso_record_parse_error",
                    extra={"error": str(exc), "line": line[:200]},
                )

        proc.wait()
        stderr = proc.stderr.read() if proc.stderr else ""
        if proc.returncode not in (0, None):
            logger.error(
                "firecracker_worker_failed",
                extra={"returncode": proc.returncode, "stderr": stderr[:500]},
            )
            raise RuntimeError(f"Plaso worker exited with code {proc.returncode}: {stderr[:200]}")

        if stderr.strip():
            # kronos-plaso-worker.py always exits 0 — even when it falls back
            # to the plaso:placeholder stub (Plaso not installed, or
            # log2timeline genuinely extracted nothing) — and logs *why* to
            # its own stderr. Previously that stderr was only ever read on a
            # non-zero exit, so every stub-fallback run left zero trace of
            # its cause: the placeholder events in OpenSearch were
            # unexplainable from server-side logs alone (Track B1).
            logger.info(
                "firecracker_worker_stderr",
                extra={"evidence_id": evidence_id, "stderr": stderr[:2000]},
            )

        logger.info(
            "firecracker_stream_complete",
            extra={"evidence_id": evidence_id, "records": record_index},
        )
