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
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.domain.timeline import KronosProvenance, TimelineRecord

logger = logging.getLogger(__name__)

_PLASO_WORKER_PATH = (
    Path(__file__).parent.parent.parent.parent / "docker" / "plaso" / "kronos-plaso-worker.py"
)


class FirecrackerLauncher:
    """Run a Plaso parse job and stream TimelineRecord objects.

    Spawns the Plaso worker subprocess, feeds it the evidence file path via
    stdin/environment, and reads JSONL output from stdout.
    """

    def __init__(
        self,
        worker_path: Path | None = None,
        python_bin: str = "python3",
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
        parser_version: str = "20240101",
    ) -> AsyncIterator[TimelineRecord]:
        """Yield TimelineRecord objects from Plaso parsing of evidence_path."""
        cmd = [
            self._python_bin,
            str(self._worker_path),
            "--evidence-path", evidence_path,
            "--evidence-id", evidence_id,
            "--case-id", case_id,
            "--org-id", org_id,
            "--org-alias", org_alias,
            "--sha256", sha256,
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

        assert proc.stdout is not None
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
                else:
                    ts = ingest_ts

                record = TimelineRecord(
                    **{"@timestamp": ts},
                    message=raw.get("message") or raw.get("description"),
                    event_original=raw.get("message") or raw.get("description"),
                    extra={k: v for k, v in raw.items() if k not in {"datetime", "@timestamp", "timestamp", "message", "description"}},
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
                    ),
                )
                yield record
                record_index += 1

            except Exception as exc:  # noqa: BLE001
                logger.warning("plaso_record_parse_error", extra={"error": str(exc), "line": line[:200]})

        proc.wait()
        if proc.returncode not in (0, None):
            stderr = proc.stderr.read() if proc.stderr else ""
            logger.error(
                "firecracker_worker_failed",
                extra={"returncode": proc.returncode, "stderr": stderr[:500]},
            )
            raise RuntimeError(f"Plaso worker exited with code {proc.returncode}: {stderr[:200]}")

        logger.info("firecracker_stream_complete", extra={"evidence_id": evidence_id, "records": record_index})
