#!/usr/bin/env python3
"""KronOS Plaso worker: parse an evidence file and emit JSONL records to stdout.

Invoked by FirecrackerLauncher; communicates via stdout (JSONL) and stderr (logs).
The launcher feeds evidence_path + metadata via CLI args.

Usage:
    python kronos-plaso-worker.py \
        --evidence-path /mnt/evidence/sample.db \
        --evidence-id <uuid> \
        --case-id <uuid> \
        --org-id <uuid> \
        --org-alias myorg \
        --sha256 <hex>
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime

logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("kronos-plaso-worker")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="KronOS Plaso evidence parser")
    p.add_argument("--evidence-path", required=True)
    p.add_argument("--evidence-id", required=True)
    p.add_argument("--case-id", required=True)
    p.add_argument("--org-id", required=True)
    p.add_argument("--org-alias", required=True)
    p.add_argument("--sha256", required=True)
    return p.parse_args()


def _emit(record: dict) -> None:
    """Write one JSONL record to stdout."""
    print(json.dumps(record, default=str), flush=True)


# Wall-clock caps (seconds) for the two Plaso stages. The heavy Celery task
# that launches this worker has its own soft/hard time_limit (540/600s); keep
# these below that so a hung Plaso stage is reported as a clean worker failure
# rather than the whole task being SIGKILLed with no diagnostics.
_L2T_TIMEOUT = 480
_PSORT_TIMEOUT = 300


def _find_tool(name: str) -> str | None:
    """Locate a Plaso CLI entry point (installed as a console script by pip)."""
    return shutil.which(name)


def _run_plaso(evidence_path: str) -> list[dict]:
    """Extract events with Plaso and return them as dicts (one per event).

    Uses Plaso's *stable public CLI* (log2timeline.py then psort.py), not its
    internal Python classes. The internal API is unversioned and changes
    between releases; the CLI + the json_line output module are the supported,
    documented contract, and psort applies the event formatters so each record
    carries a real human-readable ``message`` (raw storage EventObjects do
    not). Returns [] on any failure so the caller emits the honest placeholder.

    Pipeline:
      log2timeline.py  <source>            -> <storage>.plaso   (extraction)
      psort.py -o json_line -w <out.jsonl> <storage>.plaso      (formatting)
    """
    l2t = _find_tool("log2timeline.py")
    psort = _find_tool("psort.py")
    if not l2t or not psort:
        logger.error(
            "Plaso CLI tools not found on PATH (log2timeline.py=%s psort.py=%s); "
            "emitting placeholder",
            l2t,
            psort,
        )
        return []

    # mkstemp (not mktemp): the path is created atomically, so nothing can race
    # to occupy it between name generation and first use (EVID-11).
    storage_fd, storage_path = tempfile.mkstemp(suffix=".plaso")
    os.close(storage_fd)
    json_fd, json_path = tempfile.mkstemp(suffix=".jsonl")
    os.close(json_fd)
    try:
        # log2timeline overwrites the (empty) storage file it was handed.
        _run_subprocess(
            [
                l2t,
                "--quiet",
                "--status_view",
                "none",
                "--storage-file",
                storage_path,
                evidence_path,
            ],
            "log2timeline",
            _L2T_TIMEOUT,
        )
        _run_subprocess(
            [psort, "--quiet", "-o", "json_line", "-w", json_path, storage_path],
            "psort",
            _PSORT_TIMEOUT,
        )
        return _read_json_lines(json_path)
    except (subprocess.SubprocessError, OSError) as exc:
        logger.error("Plaso extraction failed (%s); emitting placeholder", exc)
        return []
    finally:
        for path in (storage_path, json_path):
            try:
                os.unlink(path)
            except OSError:
                pass


def _run_subprocess(argv: list, stage: str, timeout: int) -> None:
    """Run a Plaso stage, raising on non-zero exit or timeout (no shell)."""
    logger.info("Running %s: %s", stage, " ".join(argv))
    completed = subprocess.run(  # noqa: S603  # argv list, shell=False
        argv,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=timeout,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        raise subprocess.SubprocessError(
            f"{stage} exited {completed.returncode}: {(completed.stderr or '')[:500]}"
        )


def _read_json_lines(path: str) -> list[dict]:
    """Read psort's json_line output; skip any unparseable line defensively."""
    events: list[dict] = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip().rstrip(",")  # json_line may emit trailing commas
            if not line or line in ("[", "]", "{", "}"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                events.append(_normalize_event(obj))
    return events


def _normalize_event(obj: dict) -> dict:
    """Map a psort json_line event onto the worker's stable output contract.

    FirecrackerLauncher keys on ``datetime``/``@timestamp``/``timestamp`` for
    the event time and ``message``/``description`` for the message; everything
    else is preserved as ECS ``extra``. psort's field naming has shifted across
    Plaso releases, so derive those two keys from whatever this version emitted
    and pass the rest through untouched.
    """
    if "datetime" not in obj:
        for key in ("timestamp", "date_time", "@timestamp"):
            if obj.get(key):
                obj["datetime"] = obj[key]
                break
    if "message" not in obj:
        for key in ("message_short", "display_name", "data_type"):
            if obj.get(key):
                obj["message"] = obj[key]
                break
    return obj


def main() -> None:
    args = _parse_args()
    logger.info("Starting Plaso parse: %s", args.evidence_path)

    events = _run_plaso(args.evidence_path)
    if not events:
        # Honest placeholder: extraction produced nothing (Plaso unavailable,
        # unsupported artifact, or genuinely empty). The launcher surfaces this
        # worker's stderr on every run, so the specific reason is already in the
        # celery-worker-plaso logs.
        logger.warning("No events from Plaso; emitting placeholder")
        _emit(
            {
                "@timestamp": datetime.now(UTC).isoformat(),
                "message": f"Plaso: no events extracted from {args.evidence_path}",
                "data_type": "plaso:placeholder",
                "evidence_id": args.evidence_id,
            }
        )
        sys.exit(0)

    for ev in events:
        _emit(ev)

    logger.info("Plaso parse complete: %d events", len(events))
    sys.exit(0)


if __name__ == "__main__":
    main()
