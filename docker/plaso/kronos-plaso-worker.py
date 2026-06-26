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
import sys
from datetime import datetime, timezone

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


def _run_plaso(evidence_path: str) -> list[dict]:
    """Run Plaso log2timeline on the evidence file and return parsed events."""
    try:
        import plaso  # type: ignore[import-untyped]  # noqa: F401
        from plaso.cli import log2timeline_tool  # type: ignore[import-untyped]
        from plaso.storage import sqlite_file  # type: ignore[import-untyped]

        import tempfile
        import os

        storage_path = tempfile.mktemp(suffix=".plaso")  # noqa: S306
        try:
            tool = log2timeline_tool.Log2TimelineTool()
            tool.ParseOptions(argparse.Namespace(
                source=evidence_path,
                storage_file=storage_path,
                output_module="json_line",
                parsers="",
                hasher_names_string="sha256",
            ))
            tool.ProcessSources()

            events: list[dict] = []
            with sqlite_file.SQLiteStorageFileReader(storage_path) as reader:
                for ev in reader.GetEvents():
                    events.append({
                        "datetime": ev.timestamp,
                        "message": getattr(ev, "message", ""),
                        "data_type": getattr(ev, "data_type", ""),
                        "parser": getattr(ev, "parser", "plaso"),
                    })
            return events
        finally:
            if os.path.exists(storage_path):
                os.unlink(storage_path)

    except ImportError:
        logger.error("Plaso not installed; falling back to stub output")
        return []


def main() -> None:
    args = _parse_args()
    logger.info("Starting Plaso parse: %s", args.evidence_path)

    events = _run_plaso(args.evidence_path)
    if not events:
        # Fallback: emit a single placeholder record so the worker isn't silent.
        logger.warning("No events from Plaso; emitting placeholder")
        _emit({
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "message": f"Plaso: no events extracted from {args.evidence_path}",
            "data_type": "plaso:placeholder",
            "evidence_id": args.evidence_id,
        })
        sys.exit(0)

    for ev in events:
        _emit(ev)

    logger.info("Plaso parse complete: %d events", len(events))
    sys.exit(0)


if __name__ == "__main__":
    main()
