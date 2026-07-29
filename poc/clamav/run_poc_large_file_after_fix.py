"""PoC: confirms the fix for the real, reported bug in
run_poc_large_file_before_fix.py -- a real 239 MB E01 upload used to land on
ERROR/intake_failed:BrokenPipeError deterministically, because KronOS's own
upload limit (1 GB) exceeded clamd's real, compiled-in StreamMaxLength/
MaxFileSize default (100 MB, confirmed via `docker exec docker-clamav-1
clamconf`).

The fix: both limits are now reconciled at 5 GiB (5_368_709_120 bytes) and
made configurable via one shared env var:
  - src/config.py Settings.max_upload_bytes default -> 5 GiB
  - docker-compose.dev.yml: MAX_UPLOAD_BYTES on kronos-backend/celery-worker,
    CLAMD_CONF_StreamMaxLength/MaxFileSize/MaxScanSize on the clamav service
    -- all driven by ${KRONOS_MAX_UPLOAD_BYTES:-5368709120}
  - ClamAVScanner.scan_stream (src/application/scanning.py) now also catches
    BrokenPipeError/ConnectionResetError during the write loop and raises a
    clear StorageError instead of letting a raw exception propagate, as
    defense-in-depth if the two limits ever drift apart again.

This script re-runs the exact same 239 MB stream against the real,
reconfigured docker-clamav-1 container (confirmed via `clamconf` immediately
before running that its StreamMaxLength/MaxFileSize/MaxScanSize are now
5368709120) and confirms it now scans clean, deterministically.

Run: source ~/venv/bin/activate && python poc/clamav/run_poc_large_file_after_fix.py
Requires: the rebuilt docker-clamav-1 (docker-compose.dev.yml with the
CLAMD_CONF_* env vars) running, port 3310 published to the host.
"""
from __future__ import annotations

import asyncio
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.application.scanning import ClamAVScanner  # noqa: E402

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


async def clean_stream(total_bytes: int, chunk_size: int = 1024 * 1024):
    remaining = total_bytes
    pattern = b"KRONOS-POC-LARGE-FILE-SCAN-TEST-" * 1024
    while remaining > 0:
        n = min(chunk_size, remaining)
        yield (pattern * (n // len(pattern) + 1))[:n]
        remaining -= n


async def main() -> None:
    # ---------------------------------------------------------------------
    # 0. Confirm the real running container's config actually changed --
    #    don't just assume docker-compose.dev.yml's env vars took effect.
    # ---------------------------------------------------------------------
    print("=== 0. Confirm real clamd config reflects the new 5 GiB limits ===")
    conf = subprocess.run(
        ["docker", "exec", "docker-clamav-1", "clamconf"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    stream_max_ok = 'StreamMaxLength = "5368709120"' in conf
    max_file_ok = 'MaxFileSize = "5368709120"' in conf
    max_scan_ok = 'MaxScanSize = "5368709120"' in conf
    check("StreamMaxLength = 5368709120 (5 GiB)", stream_max_ok, conf.count("StreamMaxLength"))
    check("MaxFileSize = 5368709120 (5 GiB)", max_file_ok)
    check("MaxScanSize = 5368709120 (5 GiB)", max_scan_ok)

    scanner = ClamAVScanner(host="localhost", port=3310)

    # ---------------------------------------------------------------------
    # 1. The EXACT scenario that used to fail: a 239 MB stream (same size
    #    class as the reported forensic2.E01, and well over the OLD 100 MB
    #    limit that caused the bug) -- must now scan clean, not raise.
    # ---------------------------------------------------------------------
    print("\n=== 1. The exact previously-failing scenario: 239 MB stream ===")
    try:
        result = await scanner.scan_stream(clean_stream(239 * 1024 * 1024))
        check(
            "239 MB stream now scans clean (previously raised BrokenPipeError)",
            result.is_clean,
            str(result),
        )
    except Exception as exc:  # noqa: BLE001
        check(
            "239 MB stream now scans clean (previously raised BrokenPipeError)",
            False,
            f"{type(exc).__name__}: {exc}",
        )

    # ---------------------------------------------------------------------
    # 2. Confirm this is deterministic (matches the user's own experience of
    #    a repeatable, non-transient failure) -- a second identical attempt
    #    also succeeds cleanly.
    # ---------------------------------------------------------------------
    print("\n=== 2. Confirm determinism: a second identical attempt also succeeds ===")
    try:
        result = await scanner.scan_stream(clean_stream(239 * 1024 * 1024))
        check("second 239 MB attempt also scans clean", result.is_clean, str(result))
    except Exception as exc:  # noqa: BLE001
        check("second 239 MB attempt also scans clean", False, f"{type(exc).__name__}: {exc}")

    # ---------------------------------------------------------------------
    # 3. A stream close to the new 5 GiB ceiling would still be impractical
    #    to actually generate/stream in a PoC run in reasonable time, so
    #    this confirms the next order of magnitude up (1.5 GB, safely past
    #    KronOS's OLD 1 GB cap and the old clamd 100 MB cap, still well
    #    under the new 5 GiB cap) also scans clean -- covers the realistic
    #    range of large forensic images this fix exists for.
    # ---------------------------------------------------------------------
    print("\n=== 3. A 1.5 GB stream (realistic large forensic image size) ===")
    try:
        result = await scanner.scan_stream(clean_stream(int(1.5 * 1024 * 1024 * 1024)))
        check("1.5 GB stream scans clean", result.is_clean, str(result))
    except Exception as exc:  # noqa: BLE001
        check("1.5 GB stream scans clean", False, f"{type(exc).__name__}: {exc}")

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILURES:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
