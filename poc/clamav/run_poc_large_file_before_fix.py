"""PoC: reproduces the real, reported bug -- a real 239 MB E01 upload lands
on ERROR/intake_failed:BrokenPipeError, and every retry fails identically.

Root-cause hypothesis (confirmed against the real running clamd container
BEFORE writing this script, via `docker exec docker-clamav-1 clamconf`):
KronOS's own upload limit is 1 GB (src/config.py Settings.max_upload_bytes),
but the real clamd this repo's dev stack runs (`clamav/clamav:stable`,
version confirmed via `docker exec docker-clamav-1 clamd --version` ->
ClamAV 1.5.3) ships with StreamMaxLength=104857600 (100 MB, the image's
compiled-in default -- not overridden anywhere in docker-compose.dev.yml).
INSTREAM enforces this size limit by closing the TCP connection the moment
the running total exceeds it; ClamAVScanner.scan_stream()
(src/application/scanning.py) has no size check and no handling for an
early-closed connection -- it just keeps writing chunks from the async
generator until the OS raises BrokenPipeError on a write to the now-closed
socket. Any evidence file between 100 MB and KronOS's own 1 GB cap will
hit this on every attempt -- not transient, despite process_intake
classifying "intake_failed:*" as retryable.

This script sends a real >100 MB stream to the real clamd container (same
image/version as docker-compose.dev.yml) via the real ClamAVScanner class,
and captures whatever actually happens -- not assumed.

Run: source ~/venv/bin/activate && python poc/clamav/run_poc_large_file.py
Requires: docker-clamav-1 running (docker-compose.dev.yml), port 3310
published to the host (already the case in this repo's compose file).
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.application.scanning import ClamAVScanner  # noqa: E402
from src.exceptions import StorageError  # noqa: E402

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


async def clean_stream(total_bytes: int, chunk_size: int = 1024 * 1024):
    """Real innocuous bytes, streamed in 1 MiB chunks -- mirrors how
    EvidenceIntakeService._run_scan actually streams from MinIO in
    CHUNK_SIZE-ish pieces, not one giant in-memory blob."""
    remaining = total_bytes
    pattern = b"KRONOS-POC-LARGE-FILE-SCAN-TEST-" * 1024  # 32 KiB repeating block
    while remaining > 0:
        n = min(chunk_size, remaining)
        yield (pattern * (n // len(pattern) + 1))[:n]
        remaining -= n


async def main() -> None:
    scanner = ClamAVScanner(host="localhost", port=3310)

    # -----------------------------------------------------------------
    # 1. Baseline: a real stream well UNDER StreamMaxLength (100 MB) —
    #    confirms the scanner itself works before testing the failure edge.
    # -----------------------------------------------------------------
    print("=== 1. Baseline: 10 MB clean stream (well under the 100 MB limit) ===")
    try:
        result = await scanner.scan_stream(clean_stream(10 * 1024 * 1024))
        check("10 MB stream scans clean with no error", result.is_clean, str(result))
    except Exception as exc:  # noqa: BLE001
        check("10 MB stream scans clean with no error", False, f"{type(exc).__name__}: {exc}")

    # -----------------------------------------------------------------
    # 2. The real reported scenario: a stream bigger than clamd's real,
    #    running StreamMaxLength (confirmed 104857600 bytes via
    #    `docker exec docker-clamav-1 clamconf`) -- same order of
    #    magnitude as the reported 239.3 MB forensic2.E01.
    # -----------------------------------------------------------------
    print("\n=== 2. Real reported scenario: 239 MB stream (exceeds clamd's 100 MB StreamMaxLength) ===")
    exc_type = None
    exc_obj: Exception | None = None
    try:
        await scanner.scan_stream(clean_stream(239 * 1024 * 1024))
        check("raises some exception (did NOT scan cleanly)", False, "no exception raised")
    except Exception as exc:  # noqa: BLE001
        exc_type = type(exc).__name__
        exc_obj = exc
        check(
            "raises an exception when exceeding clamd's real StreamMaxLength",
            True,
            f"{exc_type}: {exc}",
        )

    check(
        "reproduces the EXACT reported error type (BrokenPipeError)",
        exc_type == "BrokenPipeError",
        exc_type,
    )
    check(
        "NOT a StorageError with a clear message -- confirms scan_stream has no "
        "graceful handling of clamd's early close, matching the raw, uncaught "
        "traceback style seen in the reported intake_failed:BrokenPipeError",
        exc_obj is not None and not isinstance(exc_obj, StorageError),
        exc_type,
    )

    # -----------------------------------------------------------------
    # 3. Confirm this is deterministic, not flaky -- a second identical
    #    attempt fails the exact same way (explains why the user's retry
    #    also failed instead of "just working" on attempt 2).
    # -----------------------------------------------------------------
    print("\n=== 3. Confirm determinism: retrying the same size fails identically ===")
    try:
        await scanner.scan_stream(clean_stream(239 * 1024 * 1024))
        check("second attempt also fails (not flaky)", False, "unexpectedly succeeded")
    except Exception as exc:  # noqa: BLE001
        check(
            "second attempt also fails the same way (not flaky, not transient)",
            type(exc).__name__ == exc_type,
            f"{type(exc).__name__}: {exc}",
        )

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILURES:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
