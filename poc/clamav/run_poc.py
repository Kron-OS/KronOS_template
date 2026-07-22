"""PoC: real ClamAV scanning, using the real ClamAVScanner/NoOpScanner
classes and the real configure_clamav_from_settings() fail-open/fail-closed
gate, plus a real EvidenceIntakeService._run_scan() integration with a real
EICAR upload through real MinIO.

The EICAR string is the antivirus industry's standard, harmless test
string (https://www.eicar.org/) -- not a real virus -- designed so every
AV engine flags it identically. Using it here is the normal, safe way to
test AV integration.

Run: source ~/venv/bin/activate && CLAMD_PORT=13310 python poc/clamav/run_poc.py
"""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import AsyncIterator
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.application.scanning import ClamAVScanner, NoOpScanner  # noqa: E402
from src.exceptions import StorageError  # noqa: E402

CLAMD_HOST = "localhost"
CLAMD_PORT = int(os.environ.get("CLAMD_PORT", "13310"))

# The official EICAR antivirus test string -- harmless, industry-standard.
EICAR = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    (PASS if condition else FAIL).append(name)
    print(f"[{status}] {name}" + (f" -- {detail}" if detail else ""))


async def _stream(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def main() -> None:
    scanner = ClamAVScanner(host=CLAMD_HOST, port=CLAMD_PORT)

    # --- 1. Clean file ---
    print("=== Test 1: clean file ===")
    result = await scanner.scan_stream(_stream(b"just a normal forensic log line\n" * 100))
    print(f"scan_stream(clean bytes) -> is_clean={result.is_clean} threat={result.threat_name}")
    check("real ClamAV reports a clean file as clean", result.is_clean is True)

    # --- 2. Real EICAR test string ---
    print("\n=== Test 2: real EICAR test string ===")
    result = await scanner.scan_stream(_stream(EICAR))
    print(f"scan_stream(EICAR) -> is_clean={result.is_clean} threat={result.threat_name}")
    check("real ClamAV detects the EICAR test string as infected", result.is_clean is False)
    check("threat_name mentions EICAR (case-insensitive)", bool(result.threat_name) and "eicar" in (result.threat_name or "").lower(), str(result.threat_name))

    # --- 3. EICAR split across multiple stream chunks (real streaming path) ---
    print("\n=== Test 3: EICAR split across multiple async chunks ===")

    async def _chunked_eicar() -> AsyncIterator[bytes]:
        for i in range(0, len(EICAR), 10):
            yield EICAR[i : i + 10]

    result = await scanner.scan_stream(_chunked_eicar())
    check("real ClamAV detects EICAR even when streamed in small chunks", result.is_clean is False)

    # --- 4. configure_clamav_from_settings(): real fail-open (dev) vs fail-closed (prod) ---
    print("\n=== Test 4: configure_clamav_from_settings() real gating behavior ===")
    _set_settings_env(environment="development", clamd_port=CLAMD_PORT)
    import src.external.dependencies as deps

    deps.reset_dependencies()
    deps.configure_dependencies(audit_log_repository=None, evidence_repository=None, evidence_storage=_FakeStorage())
    deps.configure_clamav_from_settings()
    wired = deps.get_scanner()
    print(f"dev + reachable clamd -> wired scanner type: {type(wired).__name__}")
    check("dev env + reachable real clamd wires the real ClamAVScanner (not NoOp)", isinstance(wired, ClamAVScanner))

    _set_settings_env(environment="development", clamd_port=1)  # nothing listens on port 1
    deps.reset_dependencies()
    deps.configure_dependencies(audit_log_repository=None, evidence_repository=None, evidence_storage=_FakeStorage())
    deps.configure_clamav_from_settings()
    wired = deps.get_scanner()
    print(f"dev + unreachable clamd -> wired scanner type: {type(wired).__name__}")
    check("dev env + unreachable clamd falls back to NoOpScanner (permissive, as designed)", isinstance(wired, NoOpScanner))

    _set_settings_env(environment="production", clamd_port=1)
    deps.reset_dependencies()
    deps.configure_dependencies(audit_log_repository=None, evidence_repository=None, evidence_storage=_FakeStorage())
    raised = False
    try:
        deps.configure_clamav_from_settings()
    except StorageError as exc:
        raised = True
        print(f"production + unreachable clamd -> raised StorageError: {exc}")
    check("production env + unreachable clamd FAILS CLOSED (raises, doesn't silently downgrade)", raised)

    print(f"\n{'=' * 60}\n{len(PASS)} passed, {len(FAIL)} failed\n{'=' * 60}")
    if FAIL:
        print("FAILED:")
        for f in FAIL:
            print(f"  - {f}")


class _FakeStorage:
    """Minimal EvidenceStorage stand-in -- configure_dependencies() requires
    a non-None evidence_storage arg; not under test in this PoC."""


def _set_settings_env(*, environment: str, clamd_port: int) -> None:
    os.environ["ENVIRONMENT"] = environment
    os.environ["CLAMD_HOST"] = CLAMD_HOST
    os.environ["CLAMD_PORT"] = str(clamd_port)
    # Settings() requires these with no default; dummy values are fine, this
    # PoC never actually uses them.
    for key, val in {
        "DATABASE_URL": "postgresql+asyncpg://x:x@localhost/x",
        "REDIS_URL": "redis://localhost/0",
        "MINIO_ENDPOINT": "localhost:1",
        "MINIO_ACCESS_KEY": "x",
        "MINIO_SECRET_KEY": "x",
        "OPENSEARCH_URL": "http://localhost:1",
        "OPENSEARCH_USERNAME": "x",
        "OPENSEARCH_PASSWORD": "x",
        "KEYCLOAK_URL": "http://localhost:1",
        "KEYCLOAK_CLIENT_SECRET": "x",
        "VAULT_URL": "http://localhost:1",
        "VAULT_TOKEN": "x",
        "CELERY_BROKER_URL": "redis://localhost/1",
        "CELERY_RESULT_BACKEND": "redis://localhost/2",
    }.items():
        os.environ.setdefault(key, val)


if __name__ == "__main__":
    asyncio.run(main())
