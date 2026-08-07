"""L1 PoC: real evtx-rs FAST PATH throughput, pinned to a single core.

Runs *inside* docker-kronos-backend-1 (has the real pinned `evtx==0.12.1`
binding installed, see `pyproject.toml:27` `evtx>=0.8`). Calls
`FastEvtxParser.parse()` directly -- the exact class used by the real
autonomous pipeline's FAST queue -- against the real
`tests/fixtures/samples/real/system.evtx` fixture (194 real Windows System
event-log records, copied into the container at /tmp/system.evtx via
`docker cp`). This measures parser throughput only: no HTTP, no ClamAV, no
MinIO, no Celery broker round-trip -- those are separate concerns from
CLAUDE.md SS B.6's stated baseline ("EVTX ingest: >5000 records/sec on a
single core").

Usage (run from inside the container):
    python3 /tmp/evtx_rate.py /tmp/system.evtx
"""

from __future__ import annotations

import asyncio
import os
import statistics
import sys
import time
import uuid
from collections.abc import AsyncIterator

sys.path.insert(0, "/app")

from src.domain.evidence import Evidence, EvidenceMetadata  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402
from src.external.parsers.evtx import FastEvtxParser  # noqa: E402


async def _byte_stream(data: bytes, chunk_size: int = 65536) -> AsyncIterator[bytes]:
    for i in range(0, len(data), chunk_size):
        yield data[i : i + chunk_size]


def _make_evidence(size_bytes: int) -> Evidence:
    org_id = uuid.uuid4()
    case_id = uuid.uuid4()
    return Evidence(
        metadata=EvidenceMetadata(
            original_filename="system.evtx",
            content_type="application/octet-stream",
            size_bytes=size_bytes,
            uploader_user_id=uuid.uuid4(),
            case_id=case_id,
            org_id=org_id,
            org_alias="perf-poc",
        ),
        sha256="0" * 64,
    )


def _make_tenant(org_id: uuid.UUID) -> TenantContext:
    return TenantContext(
        org_id=org_id,
        org_alias="perf-poc",
        user_id=uuid.uuid4(),
        username="perf-poc",
        roles=frozenset({Role.ANALYST}),
        correlation_id="perf-poc-correlation-id",
    )


async def _run_once(data: bytes) -> tuple[float, int]:
    parser = FastEvtxParser()
    evidence = _make_evidence(len(data))
    tenant = _make_tenant(evidence.metadata.org_id)

    start = time.perf_counter()
    count = 0
    async for _record in parser.parse(_byte_stream(data), evidence, tenant):
        count += 1
    elapsed = time.perf_counter() - start
    return elapsed, count


async def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/system.evtx"
    with open(path, "rb") as f:
        data = f.read()

    # Pin to a single CPU core -- CLAUDE.md SS B.6 baseline is explicitly
    # "single core". Confirm affinity before/after so the number in the
    # report is honestly attributable to one core, not however many the
    # container happens to have.
    try:
        os.sched_setaffinity(0, {0})
        affinity = os.sched_getaffinity(0)
    except (AttributeError, OSError) as exc:
        affinity = None
        print(f"WARNING: could not pin CPU affinity: {exc}")

    print(f"file: {path}  size_bytes={len(data)}")
    print(f"pid={os.getpid()}  sched_affinity={affinity}  cpu_count={os.cpu_count()}")

    n_iterations = 20
    rates = []
    record_count = None
    for i in range(n_iterations):
        elapsed, count = await _run_once(data)
        record_count = count
        rate = count / elapsed if elapsed > 0 else float("inf")
        rates.append(rate)
        print(f"iter={i:02d} records={count} elapsed_s={elapsed:.6f} rate_rec_per_s={rate:.1f}")

    print("---")
    print(f"record_count_per_run={record_count}")
    print(f"n_iterations={n_iterations}")
    print(f"rate_min={min(rates):.1f}")
    print(f"rate_max={max(rates):.1f}")
    print(f"rate_mean={statistics.mean(rates):.1f}")
    print(f"rate_median={statistics.median(rates):.1f}")
    print("BASELINE_TARGET=5000 records/sec/core")
    verdict = "PASS" if statistics.median(rates) > 5000 else "FAIL"
    print(f"VERDICT (median vs target, this fixture only)={verdict}")


if __name__ == "__main__":
    asyncio.run(main())
