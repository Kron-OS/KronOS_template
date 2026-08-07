"""L4-shaped PoC: real concurrent-request check against the live FastAPI
backend (docker-kronos-backend-1, real uvicorn process on :8000, not a
mock/TestClient).

CLAUDE.md SS B.6 baseline: "No blocking operations on the FastAPI thread."
This is not directly a "number" the way the other 4 baselines are -- it is
a behavioral property. The strongest real evidence available without
touching auth (this endpoint is deliberately dependency-free, see
`fastapi_app.py`'s `/healthz` docstring) is: does per-request latency stay
flat as concurrency increases? A blocked event loop would show request
latency scaling roughly linearly with N (each request queueing behind the
previous one on a single thread), instead of N requests completing in
roughly the time of one.

Complements (does not replace) the grep-based audit in README.md, which
checked *every* real route handler in src/external/routes/ for sync-
blocking patterns (requests./time.sleep/subprocess.*/open(/psycopg2/etc)
and confirmed every handler is `async def` -- this PoC only exercises
/healthz directly since it needs no auth/TLS, so the grep audit is the
evidence for the *other* routes.

Usage: python3 poc/performance_validation/concurrency_check.py
"""

from __future__ import annotations

import asyncio
import statistics
import time

import httpx

URL = "http://localhost:8000/healthz"
N = 40  # modest -- shared dev host, per orchestrator instruction


def _pxx(sorted_vals: list[float], pct: float) -> float:
    idx = max(0, min(len(sorted_vals) - 1, int(round(pct / 100 * (len(sorted_vals) - 1)))))
    return sorted_vals[idx]


async def _one_request(client: httpx.AsyncClient) -> float:
    start = time.perf_counter()
    resp = await client.get(URL)
    elapsed = time.perf_counter() - start
    assert resp.status_code == 200, resp.status_code
    return elapsed


async def sequential_baseline(client: httpx.AsyncClient, n: int) -> list[float]:
    latencies = []
    for _ in range(n):
        latencies.append(await _one_request(client))
    return latencies


async def concurrent_burst(client: httpx.AsyncClient, n: int) -> tuple[list[float], float]:
    start = time.perf_counter()
    latencies = await asyncio.gather(*[_one_request(client) for _ in range(n)])
    total_wall = time.perf_counter() - start
    return list(latencies), total_wall


async def main() -> None:
    async with httpx.AsyncClient(timeout=10.0) as client:
        # warm up (TCP/keep-alive) so the first real measurement isn't
        # penalized by connection setup unrelated to event-loop blocking
        await _one_request(client)

        print(f"=== sequential baseline: {N} requests, one at a time ===")
        seq = await sequential_baseline(client, N)
        seq_sorted = sorted(seq)
        seq_total = sum(seq)
        print(f"sequential total_wall_s={seq_total:.4f}")
        print(f"sequential mean_s={statistics.mean(seq):.6f}")
        print(f"sequential p50_s={_pxx(seq_sorted, 50):.6f}")
        print(f"sequential p95_s={_pxx(seq_sorted, 95):.6f}")

        print(f"\n=== concurrent burst: {N} requests fired at once (asyncio.gather) ===")
        conc, conc_wall = await concurrent_burst(client, N)
        conc_sorted = sorted(conc)
        print(f"concurrent total_wall_s={conc_wall:.4f}")
        print(f"concurrent mean_s={statistics.mean(conc):.6f}")
        print(f"concurrent p50_s={_pxx(conc_sorted, 50):.6f}")
        print(f"concurrent p95_s={_pxx(conc_sorted, 95):.6f}")

        print("\n=== verdict ===")
        # A blocked event loop => concurrent total wall time approaches
        # N * (single-request latency), i.e. requests effectively serialize.
        # A non-blocked loop => concurrent total wall time stays close to a
        # small multiple of ONE request's latency, regardless of N.
        single_latency_estimate = statistics.median(seq)
        serialized_estimate = single_latency_estimate * N
        print(f"single_request_latency_estimate_s={single_latency_estimate:.6f}")
        print(f"fully_serialized_estimate_for_N={N}_s={serialized_estimate:.6f}")
        print(f"actual_concurrent_wall_s={conc_wall:.6f}")
        ratio = conc_wall / serialized_estimate if serialized_estimate > 0 else float("inf")
        print(f"concurrent_wall / fully_serialized_estimate = {ratio:.4f}")
        # Non-blocking event loop: concurrent burst should complete in a
        # small fraction of the fully-serialized time (threshold: <30%).
        verdict = "PASS (non-blocking)" if ratio < 0.30 else "FAIL (looks serialized/blocking)"
        print(f"VERDICT={verdict}")


if __name__ == "__main__":
    asyncio.run(main())
