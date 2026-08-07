# poc/performance_validation — I5: CLAUDE.md SS B.6 baselines, measured for real

Measures the five performance baselines stated in CLAUDE.md SS B.6 against
the real, already-running dev stack (`docker/docker-compose.dev.yml`) and
real fixture data already committed to this repo. Per SS F.1 / roadmap SS 1
item 7: every number below comes from a captured, inspected real run — none
are estimated or assumed.

## Versions pinned (read from this repo, not assumed)

| Component | Version | Source |
|---|---|---|
| `evtx` (evtx-rs binding) | `0.12.1` (repo requires `>=0.8`) | `docker exec docker-kronos-backend-1 pip show evtx`; `pyproject.toml:27` |
| OpenSearch | `2.11.1` | `docker-compose.dev.yml`; confirmed live via `_cluster/health` |
| Plaso | `20260512` | `docker/plaso/Dockerfile`; pinned image `kronos-poc-plaso:20260512` (still present, reused from `poc/plaso/`) |
| Python (backend container) | `3.14.6` | `docker exec docker-kronos-backend-1 python3 --version`-equivalent |
| Python (host venv running pytest/httpx) | per `/home/reca/venv` | `pytest 9.1.1`, `httpx 0.28.1` |

## Method per baseline (see `output.txt` for full captured output)

### 1. EVTX ingest rate (target: >5000 records/sec/core)

`evtx_rate.py` runs **inside `docker-kronos-backend-1`** (has the real pinned
`evtx==0.12.1` binding). It imports `FastEvtxParser`
(`src/external/parsers/evtx.py`) directly and calls `.parse()` in a loop
against the real bytes of `tests/fixtures/samples/real/system.evtx` (194 real
Windows Security-log records — the same fixture used by
`poc/kape_ingestion_test/`) — no HTTP/ClamAV/MinIO/Celery in the loop, since
those measure a different concern from parser throughput. `os.sched_setaffinity(0,
{0})` pins the process to CPU 0, matching SS B.6's explicit "single core"
wording. 20 iterations; report is the median rate.

**Fixture-size caveat, stated plainly per the brief's instruction not to
extrapolate:** `system.evtx` (200,000 bytes / 194 events) is the **largest
real EVTX fixture in this repo** — confirmed via `find -iname "*.evtx"`
across the whole tree; the only other EVTX fixture is the 4 KB synthetic
`tests/fixtures/samples/test.evtx`. No multi-thousand-event or multi-MB EVTX
sample exists anywhere in-repo (including `poc/*/`) to directly measure
steady-state throughput at a scale resembling a real forensic collection. The
per-run elapsed time (~6.3ms for 194 records) is dominated by fixed
per-invocation overhead (buffering the file into `BytesIO`, constructing a
fresh `PyEvtxParser`, building one `Evidence`/`TenantContext` per run) more
than by true per-record marginal cost, so the measured rate is a real,
reproducible number for *this* fixture, not a validated steady-state rate at
scale. It clears the 5,000/s target by roughly 6x even under that
conservative reading, but the honest caveat is: **this does not validate
million-record-file throughput, because no such fixture exists to test
against.**

### 2. OpenSearch query p95 (target: <500ms)

`opensearch_query_p95.sh` runs **inside `docker-opensearch-1`** (avoids an
extra TLS/nginx hop that would measure nginx, not OpenSearch) against the
real `kronos-*` indices already populated by this session's own H1–I2 PoC
work (1,570 real documents across 50+ real case-scoped indices, confirmed via
`_cat/indices` and `_count` — see `output.txt`). 4 realistic query shapes
(`_count`, `match_all` + sort, `term` on `event.code`, `terms` aggregation on
`kronos.parser`) x 20 iterations each = 80 total requests (within the
50–100 asked for). p50/p95 computed from curl's own `time_total` (client-
observed wall time, same as a real caller would see, TLS included since the
cluster's security plugin is genuinely on).

### 3. Plaso heavy-task duration (target: <10 minutes)

Reused the exact pinned image from `poc/plaso/` (`kronos-poc-plaso:20260512`,
built from the real `docker/plaso/Dockerfile`, running the real
`docker/plaso/kronos-plaso-worker.py` — the same script
`FirecrackerLauncher` execs in production) rather than re-deriving from
scratch, per the brief. `poc/plaso/output.txt` did not exist (only a
`README.md`) and neither `poc/plaso/` nor `poc/kape_ingestion_test/` had
previously captured a *timed* invocation (only pass/fail record counts), so
this PoC re-ran both known-working real samples under a real shell `time`:

- The light case: `tests/fixtures/samples/real/CMD.EXE-087B4001.pf` (a single
  real Prefetch file, 5 real events out).
- The heavier, more representative case: the real whole-disk
  `tests/fixtures/samples/real/kape/kape_triage.E01` image already exercised
  by `poc/kape_ingestion_test/` (414 real events out last time; reproduced
  here) — `PlasoParser`'s EWF routing sends the **whole image** through
  `log2timeline`/`psort` with dfVFS walking the filesystem itself, which is
  a materially heavier real workload than a single artifact file and the
  closest real analogue in this repo to a genuine "heavy Plaso task".

**Scale caveat, same honesty standard as #1:** both fixtures are small
synthetic/test-corpus samples (11,986 bytes and 62,050 bytes respectively) —
real KAPE/forensic images that would exercise the "heavy Celery task, <10
minutes" ceiling in practice are GB-scale, and no such fixture exists
in-repo. The measured ~13s for the E01 image is a real, reproducible number
for *this* fixture; it does not validate the 10-minute ceiling at realistic
scale, because nothing in this repo is close to that scale.

### 4. Unit suite wall time (target: <5s)

`pytest tests/unit/ -q` run for real, 2x with the repo's default `addopts`
(`--cov=src --cov=kronos_attest ...` from `pyproject.toml:50`) and 2x with
`--no-cov`, plus one `--collect-only` run to isolate import/collection
overhead from actual test execution. All from the host venv
(`/home/reca/venv`, `pytest 9.1.1`) against this worktree's `tests/unit/`
(1,316 collected, matching the 1315 passed + 1 skipped baseline stated in
the dispatch brief — confirms this worktree is not diverged).

### 5. No blocking operations on the FastAPI thread

Two real, complementary checks (brief allows either; both were feasible in
the time available so both were done):

- **Grep audit** (`output.txt` section 5a) of every route handler in
  `src/external/routes/*.py` for synchronous blocking patterns
  (`requests.`, `time.sleep`, `subprocess.run/call/check_*`, `open(`,
  `urllib.request`, `psycopg2`, `pymongo.`, `boto3.client(`) — zero matches
  — plus a structural check confirming every function immediately following
  an `@router.get/post/put/delete/patch` decorator across all 8 route
  modules is `async def` (a small Python AST-free line-scan, not a guess).
- **Real concurrent-request test** (`concurrency_check.py`, output section
  5b): fires 40 requests at the real live `docker-kronos-backend-1` process
  on `http://localhost:8000/healthz` (deliberately dependency-free per its
  own docstring in `fastapi_app.py` — no auth/TLS needed, so no login/step-ca
  friction) — once sequentially (baseline latency) and once as a genuine
  concurrent burst (`asyncio.gather`). A blocked event loop would make the
  concurrent burst's wall time approach `N x single-request-latency`
  (effectively serialized); a non-blocking loop completes the whole burst in
  close to one request's latency. Real result: the 40-request concurrent
  burst completed in 0.144s vs. a 1.87s fully-serialized estimate (7.7%
  ratio) — consistent with a non-blocked event loop.

  **Scope caveat:** this concurrency test only exercises `/healthz` itself
  (chosen because it needs no auth/TLS). It demonstrates the event loop
  isn't blocked *by that endpoint*, and — combined with the grep audit
  showing zero sync-blocking calls anywhere in `src/external/routes/` and
  100% `async def` coverage on route handlers — together this is real
  evidence for the FastAPI thread as a whole, but a genuinely
  authenticated, cross-route concurrent load test (e.g. one slow
  Plaso-triggering upload concurrent with many `/healthz` calls) was judged
  out of proportion for a shared, modest dev host per the dispatch
  instruction to keep load reasonable, and was not run.

## How to reproduce

```bash
# 1. EVTX rate (inside backend container)
docker cp poc/performance_validation/evtx_rate.py docker-kronos-backend-1:/tmp/evtx_rate.py
docker cp tests/fixtures/samples/real/system.evtx docker-kronos-backend-1:/tmp/system.evtx
docker exec docker-kronos-backend-1 python3 /tmp/evtx_rate.py /tmp/system.evtx

# 2. OpenSearch p95 (inside opensearch container)
docker cp poc/performance_validation/opensearch_query_p95.sh docker-opensearch-1:/tmp/opensearch_query_p95.sh
docker exec docker-opensearch-1 bash /tmp/opensearch_query_p95.sh

# 3. Plaso heavy-task duration (real docker run against the pinned PoC image)
time docker run --rm \
  -v "$(pwd)/tests/fixtures/samples/real/kape/kape_triage.E01:/mnt/evidence/kape_triage.E01:ro" \
  kronos-poc-plaso:20260512 \
  --evidence-path /mnt/evidence/kape_triage.E01 --evidence-id 00000000-0000-0000-0000-000000000002 \
  --case-id 00000000-0000-0000-0000-00000000000c --org-id test-org-id --org-alias testorg --sha256 deadbeef \
  > /tmp/plaso_e01_output.jsonl

# 4. Unit suite wall time
python3 -m pytest tests/unit/ -q            # with coverage (repo default)
python3 -m pytest tests/unit/ -q --no-cov   # without coverage

# 5. FastAPI blocking check
python3 poc/performance_validation/concurrency_check.py   # backend must be reachable on :8000
```

## Results summary (see `output.txt` for full captured logs)

| # | Baseline (CLAUDE.md SS B.6) | Real measured result | Verdict |
|---|---|---|---|
| 1 | EVTX ingest >5000 rec/s/core | median **30,395 rec/s** (194-record fixture, single core pinned) | **PASS** (6x target) — caveat: no larger fixture exists to test at scale |
| 2 | OpenSearch query p95 <500ms | **p95 = 12.2ms** (80 real queries against 1,570 real docs) | **PASS** (41x margin) |
| 3 | Plaso heavy task <10 min | **12.6s** real wall time (E01 whole-image parse, 414 events); 6.5s (single Prefetch file) | **PASS** (~48x margin) — caveat: fixtures are KB-scale, not GB-scale |
| 4 | Unit suite <5s | **9.36–10.85s** (1315 passed, 1 skipped; with coverage ~10.8s, without ~9.4s) | **FAIL** — confirmed, not a measurement artifact (see analysis below) |
| 5 | No blocking on FastAPI thread | Zero sync-blocking patterns in any route handler; 100% `async def`; 40-request concurrent burst completed in 7.7% of the fully-serialized-time estimate | **PASS** |

### Baseline 4 analysis (why it fails, and whether it's a real regression)

The dispatch brief asked to investigate *why*, not just report fail:

- **Coverage instrumentation cost:** ~1.4s of the ~10.8s default run
  (~13%) — real but not the dominant factor. Disabling it
  (`--no-cov`) still leaves **9.36–9.43s**, itself already ~2x over the 5s
  target.
- **Suite growth:** `--collect-only` reports **1,316 tests collected**
  (1315 passed + 1 skipped in the executed runs). CLAUDE.md's SS B.6 <5s
  figure predates this session's M0–M8 build-out; the brief's own framing
  (suite grew from "under 700 tests" to "over 1300") is consistent with what
  was measured here. At a roughly-comparable ~7ms/test average
  (9.4s / 1316 ≈ 7.1ms/test), a ~700-test suite would plausibly have landed
  under 5s (~5.0s at that same per-test rate) — i.e. the regression is
  explained by real, legitimate suite growth (more coverage of more
  subsystems), not a newly-introduced inefficiency.
- **Verdict:** this is a genuinely current, reproducible **miss** against
  the letter of SS B.6 (confirmed 4x independently: 2 default runs, 2
  `--no-cov` runs, all >9s) — reported plainly per roadmap SS 1 item 8
  ("fail loudly"). Whether the *number* in SS B.6 should be revised upward
  (e.g. to reflect a suite of this size) is a product/process decision for
  the project owner, not something this PoC silently papers over by
  "extrapolating a pass."

## What was NOT fixed

No `src/` files were touched. This is a measurement/reporting item per the
dispatch brief; the one real miss found (#4, unit suite wall time) is not a
bug with an "obviously safe" one-line fix — the two real causes (suite size,
coverage overhead) are both legitimate trade-offs (more tests = more
coverage; coverage measurement is itself required by SS B.5's "target
coverage >=80%") rather than a defect to patch, so it is reported, not
silently worked around.

## What was NOT measured, and why

- **EVTX/Plaso at realistic (GB-scale) size:** no fixture of that size
  exists anywhere in this repo; generating one synthetically for a PoC would
  produce a number about synthetic data generation, not about the real
  parser, so it was not attempted (would need a real multi-GB forensic
  sample, out of scope to source for this item).
- **Full authenticated, cross-route concurrent load test** for baseline 5:
  judged disproportionate for a shared, modest dev host per the dispatch
  instruction to keep concurrency/volume reasonable; the `/healthz` burst +
  full grep audit together are real, if narrower, evidence.
- **Query workload against a single very large index:** the live cluster's
  largest single index is 388 docs (case-scoped by design, per
  `docs/NEXTGEN_SOC_ROADMAP.md` SS0's `kronos-{org}-case-{case_id}-{yyyymm}`
  naming) — the 80-query workload above spans `kronos-*` (cross-index) to
  exercise a realistic multi-index query pattern instead, which is what a
  real cross-case search in this platform actually looks like.
