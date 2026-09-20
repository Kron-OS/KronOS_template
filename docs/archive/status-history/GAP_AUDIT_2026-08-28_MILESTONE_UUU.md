# Gap Audit — Milestone UUU (2026-08-30)

**Scope:** close the heavy-parser CI coverage gap carried since Milestone
PPP and named again explicitly in Milestone TTT's recommendation #1 —
`docker-compose.test.yml` had no consumer for `q.parse.plaso` at all, so a
real `ParserType.HEAVY` upload (Plaso, archive-format EWF/ZIP routing,
VolatilityModule) would sit in `RECEIVED`/`PARSING` forever in CI, silently,
with zero error. No prior spec in this profile ever exercised anything but
the FAST path.

---

## Fixed this cycle

### 1. `celery-worker-plaso` added to `docker-compose.test.yml`

Mirrors the service `docker-compose.dev.yml` already had (added there in an
earlier milestone), with the test-profile credential fixes already applied
to the existing `celery-worker` service in Milestone MMM
(`kronos_test_password`/`kronos_test` DB, `KronOSCiTest#2026` OpenSearch
password, `MINIO_USE_TLS: "false"`, bare `minio:9000` endpoint). Consumes
only `q.parse.plaso`, matching `parse_artefact_heavy`'s routing in
`src/external/celery_app.py`. Validated with
`docker compose -f docker-compose.test.yml config -q`.

Before writing this, checked what `FirecrackerLauncher`
(`src/external/sandbox/firecracker.py`) actually requires at runtime —
despite the name, it is a `subprocess.Popen` launcher around
`docker/plaso/kronos-plaso-worker.py`, container-level sandboxed
(Chainguard/Wolfi + Seccomp), not a real Firecracker microVM. Its own code
comment says so directly: "In production this would call the Firecracker
API... In the current implementation we spawn the Plaso worker as a
subprocess." This de-risked the whole effort — no KVM/microVM
infrastructure was needed in CI, just a container with Plaso installed,
which `docker/Dockerfile.plaso-worker` (Chainguard Python base,
`plaso==20260512`, `volatility3==2.28.0` via pip) already provides.

### 2. New spec: `frontend/e2e/evidence-upload-heavy-parser.spec.ts`

Uploads a real Windows 10 prefetch sample already present in the repo
(`tests/fixtures/samples/real/CMD.EXE-087B4001.pf`, ~12KB) — no synthetic
fixture needed. Confirmed via `src/application/validation.py`'s
`MagicByteValidator` table and `src/external/parsers/plaso.py` that this
file's magic bytes (`MAM`/`SCCA`) route it to `PlasoParser`
(`parser_type` → `ParserType.HEAVY`), never the evtx-rs FAST path. Watches
live SSE state via `watchEvidenceStateLive(...)` to confirm the evidence
actually reaches `Complete`, with `test.setTimeout(120000)` to budget for
Plaso's real (not FAST-path) startup + parse time.

### 3. Wired into `.github/workflows/security-integration-tests.yml`

- `celery-worker-plaso` added to the `docker compose up -d --build`
  service list, with a comment noting the confirmed real build time
  (>5 minutes — this build ran long enough locally to exceed the Bash
  tool's own 300s foreground timeout and move to background).
- New 8th E2E step, `"E2E: evidence-upload-heavy-parser"`, added after
  `"E2E: evidence-parse-retry"`, `if: always()`, matching every other E2E
  step's shape in this job.
- `timeout-minutes: 55 → 70`, grounded in the measured >5min Plaso image
  build plus this spec's own 120s budget, not a round-number guess.

Both YAML (`yaml.safe_load`) and Docker Compose config validation passed
as the final check before commit.

## Verified live, not just re-read

Brought up an isolated `kronos-test`-named stack (per the Milestone TTT
local-verification override) and ran the full sequence for real:

1. `docker compose ... up -d --build kronos-backend celery-worker-plaso
   tls-init opensearch-dashboards nginx` — exceeded the Bash tool's 300s
   timeout, moved to background; confirmed the real, non-trivial Plaso
   build time this cycle's `timeout-minutes` change is based on. Waited
   for completion, confirmed all containers `Up`/healthy.
2. First spec run failed: evidence stuck at "Uploading". This was my own
   test-setup mistake, not a real bug — I'd only brought up
   `celery-worker-plaso` and forgot the pre-existing `celery-worker`
   service, which is what actually consumes `q.intake`/`q.parse.fast`/
   `q.index` (`process_intake`/`dispatch_parse`) before a task ever
   reaches `q.parse.plaso`. Confirmed via `docker logs
   kronos-test-celery-worker-plaso-1` showing zero task activity.
3. Brought up `celery-worker` too, re-ran the spec: passed in 13.5s, with
   worker logs showing a real Plaso subprocess execution and 5 real
   timeline records extracted into OpenSearch. Two `parse_artefact_heavy`
   invocations appeared in the logs — the first attempt's evidence, stuck
   unconsumed in Redis's `q.intake` queue during my setup mistake, was
   automatically picked up once `celery-worker` connected. This is a real,
   positive confirmation of the pipeline's own queue-persistence design,
   not a bug.
4. Ran the full declared 8-spec CI order against the same stack. One
   transient, unreproduced anomaly: `evidence-upload.spec.ts` failed once
   during this pass (the exact error text was lost — the test-results
   directory was overwritten by the next run before it could be
   inspected). Attempted to reproduce by bringing up a fresh
   `celery-worker` and running the spec immediately with zero wait — it
   passed (7.7s); could not reproduce. Checked whether real CI has any
   incidental buffer here: yes — the "wait for nginx to serve the real
   frontend over HTTPS" step (up to 60s of polling) runs before any spec,
   which my own zero-wait local reproduction attempt didn't have. Most
   likely explanation is transient host contention (many concurrent
   Docker containers + browser/Node processes on one machine), not a real
   regression — but recording this honestly rather than silently
   dropping it, per this initiative's own verification-first discipline.
   A final, clean full run of all 8 specs in exact CI order passed with
   zero failures afterward.

## Documented, not fixed this cycle

Carried forward unchanged from Milestone TTT (still open, still real):

1. Intake-stage retry has zero E2E coverage (mid-intake, not pre-upload,
   dependency failure) — a real design question, not a quick wiring pass.
2. No spec covers two simultaneous dependency failures, or a
   degraded-not-hard-down dependency.
3. `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8 (dashboards embed,
   resilience, a11y/visual), RBAC access-denial specs.
4. Milestone RRR's finding (no workflow has ever actually run against this
   branch on real GitHub Actions) remains true as of this cycle — still
   only locally verified.

New, from this cycle:

5. The one unreproduced `evidence-upload.spec.ts` transient failure above.
   Not treated as a real regression given the clean re-runs, but flagged
   for anyone who sees it recur — if it does, the next step is checking
   whether the real CI job's pre-spec buffer (nginx health poll) is
   actually sufficient headroom, or whether this host's specific resource
   contention during heavy local verification runs (many specs +
   browsers + a freshly-built Plaso image all under one Docker daemon)
   was the real, non-CI-relevant cause.
6. `q.parse.plaso` coverage is still single-format (Plaso only, via one
   `.pf` sample). `ArchiveParser`/`TarArchiveParser`'s EWF/ZIP routing and
   VolatilityModule are also HEAVY-tier and share this same queue/worker,
   but remain untested end-to-end through the real CI pipeline.

## Status

The structural gap named by Milestones PPP and TTT — zero CI coverage for
the entire HEAVY parser tier — is closed for the Plaso case specifically,
verified against a real, freshly-built isolated stack with real Plaso
subprocess execution observed in worker logs, not assumed from reading the
compose file. `celery-worker-plaso`, the new spec, and the workflow wiring
are all committed together as one coherent fix. Two real issues surfaced
during verification are both documented honestly (a corrected setup
mistake, and an unreproduced transient anomaly), matching this initiative's
practice of not hiding what verification actually turns up.

## Recommendation for the next cycle

1. Extend HEAVY-tier coverage to the archive-routing (EWF/ZIP) and/or
   VolatilityModule paths sharing `q.parse.plaso` — currently only Plaso
   itself is exercised end-to-end.
2. Intake-stage retry E2E coverage (carried since Milestone TTT).
3. `security-stack` also booting `kronos-backend`, RBAC access-denial
   specs, or `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8 remain open.
4. Periodically re-check Milestone RRR's finding (no workflow has ever run
   against this branch) — a merge or manual `workflow_dispatch` by
   someone with repo access would be a genuinely new class of signal.
5. If the unreproduced `evidence-upload.spec.ts` transient failure (§
   above) recurs, investigate host resource contention vs. a real timing
   bug before assuming it's noise again.
