# Gap Audit — Milestone MMM (2026-08-28)

**Scope:** Milestone LLL's own recommendation #1 — add `celery-worker` to
`frontend-e2e-smoke` and wire in `evidence-upload.spec.ts` as the next
incremental flow-tier spec. This is the first time any real evidence
upload has ever been driven end-to-end against
`docker/docker-compose.test.yml` — every prior milestone touching this
profile (HHH/JJJ/KKK/LLL) only ever exercised login. Running it for real
(CLAUDE.md §F) surfaced **five real, previously-undiscovered bugs**, all
now fixed.

---

## The bugs

Ran `evidence-upload.spec.ts` against a freshly-built isolated stack
before touching anything else, per Section F. First attempt failed
immediately with a real backend `500` (screenshot: "Request failed with
status code 500") on `POST /api/evidence/upload/request`. Traced through
the real traceback, fixed, re-ran, hit the next real failure, repeated —
five real bugs in total, none guessed, each confirmed from an actual
stack trace or log line before being fixed:

1. **`MINIO_ENDPOINT: http://minio:9000` — a full URL where
   `Settings.minio_endpoint` expects a bare `host:port`** (its own
   docstring: `"e.g. minio:9000"`). `startup.py` builds
   `endpoint_url=f"{scheme}://{minio_endpoint}"`, so the old value
   produced the literal string `"https://http://minio:9000"` — botocore
   tried to resolve the hostname `"http"` and failed with a real
   `socket.gaierror`, confirmed via the actual traceback
   (`s3.py:89 request_presigned_upload → ensure_quarantine_bucket →
   _ensure_bucket → head_bucket`). Set on both `kronos-backend` and
   `celery-worker`; `docker-compose.dev.yml` already had the correct bare
   form (`minio:9000`) the whole time.
2. **`MINIO_USE_TLS` never set at all**, defaulting to `Settings`'s own
   `True` — but this profile's `minio` service (`minio/minio:latest`, no
   TLS cert configured) only ever serves plain HTTP. Fixed with
   `MINIO_USE_TLS: "false"` on both `kronos-backend` and `celery-worker`,
   matching dev.
3. **`MINIO_PUBLIC_ENDPOINT` never set at all**, so presigned upload URLs
   were signed against the internal `minio:9000` hostname — unreachable
   and (SigV4 signs the Host header) cryptographically invalid once a
   browser sent the request anywhere else. Fixed with
   `MINIO_PUBLIC_ENDPOINT: https://kronos.local:9444` on
   `kronos-backend`, reusing nginx's existing, already-shared `:9444`
   dedicated MinIO reverse-proxy block
   (`docker/nginx/nginx-lan-https.conf.template`, unchanged) rather than
   inventing new nginx config.
4. **nginx never published port `9444` at all** in this profile, so even
   a correctly-signed presigned URL had nothing to connect to. Added
   `9444:9444` and set nginx's own `MINIO_PUBLIC_URL` env (used only for
   the CSP `connect-src` directive) to the same value — without it, the
   browser's own Content-Security-Policy would have blocked the presigned
   PUT even after every other fix.
5. **MinIO had no CORS configuration**, and the presigned PUT is
   genuinely cross-origin (the SPA's `https://kronos.local` vs. the
   presigned URL's `https://kronos.local:9444` — different port, so
   different origin under browser same-origin policy). Fixed with
   `MINIO_API_CORS_ALLOW_ORIGIN: "https://kronos.local"` on the `minio`
   service, matching dev's already-proven value (MinIO's own
   `PutBucketCors` S3 API returns `NotImplemented` on this image; CORS is
   a server-level env setting instead).
6. **The real, most severe find**: `celery-worker`'s command only listened
   on `-Q q.parse.fast,q.index`. The *current* intake pipeline
   (`src/external/routes/evidence.py`'s own docstring: "hand off
   validate/scan/hash/promote to the autonomous pipeline
   (`kronos.process_intake`)") enqueues that task to `q.intake`
   (`src/external/celery_app.py`) — a queue this profile's worker never
   consumed at all. Every real evidence upload against this profile would
   have sat in `UPLOADING` forever, silently, with **zero error anywhere**
   — the task simply accumulates unconsumed in Redis's `q.intake` list.
   `docker-compose.dev.yml`'s own `celery-worker` already listens on all
   three queues (`q.parse.fast,q.index,q.intake`); this profile's had
   silently drifted out of sync, undetected because nothing here ever
   drove a real upload far enough to notice. Fixed to match dev exactly.

None of these six items are hypothetical or guessed — each was confirmed
from a real stack trace, a real screenshot, or a real absent log line
before the corresponding fix was written, in the order the actual test
run surfaced them.

## What changed

`docker/docker-compose.test.yml`: `minio` (added CORS), `kronos-backend`
(three MinIO env fixes), `celery-worker` (same three MinIO env fixes plus
the `q.intake` queue fix), `nginx` (published `9444`, set
`MINIO_PUBLIC_URL`).

`.github/workflows/security-integration-tests.yml`: `frontend-e2e-smoke`
now also builds+starts `celery-worker`, runs
`e2e/evidence-upload.spec.ts` alongside `e2e/login.spec.ts`, and its
`timeout-minutes` raised `35` → `40` (three fresh image builds now, plus
a real parse-pipeline round trip, not just two builds and a login).

## Verification (CLAUDE.md §F)

Three separate real runs against freshly-built isolated stacks (own
project, no host ports published, nginx reached via its Docker bridge
container IP + Chromium `--host-resolver-rules`, same technique as every
prior milestone in this initiative — never touched the live dev stack,
confirmed via `docker ps` before/after each):

1. First run against the **unfixed** profile — real `500`, real
   traceback, confirming bug #1.
2. After fixing #1-#5 (all five MinIO-related items): upload itself
   succeeded (no more `500`), but `watchEvidenceStateLive()` timed out —
   evidence never left a non-terminal state. Checked `celery-worker`'s
   own logs: zero task activity at all. Found bug #6 by reading the
   actual queue routing in `celery_app.py` against the worker's own
   `-Q` flag.
3. After fixing #6: `evidence-upload.spec.ts` — **passed** (real upload →
   real Celery `process_intake` → real Celery `dispatch_parse` →
   `parse_artefact_fast` → real live SSE `Complete` state, no page
   reload). Re-ran together with `login.spec.ts` — both passed, no
   regression, no cross-spec interference.
4. **Full mirror of the exact, final committed CI job sequence** (not
   just the ad hoc debugging runs above) against one more freshly-built
   isolated stack, step-for-step matching the new
   `frontend-e2e-smoke` job: base services `--wait`, provisioning,
   `--build kronos-backend celery-worker tls-init opensearch-dashboards
   nginx`, then `npx playwright test e2e/login.spec.ts
   e2e/evidence-upload.spec.ts` — **2 passed** (15.3s total). This is the
   run that gives real confidence in the committed workflow file itself,
   not just the underlying compose changes.

All three isolated stacks torn down (`down -v --remove-orphans` +
built-image cleanup) after each; live dev stack (`docker ps`, project
`docker`, 15 containers) confirmed untouched throughout every step.

## Status

The evidence-upload flow-tier spec is now real, verified, and CI-wired.
This is the first real evidence ever to make it through
`docker-compose.test.yml`'s intake→parse→COMPLETE pipeline — a
substantial, previously-entirely-latent gap (the pipeline could not have
worked for ANY real upload before this fix, not just this specific test's
own fixture file) now closed and locked in by nightly CI.

## Recommendation for the next cycle

1. **`evidence-retry.spec.ts` is deliberately NOT wired in** — it uses
   `DevStackFaultInjector` (Milestone LLL hardened this class to assert
   it only ever targets the real dev stack's own container, by design).
   Porting retry coverage to this profile would need either a
   test-stack-aware variant of that fault-injection technique or a
   different mechanism entirely — worth scoping deliberately, not
   reusing the dev-only class as-is.
2. `detection-triage.spec.ts`/`detection-triage-race.spec.ts` don't need
   Celery at all (pure API CRUD against Postgres/OpenSearch) — likely the
   next-cheapest increment; not yet confirmed live against this profile,
   should get the same run-it-first treatment this milestone did rather
   than being assumed to just work.
3. `cross-tenant-isolation.spec.ts` still needs the Python-fixture
   tooling gap closed first (Milestone LLL, item 4) — a real second
   Keycloak org via `SecondOrgSeeder`, which this CI job doesn't
   provision.
4. Otherwise, making `security-stack` also boot `kronos-backend` (LLL's
   recommendation #2) or a permanent concurrent-`/auth/refresh` regression
   spec (LLL's recommendation #3) remain open.
