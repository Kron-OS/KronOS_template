# PoC: Prod compose / Helm parity debt (roadmap I3, Milestone M8)

**Objective (roadmap I3, verbatim):** "Known-open, already documented: Helm
has no `CLAMD_HOST` wiring at all; `MAX_UPLOAD_BYTES`/`CLAMD_CONF_*`
reconciliation was scoped to `docker-compose.dev.yml` only; SA/AD/ISM
provisioning must be added for prod and Helm. Also: the pre-existing
~300s `test_sse_routes.py` slow test."

This is a resumed session (a prior attempt died to a real usage-limit error
mid-flight). `docker/docker-compose.prod.yml` already had real, uncommitted
edits when this session picked up: ClamAV `CLAMD_CONF_*` size wiring, a new
`opensearch-security-init` service, and `OPENSEARCH_SECURITY_ENABLED` added
to `kronos-backend`. This session reviewed that diff, found and fixed two
further real gaps in it, then did the Helm-side equivalent, then
investigated and fixed item 4.

## Versions pinned (CLAUDE.md SS F.2 step 1)

- Helm **v3.16.4** (`get-helm-3` official installer script, not previously
  installed on this host for this task — installed fresh, see output.txt
  section 1).
- Chart `apiVersion: v2` (`charts/kronos/Chart.yaml`) — standard Helm 3
  chart, no `kubeVersion` constraint set. `post-install`/`post-upgrade` hook
  Jobs are a stable Helm 3 primitive (already used by this exact chart for
  `keycloak.provisionOrg` — `charts/kronos/templates/keycloak/
  provision-org-job.yaml`), so no version-gating concern for reusing the
  same mechanism for OpenSearch.
- Bitnami `postgresql >=15.0.0` / `redis >=18.0.0` subcharts (declared in
  `Chart.yaml`, not vendored in git — fetched via `helm dependency build`,
  which requires network access; this host had it, see output.txt section
  2. Pulled `postgresql:18.8.6` / `redis:28.0.0` from
  `registry-1.docker.io/bitnamicharts`).
- OpenSearch `2.13.0` (prod compose) / `2.11.1` (dev compose) — the shared
  `scripts/provision_opensearch_security.py` was already verified against
  a real running cluster in `poc/opensearch_dashboards_sso/` and
  `poc/keycloak_opensearch_dls/` by prior sessions; this session did not
  re-run it against a live cluster (see "What was NOT verified" below).

## Item 1 — reviewed the existing docker-compose.prod.yml diff

Agreed with and kept: the ClamAV `CLAMD_CONF_StreamMaxLength/MaxFileSize/
MaxScanSize` wiring, the new `opensearch-security-init` service (reuses the
real, already-committed `scripts/provision_opensearch_security.py`), and
`OPENSEARCH_SECURITY_ENABLED: "true"` on `kronos-backend`.

Found and fixed two real, separate problems while reviewing:

1. **`celery-worker` was missing `OPENSEARCH_SECURITY_ENABLED` entirely**,
   even though `kronos-backend` had just been given it. Confirmed via
   `grep -rn ensure_generic_tenant_role src/` that only
   `TimelineIngestionService` calls it, and `celery_app.py` routes
   `dispatch_parse`/`finalize_evidence` to `q.index`, which
   `docker-compose.prod.yml`'s `celery-worker` consumes
   (`-Q q.parse.fast,q.index,q.intake`). Without this, the exact same
   silent-DLS-skip bug the prior session found on the backend would still
   happen on every real prod ingest via the worker. Fixed by mirroring
   `docker-compose.dev.yml`, which sets this var on all four of its
   backend/celery-worker/celery-worker-plaso services.
2. **`MAX_UPLOAD_BYTES` was never set on `kronos-backend` or
   `celery-worker` in prod**, even though it exists and is set on both
   services in `docker-compose.dev.yml` (with a documented root-cause
   comment about a real 239 MB E01 upload). It happens to coincide with
   `src/config.py`'s compiled-in 5 GiB Python default today, but the
   moment an operator overrides `KRONOS_MAX_UPLOAD_BYTES` to raise ClamAV's
   ceiling, the backend/worker's own enforced ceiling would silently stay
   at the old default — a real, silent drift bug. Fixed by adding the same
   `${KRONOS_MAX_UPLOAD_BYTES:-5368709120}`-driven var to both services,
   matching dev exactly.

**Found but explicitly NOT fixed (out of scope, flagging per instructions
rather than silently fixing):** `docker-compose.prod.yml`'s
`kronos-backend`/`celery-worker` set `OPENSEARCH_URL: http://opensearch:9200`
(plain HTTP), but the `opensearch` service's own config
(`docker/opensearch/opensearch.yml`) does not set
`DISABLE_INSTALL_DEMO_CONFIG=true` or `plugins.security.ssl.http.enabled:
false` — meaning the security plugin's bundled demo installer runs and
enables HTTPS on the REST layer by default, the same as
`docker-compose.dev.yml`'s identical `opensearch.yml`/`opensearch` service,
which correctly uses `OPENSEARCH_URL: https://opensearch:9200` for exactly
this reason. This looks like a real, pre-existing scheme mismatch in prod
(present before this session started, not introduced by the diff under
review) that could mean the backend cannot actually reach OpenSearch in
this compose file as configured. This is a TLS-trust/cert-verification
question (self-signed demo certs) that is materially bigger than this
item's four sub-items and was not touched here — worth a dedicated,
verified follow-up rather than a guess folded into this pass.

## Item 2 — Helm equivalent

**ClamAV Deployment check (per brief instruction): none exists.** Confirmed
via `find charts/kronos -type f` — no ClamAV Deployment/Service/PVC
anywhere. However, on inspection this is the SAME pattern already used for
every other backing service in this chart except Postgres/Redis:
OpenSearch, Keycloak, Vault, MinIO, and TSA are ALSO not chart-managed
Deployments here — only referenced by an external endpoint value
(`opensearch.url`, `keycloak.url`, `minio.endpoint`, `vault.addr`) that the
operator's own infrastructure is assumed to provide, with Postgres/Redis
being the only two actually deployed via the Bitnami subcharts. So the
gap is specifically "ClamAV has zero wiring of any kind" (confirmed:
`grep -rn CLAMD charts/kronos/` was a hard zero before this change), not
"ClamAV is missing a Deployment while its peers have one." Wiring
`clamav.host`/`clamav.port` as an external-endpoint value follows the
chart's own established convention rather than inventing a new one.
**If the real intent is for this chart to OWN a ClamAV Deployment** (unlike
Keycloak/Vault/etc.), that is a materially bigger, separate scope decision
(Deployment + Service + PVC for the virus DB + its own SecurityContext/
resources template) that was deliberately not made unilaterally here —
flagging for an explicit decision.

Changes made:

- `charts/kronos/values.yaml`: new `clamav.host`/`clamav.port` (external
  endpoint, matching the `opensearch.url`/`minio.endpoint` convention),
  new top-level `maxUploadBytes`, new `opensearch.securityEnabled` (true by
  default) and `opensearch.securityInit` (opt-in hook config, disabled by
  default like `keycloak.provisionOrg`).
- `charts/kronos/templates/configmap.yaml`: new `clamd-host` key.
- `charts/kronos/templates/_helpers.tpl` (`kronos.commonEnv`, shared by
  ALL FIVE workload Deployments — backend + celery-fast/plaso/index/beat):
  added `OPENSEARCH_SECURITY_ENABLED`, `CLAMD_HOST`, `CLAMD_PORT`,
  `MAX_UPLOAD_BYTES`. Adding it once here (vs. per-service, which is what
  compose does and is exactly how compose's celery-worker gap in item 1
  happened) means this class of gap can't recur per-Deployment in Helm.
- `charts/kronos/templates/networkpolicies/app-to-data.yaml`: added port
  `{{ .Values.clamav.port }}` (3310) to the App-zone -> Data-zone ingress
  allowlist, alongside the existing Postgres/Redis/MinIO/OpenSearch/Vault/
  KES/Keycloak/TSA ports — ClamAV was missing from this list entirely.
- **New**: `charts/kronos/templates/opensearch/security-init-configmap.yaml`
  + `security-init-job.yaml` — a `post-install,post-upgrade` hook Job
  (mirrors `keycloak/provision-org-job.yaml`'s exact shape: same hook
  annotations, same ConfigMap-mounted-script pattern, same
  `restartPolicy: Never`/`backoffLimit` shape), opt-in via
  `opensearch.securityInit.enabled` (default `false`). Ships a chart-local
  copy of `scripts/provision_opensearch_security.py` at
  `charts/kronos/files/provision_opensearch_security.py` (byte-identical,
  confirmed via `diff`) because Helm's `.Files.Get` cannot read outside the
  chart directory — the same reason `keycloak.provisionOrg`'s ConfigMap
  ships its own copy of `provision_keycloak_org.sh`.
  **Invariant #3 (tenant isolation computed, never supplied):** this Job
  takes no org id as input anywhere — it provisions one cluster-wide authc
  domain + one cluster-wide DLS role, with the DLS filter itself templated
  from each request's own JWT (`${attr.jwt.org_id}`) at query time, not
  from anything the Job passes in. Documented explicitly in the Job's own
  header comment.

## Item 3 — `test_sse_routes.py`'s ~300s slow test: investigated and fixed

Root cause (`src/external/routes/sse.py`,
`evidence_sse_stream`/`event_generator`): the endpoint polls
`evidence_repo.stream_by_case` every `_POLL_INTERVAL_SECONDS` (5s) and
stops early once `current` is non-empty AND every value is a terminal
state (`if current and all(s in _TERMINAL_STATES for s in
current.values())`). `test_valid_ticket_consumed_once`
(`tests/unit/test_sse_routes.py`) seeded **no evidence at all** for its
case, so `current` was always `{}` — `bool({})` is `False`, so the
early-exit condition never fired, and the generator ran the real,
unmocked `asyncio.sleep(5)` on every iteration until hitting the real
`_MAX_STREAM_SECONDS = 300` ceiling. The test used a plain (non-streaming)
`client.get(...)`, which forces httpx to drain the entire response body —
i.e. wait out the full 300s — before returning.

Confirmed by direct reproduction (not assumed): `timeout 15 pytest
tests/unit/test_sse_routes.py::TestSSEStream::test_valid_ticket_consumed_once
-q` reliably times out (exit 143 / "Terminated") — see output.txt section 8.

**Fix (test-only, no `src/` change, no risk to the endpoint's real 5-minute/
5-second production timing):** seed one `Evidence` record already in
`EvidenceState.COMPLETE` for the exact `case_id`/`org_id` under test
before calling the endpoint. This makes the FIRST poll iteration already
satisfy the early-exit, so the generator returns immediately without ever
sleeping — exercising the endpoint's real, documented "stream closes ...
when all evidence reaches a terminal state" behavior instead of
sidestepping it (an earlier draft of this fix used `client.stream()` to
avoid draining the body without changing what's seeded; kept the seeded-
evidence version instead because it verifies more real behavior for the
same effort, and reproducibly confirmed `client.stream()` alone did NOT
fix the hang — see "what did not work" note below).

**What did not work, and why (kept for anyone touching this test later):**
first attempt used `with client.stream("GET", ...) as resp:` on the
*original* (unseeded) test, reasoning that the ticket is popped
synchronously in the route handler before `event_generator()` is even
constructed, so reading only headers should be enough. Re-run under
`timeout 30` still hung/timed out. Not fully root-caused (plausibly
Starlette/httpx's ASGI transport in this pinned version still drives the
background portal to completion around `.stream()`'s context-manager
exit) — rather than spend more time confirming the exact internal reason,
switched to the seeded-evidence fix above, which is verified to work
(output.txt section 8: full file passes in 1.88s) and is arguably the
more correct test regardless.

## Full verification (mandatory bar, CLAUDE.md SS F.1 / roadmap #7)

All commands below were actually run in this worktree; see `output.txt`
for the complete, unedited captured output.

1. `which helm` → not found → installed via the official `get-helm-3`
   script (`v3.16.4`).
2. `helm dependency build charts/kronos` → pulled real Bitnami
   `postgresql:18.8.6` / `redis:28.0.0` charts.
3. `helm lint charts/kronos` → **0 chart(s) failed** (only pre-existing,
   unrelated warnings: missing `icon:`, missing vendored subchart dirs
   — both present before this session's changes too).
4. `helm template kronos-test charts/kronos` (default values, hooks
   disabled) → **exit 0**, 2459 lines rendered. Grepped and confirmed:
   `OPENSEARCH_SECURITY_ENABLED` present on all 5 workload Deployments;
   `CLAMD_HOST`/`CLAMD_PORT`/`MAX_UPLOAD_BYTES` present on all 5; port
   3310 present in the NetworkPolicy; `opensearch-security-init`
   correctly ABSENT (opt-in, disabled by default).
5. `helm template ... --set opensearch.securityInit.enabled=true --set
   keycloak.provisionOrg.enabled=true` → **exit 0**. Confirmed the
   ConfigMap + Job render with the full embedded script content and
   correct secretKeyRef/env wiring (full Job YAML pasted in output.txt
   section 5).
6. The hook-enabled render was fed through `yaml.safe_load_all` — **all 42
   documents parsed without error** (catches any indentation bug in the
   embedded Python script that a visual read could miss).
7. `docker compose -f docker/docker-compose.prod.yml config --quiet`
   (re-run AFTER all of this session's own edits) → **exit 0**, same
   benign "variable not set" warnings as the orchestrator's own
   pre-session baseline run, no new ones. Also confirmed
   `KRONOS_MAX_UPLOAD_BYTES` override propagates identically to both
   `MAX_UPLOAD_BYTES` (backend/worker) and the `clamav` service's
   `CLAMD_CONF_*` vars.
8. `pytest tests/unit/test_sse_routes.py` → **7 passed in 1.88s** (was:
   one test alone reliably exceeded 15s / hung toward 300s).
9. `pytest tests/unit/` (full suite) → **1283 passed, 1 skipped**, 88.35%
   coverage — exact match to the orchestrator-stated baseline count.
   Suite wall time now ~11s (previously dominated by the one ~300s test).
10. `mypy src/` → **29 errors in the same 10 files** as the stated
    baseline — zero new errors introduced by this session's test-only
    Python change (docker-compose.yml/Helm chart changes are not Python
    and are outside mypy's scope).

## What was NOT verified, and why

- **Did not run `helm install`/`helm upgrade` against a real Kubernetes
  cluster.** No cluster was available in this environment (this is a
  Docker-on-host PoC session per CLAUDE.md's Quick Start, not a K8s one);
  `helm template`+`helm lint`+manual YAML/parse inspection is the
  strongest verification available here. This means the
  `opensearch-security-init` Job's actual runtime behavior against a real
  cluster + real OpenSearch + real Keycloak was NOT re-verified end-to-end
  in this session — only that it renders correctly and reuses a script
  whose *logic* was already verified against a real OpenSearch+Keycloak by
  earlier PoCs (`poc/opensearch_dashboards_sso/`,
  `poc/keycloak_opensearch_dls/`). Follow-up: run this Job for real once a
  test cluster is available (e.g. via the `sandbox/` Sysbox box + kind/k3d).
- **Did not build or deploy an actual ClamAV Kubernetes resource** — see
  item 2's explicit flag above; this was a deliberate scope decision to
  report rather than silently invent, not an oversight.
- **Did not resolve the pre-existing `OPENSEARCH_URL` http-vs-https
  mismatch** found in item 1 — flagged, not fixed, as it is materially
  outside I3's four sub-items and touches TLS/cert-trust decisions that
  deserve their own verified pass.
- **Did not root-cause exactly why `client.stream()` alone didn't fix the
  SSE test hang** — documented as a dead end for future reference instead
  of spending further budget on it, since the seeded-evidence fix is
  verified working and arguably better anyway.
