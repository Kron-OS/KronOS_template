# Gap Audit — Milestone KKK (2026-08-28)

**Scope:** closes Milestone JJJ's own recommendation #1 — wire a
smoke-tier `frontend/e2e/` spec into
`.github/workflows/security-integration-tests.yml`, now unblocked since
that profile's nginx genuinely builds/serves the frontend over real HTTPS.

---

## What changed

New `frontend-e2e-smoke` job added to
`.github/workflows/security-integration-tests.yml` (same nightly +
manual-dispatch triggers as the existing `security-stack` job, own
runner, own project — the two jobs never share a Compose project or
interfere with each other):

1. `echo "127.0.0.1 kronos.local" | sudo tee -a /etc/hosts` — safe on a
   GHA runner specifically because it's a fresh VM with no other stack
   that could ever hold a conflicting `kronos.local` mapping. Explicitly
   NOT the pattern to reuse for local/shared-host verification (see below).
2. Bring up `postgres`/`redis`/`minio`/`opensearch`/`keycloak`, run
   `opensearch-init`/`keycloak-init`/`db-migrate`, build+start
   `kronos-backend`/`tls-init`/`opensearch-dashboards`/`nginx` (the real
   frontend build, `docker/Dockerfile.frontend`).
3. Wait for `https://kronos.local/login` to respond (30 x 2s poll, then a
   final `curl -f` so the step fails loudly if it never came up).
4. `actions/setup-node@v4` (Node 20, matching `test.yml`'s own
   `frontend-build` job exactly), `npm ci`,
   `npx playwright install --with-deps chromium`.
5. `npx playwright test e2e/login.spec.ts --reporter=list` — the real,
   unmodified smoke spec, no CI-only variant.
6. On failure: upload the Playwright report artifact + dump
   `docker compose logs`. Always: tear down.

## Verification (CLAUDE.md §F — actually run, not inferred from Milestone JJJ)

Milestone JJJ already proved the underlying stack works end-to-end, but
that was a hand-built isolated Compose run, not this exact job's own step
sequence (fresh `docker compose up -d --wait` in this order, a real `npm
ci` rather than reusing an existing `node_modules`, `playwright install
--with-deps`, the exact `curl`-poll readiness check). Re-ran the *whole
sequence* locally, end to end, mirroring the new job as closely as this
host allows:

- Same technique as Milestone JJJ for avoiding this host's live dev
  stack: no host ports published at all (`ports: !override []` on every
  service in a throwaway, uncommitted override), nginx reached via its
  own Docker bridge container IP + Chromium's
  `--host-resolver-rules=MAP kronos.local <ip>` (scoped to one browser
  process — the real CI job instead edits `/etc/hosts` directly, which is
  only safe because a GHA runner has no other stack to protect; this
  host does, so the substitute technique was used for the *local dry
  run* only, not because the workflow needs it).
- Brought up `postgres`/`redis`/`minio`/`opensearch`/`keycloak` (`--wait`,
  all healthy), ran `opensearch-init`+`keycloak-init` (both real
  production provisioning scripts, both exit 0), `db-migrate` (real
  Alembic run, applied 3 real migrations, exit 0), built+started
  `kronos-backend` (clean startup log, `Application startup complete`)
  and `nginx` (real `docker/Dockerfile.frontend` build).
- Ran `npx playwright install --with-deps chromium` for real (not a
  no-op check) — succeeded, including the apt-level Mesa/GL dependency
  updates `--with-deps` pulls in.
- Ran the real, unmodified `npx playwright test e2e/login.spec.ts`
  against this freshly-built stack (via the same
  `--host-resolver-rules` substitute, confirmed hitting the isolated
  stack's own nginx access log, not the live dev stack) — **1 passed**.

Isolated stack (`kronos-poc-ci-e2e`) torn down (`down -v
--remove-orphans`), built images removed, live dev stack (`docker ps`,
project `docker`, 15 containers) confirmed untouched before and after.

## Documentation updated

- `PROGRESS.md` §2.7/§2.8/§3.2: three corrections — the `frontend/e2e`
  Playwright-suite-can't-run-against-this-profile gap is closed; CI now
  genuinely runs `docker-compose.test.yml` against real services for the
  frontend too, not just the backend security stack; and the long-open
  `poc/frontend_browser` checklist item was stale (that directory never
  existed under that name — already superseded by
  `poc/dashboards_embed/autoload_verification/`, plus this cycle's new CI
  job for login coverage specifically).
- `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §4: pointer updated (see below).

## Status

Both of Milestone JJJ's recommendations are now done. The
`docker-compose.test.yml` profile is fully CI-wired for both the backend
security stack and a real frontend browser smoke check, nightly +
manual-dispatch. `frontend/e2e/`'s remaining five specs
(evidence-upload, evidence-retry, detection-triage,
detection-triage-race, cross-tenant-isolation) are NOT yet wired into
this CI job — deliberately scoped to smoke-tier only for this pass, per
the workflow's own tax-proportionality reasoning (each additional spec
adds real wall time to an already-nightly job, and several depend on
heavier fixtures like Celery/OpenSearch DLS provisioning not yet
confirmed working in this exact CI-built-frontend context).

## Recommendation for the next cycle

1. If the flow/isolation-tier specs are wanted in CI too, do it
   incrementally: add one spec, verify CI wall-time/flakiness impact
   before adding the next, rather than porting all five at once.
2. Otherwise, `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8 (dashboards
   embed, resilience, a11y/visual) or Milestone EEE's still-open
   maintainability findings remain available.
