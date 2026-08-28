# KronOS real-browser E2E suite

Real `@playwright/test` specs against a real, already-running KronOS
stack — not a mocked harness. See `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` for
the full design rationale, scenario catalogue, and delivery-order status.

## Prerequisites

- A real KronOS dev stack already up and reachable at
  `https://kronos.local` (default; override with `KRONOS_E2E_BASE_URL`).
  **On this host, the live stack runs under the Compose project name
  `docker`, not the `kronos-dev` the compose file's own `name:` field
  declares — any `docker compose` command against it must pass `-p
  docker` explicitly. See `docker/docker-compose.dev.yml`'s own
  "OPERATOR WARNING" comment for why.**
- A real, dev-seeded Keycloak user (`case-lead`/`DevCaseLead#2026` etc. —
  see `fixtures.ts`'s `DEV_USERS`), already provisioned by
  `docker/keycloak/kronos-realm.json`.
- `kronos.local`'s step-ca leaf cert has a 24h TTL and can expire mid-run
  — if specs suddenly fail to reach the app at all, refresh it first:
  `docker compose -p docker -f docker/docker-compose.dev.yml up -d
  tls-init && docker restart docker-nginx-1`.
- **A second interpreter**: `frontend/e2e/fixtures/seed_detection.py`
  (used by `DetectionSeeder.ts`) needs a real Python 3 with this repo's
  own backend dependencies installed (it imports `src.adapter.repository.postgres_detection`
  etc. directly, reusing real domain code rather than hand-written SQL —
  see that script's own docstring for why). Defaults to
  `~/venv/bin/python3`; override with `KRONOS_E2E_PYTHON` if that path
  doesn't exist on your machine. If neither exists, `DetectionSeeder.seed()`
  fails with a raw Node `ENOENT` — that's this exact prerequisite missing,
  not a suite bug.

## Running

```bash
npm run e2e                              # full suite
npx playwright test e2e/login.spec.ts    # one spec
npx playwright show-report e2e-report    # last run's HTML report
```

Runs serialized (`workers: 1` in `playwright.config.ts`) on purpose — the
suite reuses one real, shared dev Keycloak account across specs, and two
real simultaneous logins as the same account are a real, reproduced
Keycloak collision, not a hypothetical. See that config file's own
comment. Known cost of this: `evidence-retry.spec.ts` alone takes ~2.3
minutes (it forces and recovers from a real backend outage with real
Celery retry backoff) — don't be surprised the full suite takes ~2.5-3
minutes today. Not yet wired into CI — `docker-compose.test.yml` lacks
the OpenSearch-security/TLS/Keycloak scaffolding this suite needs; see
the plan doc's §4.

## Structure

- `pages/` — OOP page objects, one class per real page/view, all
  extending `KronosPage` (shared `fetchJson()`/`getFreshAccessToken()`/
  `pollLiveText()` helpers — see that class's own docstring).
- `fixtures.ts` — real dev user credentials + the `casesPageAsCaseLead`
  fixture (drives a real login before each test that needs one).
- `DevStackFaultInjector.ts` — deliberately breaks a real dependency
  (currently: stops/restarts `docker-opensearch-1`) to force a real,
  transient pipeline failure for retry/resilience specs. Hardcodes that
  container name; if this repo's Compose project-naming ever changes,
  update it there.
- `DetectionSeeder.ts` / `fixtures/seed_detection.py` — seeds a real
  Detection row for triage-related specs, resolving the real org_id live
  via Keycloak Admin REST (org_id churns across dev-stack recreations —
  never hardcode it).
- `*.spec.ts` — the actual specs, one real user-journey per file.
