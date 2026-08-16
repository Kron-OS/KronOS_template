# PoC: GET /api/admin/connectors/status -- real Postgres, real push, real Defender DI

**Milestone:** W14 (`docs/ASSESSMENT_SYNTHESIS_2026-08.md` P2-W14, from
`docs/assessments/ux_onboarding_review.md` SS1) -- the connector-status view
frontend gap.

**Versions pinned (read from this repo, not assumed):**
- Postgres: real running `docker-postgres-1` (`postgres:16-alpine`, per
  `docker/docker-compose.dev.yml`).
- `alembic==1.19.1`, `sqlalchemy==2.0.51`, `asyncpg==0.31.0` (installed in
  `/home/reca/venv`, matching `pyproject.toml`'s `>=1.13`/`>=2.0`/`>=0.29`
  pins).

## What this proves

1. **PUSH-mode enrichment is real, not fabricated.** A real API key is
   provisioned for a fresh org via the real, unmodified W8 admin route
   (`POST /api/admin/integration-sources/generic-webhook/provision`); the
   status route shows `status: "never_used"`, `lastIngestedAt: null`
   *before* any traffic. A real webhook push
   (`POST /api/integrations/push/generic-webhook`) using that exact key is
   then sent -- this creates a real `INTEGRATION_SOURCE_PUSH_INGESTED` audit
   row in the real, Postgres-backed `PostgresAuditLogRepository`. The status
   route is called again and now shows `status: "active"` and a real,
   non-null `lastIngestedAt` that matches the audit row's own
   `occurred_at` -- not a value the route invented.
2. **The Defender global-poll asymmetry is real, not asserted.** Using the
   real `configure_defender_poll_source_from_settings()` /
   `get_defender_poll_org_id()` / `get_defender_poll_source_id()` DI path
   (`src/external/dependencies.py`) with a real (mocked-env, per this
   module's own existing test convention --
   `tests/unit/application/test_defender_poll_source_wiring.py`) `Settings`
   instance:
   - `defender_poll_org_id` set to a **different** org -> the Defender entry
     is absent from this org's status response.
   - `defender_poll_org_id` set to **this** org -> the Defender entry is
     present, `mode: "poll"`, `selfService: false`, and its `note` field
     reads *"Configured for this org via platform settings — not
     self-service; contact your KronOS operator to change it."* -- the exact
     honest wording shipped in `src/external/routes/admin_connector_status.py`.
   - The real push-source entry from part 1 remains present alongside it
     (2 total entries) -- proving the two code paths compose correctly in
     one response, not just individually.

No real Microsoft Graph API call is made or needed -- the Defender half of
this route never talks to Graph, it only reads `Settings` + the audit log,
so this is a complete, real verification of the route's own logic.

## Exercises the real, unmodified classes

- `src/external/routes/admin_connector_status.py` -- `get_connector_status`
- `src/adapter/repository/postgres_integration_source_key.py` --
  `PostgresIntegrationSourceKeyRepository`
- `src/adapter/repository/postgres_audit_log.py` --
  `PostgresAuditLogRepository`
- `src/external/routes/admin_integration_sources.py` -- `provision` (W8,
  reused unmodified)
- `src/external/routes/integration_source_push.py` -- `push_webhook` (reused
  unmodified)
- `src/external/dependencies.py` --
  `configure_defender_poll_source_from_settings`, `get_defender_poll_org_id`,
  `get_defender_poll_source_id` (the two getters are new, added alongside
  this route)

## Why `httpx.ASGITransport`, not `TestClient`

`TestClient`'s own threaded portal runs the ASGI app on a separate anyio
worker-thread event loop, incompatible with the async SQLAlchemy engine
created on THIS coroutine's own loop -- the same real, previously-confirmed
"Future attached to a different loop" failure
`poc/kronos_attest_export/run_poc.py` and
`poc/integration_source_key_provisioning/run_poc.py` already documented;
this script follows that exact working pattern
(`httpx.AsyncClient(transport=httpx.ASGITransport(app=app))`).

## Isolation

A distinctly-named fresh org (`poc-w14-connector-status-org`, a random
`uuid.uuid4()` org_id, never a pre-existing one) is used throughout. The
script only ever appends rows scoped to that org_id and a second throwaway
`other_org_id` used purely to prove Defender-entry exclusion -- it never
resets or touches any other org's data in the shared dev Postgres, and never
touches any container/volume it didn't create.

## How to run (backend half)

```sh
cd /home/reca/Claude/Kronos/KronOS_template/.claude/worktrees/agent-ac50c04554f642836
/home/reca/venv/bin/python poc/connector_status_view/run_poc.py
```

Requires `docker-postgres-1` (part of `docker/docker-compose.dev.yml`)
already running on `localhost:5432`.

## Captured output (last real run, backend)

See `output.txt` in this directory for the full captured stdout of the last
real run -- every check passed (`ALL CHECKS PASSED`, 0 failures).

## Frontend visual verification (`run_poc_frontend.mjs`)

Real headless Chromium (Playwright 1.62.1, already a devDependency since
Milestone W7's `poc/frontend_theme_fix/`) against the real Vite dev server
(`npm run dev -- --host 127.0.0.1 --port 5199`), screenshotting the real,
unmodified `ConnectorStatusPage` + `Layout` component tree at `/admin/connectors`
in both dark and light mode. Mirrors `poc/frontend_theme_fix/run_poc.mjs`'s
own harness approach exactly, for the same reason: a real Keycloak login
isn't reachable in this sandbox (`kronos.local` doesn't resolve with a valid
cert here), so a throwaway `frontend/harness-authenticated.tsx` +
`.html` (pre-seeding the zustand auth store with an `org-admin` tenant,
pointing `window.history` at `/admin/connectors` before mounting the real
`<App/>`, deleted after this run, not part of the commit) stands in for a
real login. `GET /api/admin/connectors/status` is intercepted with
Playwright's `page.route()` and fulfilled with a fake-but-realistic response
covering all four real status/mode combinations the route can return
(active push, never-used push, revoked push, failing poll) -- this is
browser-level network mocking of one HTTP call (the real backend
integration is what part 3/4 above already proved against real Postgres),
not a change to any application code, so what's screenshotted is the real
page rendering real (fake-fed) data.

How it was run:

```sh
cd frontend
npm run dev -- --host 127.0.0.1 --port 5199 &
cp ../poc/connector_status_view/run_poc_frontend.mjs ./run_poc_tmp.mjs
# recreate harness-authenticated.tsx/.html per this README's own description
POC_OUT_DIR=../poc/connector_status_view node run_poc_tmp.mjs
rm run_poc_tmp.mjs harness-authenticated.tsx harness-authenticated.html
```

### Captured output (last real run, frontend)

```json
[
  {
    "page": "ConnectorStatusPage (Layout + /admin/connectors, mocked API)",
    "mode": "dark",
    "htmlClass": "dark",
    "url": "http://127.0.0.1:5199/admin/connectors"
  },
  {
    "page": "ConnectorStatusPage (Layout + /admin/connectors, mocked API)",
    "mode": "light",
    "htmlClass": "",
    "url": "http://127.0.0.1:5199/admin/connectors"
  }
]
```

Screenshots in this directory: `connector_status_dark.png`,
`connector_status_light.png`. Both confirm: the real `Connectors` nav link
in `Layout.tsx` (active/highlighted), the real table with all 6 DTO columns
populated, correct light/dark `dark:` pairing on every element (badges,
borders, table header background, row hover), and the honest
self-service-vs-platform-configured distinction rendered as visually
distinct badges (indigo "Self-service (this org)" vs gray "Platform-configured
(global)").
