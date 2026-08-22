# PoC: Detection Containment UI (Gap Audit Milestone MM, 2/2)

**Objective:** live-browser verification that the new frontend Containment
UI (`frontend/src/components/ContainmentPanel.tsx`, wired into
`frontend/src/pages/DetectionDetailPage.tsx`) actually drives the two real,
previously-UI-less backend routes end to end:

- `POST /api/detections/{id}/contain/revoke-session` (roadmap M7/H2/EE1/JJ/LL)
- `POST /api/detections/{id}/sync-to-siem/{sink_name}` (roadmap W/W1)

and the real, first-ever UI consumer of `POST /api/step-up/ticket`
(RFC 9470) anywhere in this codebase — confirmed via
`grep -rn "step-up/ticket" frontend/src/` before writing any frontend code:
zero matches outside this milestone's own new files.

## Versions / real dependencies (CLAUDE.md SS F.2 step 1)

- Keycloak **26.2.5** (`docker-keycloak-1`, already running — confirmed
  live in prior milestones, e.g. `poc/revoke_session_route/README.md`).
- Postgres **16** (`docker-postgres-1`).
- `keycloak-js` **26.2.4** (`frontend/package.json`) — the exact client
  library `frontend/src/keycloak.ts` wraps; its real `lib/keycloak.js`
  source (not just its `.d.ts`) was read directly to find the real bug
  documented below.
- `playwright` (Python, `~/venv`) + `pyotp` for real TOTP code generation.
- Real dev-stack users: `case-lead`/`DevCaseLead#2026` (ORG_ADMIN/CASE_LEAD
  gate), `analyst`/`DevAnalyst#2026` (ANALYST-only gate check).

## Setup (`setup.py`)

Resolves the **current** `kronos-dev` org id live via the Keycloak Admin
API (org id churns across dev-stack recreations — never hardcode an old
one, see `poc/detection_risk_score_ui/README.md`'s own warning), seeds one
real `Detection` row via the real, unmodified `PostgresDetectionRepository`
+ `DetectionRiskScorer`, creates one real throwaway Keycloak user in that
org, and produces a real, live Keycloak session for it via
`poc/auth_flow/auth_helpers.py`'s scripted Authorization Code + PKCE login
(mirrors `poc/revoke_session_route/run_poc.py`'s own `real_login_get_session`
helper). That session is the "victim" `run_poc.py`'s Playwright script
actually revokes through the real UI. Prints one JSON line to stdout.

## Run

```
docker compose -f docker/docker-compose.dev.yml build nginx
docker compose -f docker/docker-compose.dev.yml up -d --no-deps nginx   # --no-deps: see Milestone KK's own "Real, unrelated infra issue" section
~/venv/bin/python3 poc/detection_containment_ui/run_poc.py
```

Requires the dev stack already up (`docker-nginx-1`, `docker-postgres-1`,
`docker-keycloak-1`, `docker-kronos-backend-1`) and a fresh nginx/step-ca
leaf cert (`docker compose -f docker/docker-compose.dev.yml up -d tls-init
&& docker restart docker-nginx-1` if `kronos.local`'s 24h cert expired).

## A real, significant bug found and fixed while verifying (not fabricated, not assumed)

Section F requires actually running the flow, not just reading the code
and assuming RFC 9470 step-up "should work" because the pieces look right
in isolation. Doing exactly that surfaced a genuine, previously-undetected
defect in `frontend/src/keycloak.ts`, unrelated to this milestone's own new
files, that made the step-up flow completely non-functional:

**Symptom, reproduced live:** clicking "Request Approval" on a detection
page reached via normal navigation (i.e. every page except the very first
login) called `keycloak.login({ acrValues: 'aal2', prompt: 'login' })`
(the response interceptor in `frontend/src/api/client.ts`) — and **nothing
happened**. No navigation, no console error, no rejected-promise log. Real
browser network tracing (`page.on('request')`) showed zero requests to
Keycloak after the call. Confirmed independently that the identical call
succeeded when fired from the browser console on the very first login page
right after bootstrap — narrowing the difference to *which page load* the
call happened on, not the call itself.

**Root cause, found by reading `keycloak-js@26.2.4`'s real, unminified
`lib/keycloak.js`** (not the `.d.ts`, not assumed from the README):
`keycloak.login()`/`.logout()`/`.register()` all delegate to
`this.#adapter` (a private field) and read `this.pkceMethod`/
`this.responseMode`/`this.scope`, **all of which are only ever set inside
`keycloak.init()`** (`init = async (initOptions) => { ... this.#adapter =
this.#loadAdapter(...) ... }`). `frontend/src/keycloak.ts`'s
`initKeycloak()` has a deliberate fast path (AUTH-002/FE-2's own cookie-
resume optimization): if the backend's HttpOnly refresh-token cookie is
valid, it adopts a token immediately and **returns without ever calling
`keycloak.init()`** — that's the whole point of the fast path (skip a
redundant Keycloak discovery + third-party-cookie round trip on every page
load). But that also meant `keycloak.login()` was silently broken (throws
"Cannot read properties of undefined" on the unset private field,
swallowed inside the interceptor's un-awaited call) on **every page except
the very first login** — this codebase simply never had a second caller of
`keycloak.login()` until this milestone to expose it.

A second, related bug surfaced once the first was understood: a page
reached by *returning* from a step-up redirect still carries the OLD,
pre-step-up HttpOnly refresh cookie (not yet expired) — resuming from it
first would win the race against the fresh `code=` fragment in the URL and
silently keep the stale aal1 token, dropping the real aal2 callback on the
floor unprocessed.

**Fix (`frontend/src/keycloak.ts`):**
1. `hasPendingRedirectCallback()` detects a `code=`/`error=` fragment in
   `window.location.hash` and, when present, skips the cookie fast path
   entirely so `keycloak.init()` always processes the real callback
   instead of losing the race to a stale cookie.
2. On the (now callback-free) fast path, fire `keycloak.init(...)` in the
   background (not awaited, so it doesn't block the fast path's whole
   point — immediate render) purely to populate the private adapter/PKCE/
   scope state that a *later* `keycloak.login()`/`.logout()` call on that
   same page needs.

New unit tests in `frontend/src/__tests__/keycloak.test.ts` lock both
behaviors in (spy on `keycloak.init`, assert it fires after a fast
cookie-resume; assert the cookie path is skipped when a `code=` fragment
is present). Full suite: **84/84 pass** (`npx vitest run`), `tsc --noEmit`
clean, `oxlint` clean (one pre-existing unrelated warning in
`ErrorCatalogue.tsx`, confirmed via `git stash` unchanged by this work).

Without this fix, `run_poc.py` reproducibly failed at the exact point
where "Request Approval" should trigger the step-up redirect — the retry
after step-up returning would 401 forever, and the whole containment
action would be silently, permanently unreachable via the real UI. This
is exactly the class of gap CLAUDE.md SS F exists to catch: the code
"looked right" (interceptor calls the documented `keycloak.login()` API
correctly per its own type signature) but had never actually been run.

## A real, one-time side effect this PoC's own first run caused

Triggering step-up for `case-lead` for the first time required completing
Keycloak's real `CONFIGURE_TOTP` enrollment flow interactively (parsing the
real QR-code secret from the rendered page, computing a real TOTP code with
`pyotp`, submitting the real enrollment form) — the shared dev-stack
`case-lead` account had no MFA credential before this. That is a real,
intentional side effect (mirrors `admin`'s own pre-existing `otp` credential
found via the Admin API before this work started — this is an established
pattern in this dev stack, not new). The resulting secret is persisted at
`case_lead_totp_secret.txt` (committed, low sensitivity: a throwaway TOTP
seed for a fake credential in an isolated dev realm, no different in kind
from the hardcoded `DevCaseLead#2026` password already committed elsewhere)
so `run_poc.py` is reproducible on subsequent runs without repeating
enrollment (it correctly detects and handles either the one-time
`CONFIGURE_TOTP` page or the later `login-otp` entry page — both markups
were inspected directly against this real, running Keycloak 26.2.5 before
`run_poc.py` was written, not guessed).

## What `run_poc.py` actually proves (16/16 checks, see `output.txt`)

1. Real `case-lead` login via the actual SSO UI; real detection page
   renders the "Containment" section with both Sync-to-SIEM and
   Revoke-Session controls.
2. Sync to SIEM: real `POST /sync-to-siem/splunk` → real 404 (no
   `SPLUNK_HEC_URL`/`CEF_SYSLOG_HOST`/`SENTINEL_*` set on
   `docker-kronos-backend-1`, confirmed via `docker exec ... env` before
   writing this PoC — an honest "not configured" outcome, not fabricated
   success) — and the UI shows that honestly, not a fake success state.
3. Revoke Session: fills in a real throwaway user id + real live Keycloak
   session id, clicks "Request Approval" → real 401 → real redirect to
   Keycloak → real interactive re-authentication (step-up MFA) → real
   return to the app → **the original in-flight form state is lost** (the
   exact UX reality this milestone's own brief called out) → re-fills the
   form and retries "Request Approval" → now succeeds (real 201 ticket,
   `acr=aal2` now genuinely carried by the SPA's active token) → "Confirm
   Revoke" → real `POST /contain/revoke-session` → real success.
4. **Independent verification**: a **fresh, separate** Keycloak Admin API
   call (not the one the backend itself made) confirms the target session
   is actually gone, both before (present) and after (absent) the UI
   action.
5. Role separation, live: a **second**, independently-logged-in `analyst`
   session sees and can use Sync to SIEM (same honest 404), but the Revoke
   Session inputs/buttons are entirely absent from the DOM, replaced by the
   role-restriction message — matching the backend's own stricter
   `ORG_ADMIN`/`CASE_LEAD`-only gate on that route.

Full captured output: `output.txt`. Screenshots: `screenshots/` (case-lead's
full panel, the honest not-configured SIEM result, the post-step-up-redirect
page, the granted-approval state, the succeeded-revoke banner, the
analyst's panel, and the analyst's own sync-to-siem result).
