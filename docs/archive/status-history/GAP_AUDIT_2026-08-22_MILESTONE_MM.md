# Gap Audit — Milestone MM (2026-08-22)

Continuation of `docs/GAP_AUDIT_2026-08-22_MILESTONE_LL.md`'s own
"Recommendation for the next wake-up cycle." This milestone closes all
four of Task #30's items: `riskScore`/`riskFactors` UI, the client-side
DSN secret exposure in `docker-compose.prod.yml`, a stale long-running
dev-stack image, and the `revoke-session`/`sync-to-siem` containment UI.
The last two items were dispatched to isolated worktrees and merged after
independent re-verification of every claim (test counts re-run personally,
not trusted from either subagent's own report — this initiative's standing
rule, which has caught real wrong numbers before).

---

## 1. `riskScore`/`riskFactors` surfaced in the frontend UI — FIXED

**Finding.** `riskScore`/`riskFactors` are computed server-side
(`src/application/risk_scoring.py`, real since Milestone F4) and exposed
on `DetectionOut`, but the frontend `Detection` type had no matching
fields and no UI surfaced them at all (confirmed via grep, zero matches).

**Fix.** Added `riskScore`/`riskFactors` to the frontend `Detection` type;
a new `RiskScorePill` component (banded Low/Medium/High/Critical over the
real 0-100 scale, honest "Not scored" for `null`) wired into both the
Detections list row and the detail page header; a full "Risk Score
Breakdown" table on the detail page showing each real factor's name,
weight, normalized value, and detail string.

**Verification.** `kronos-dev` had zero real Detection rows at the time
(a stale, orphaned org_id from a past dev-stack incarnation held the only
real risk-scored rows in Postgres) — seeded one real detection via the
real, unmodified `PostgresDetectionRepository` and `DetectionRiskScorer`,
then confirmed via a real Playwright run against the rebuilt
`docker-nginx-1` that the list pill, detail pill, and full breakdown table
all render the real data. **5/5 checks passed**
(`poc/detection_risk_score_ui/`). 74/74 frontend tests passing at the
time (8 new), `tsc`/`oxlint` clean. Commit `6ec6b67`.

---

## 2. Backend/celery/db-migrate `Config.Env` secret exposure — FIXED

**Finding.** `docker-compose.prod.yml`'s `db-migrate`/`kronos-backend`/
`celery-worker` services interpolated real Postgres/Redis passwords
directly into `environment:` values (e.g. `DATABASE_URL: postgresql+
asyncpg://kronos:${POSTGRES_PASSWORD}@postgres:...`) — `docker inspect
--format '{{json .Config.Env}}'` returned them fully resolved, in
plaintext. The same class of exposure Milestone LL fixed for
`redis-auth-streams`/`redis-celery`'s `command:` argv, this time in
`Config.Env` rather than `Config.Cmd` — explicitly flagged as a real,
separate, not-yet-fixed finding in that milestone's own PoC README.

**Real, honest scope correction found while investigating**: the dispatch
named 5 services, but only 3 (`db-migrate`, `kronos-backend`,
`celery-worker`) actually exist in `docker-compose.prod.yml` — prod has no
`celery-beat`/`celery-worker-plaso` service at all (a separate,
pre-existing gap, flagged but not fixed here — out of scope for a
secrets-exposure fix).

**Why Milestone LL's own `sh`-entrypoint-script pattern doesn't carry
over here**: `redis:7-alpine` has a real shell; `kronos-backend`'s own
runtime image (`cgr.dev/chainguard/python:latest`) does not (confirmed
directly — `docker run --rm --entrypoint sh ...` fails with `"sh":
executable file not found in $PATH`; `docker/Dockerfile`'s own
`ENTRYPOINT []` comment explains why: no shell exists to write a wrapper
script for).

**Fix, two mechanisms** (the two real services resolve their DSN through
genuinely different code paths):
1. **`kronos-backend`/`celery-worker`** (both instantiate a bare
   `src.config.Settings()`): `src/config.py` now sets `Settings`'
   `model_config` to use pydantic-settings 2.14.2's real, current
   `secrets_dir` option, gated behind a new `KRONOS_SECRETS_DIR` env var
   (unset — dev's real state — is a complete no-op; plain env vars work
   exactly as before). Set to `/run/secrets` in prod, it resolves
   `database_url`/`redis_url`/`celery_broker_url`/`celery_result_backend`
   from real, field-named Docker secret files instead. A new
   `field_validator` closes the one gap that contract itself leaves open:
   a secret file that exists but is blank would otherwise resolve to a
   syntactically-valid empty string, sailing past pydantic's "field
   required" check — now raises a clear `ValidationError` instead.
2. **`db-migrate`** (`alembic upgrade head`, deliberately bypasses
   `Settings()` — reads `DATABASE_URL` directly, avoiding ~15 unrelated
   required fields a migration-only run has no reason to need): fixed via
   a new, pure `migrations/db_url.py::resolve_database_url()`, adding a
   `DATABASE_URL_FILE` fallback mirroring the official `postgres` image's
   own `POSTGRES_PASSWORD_FILE` convention already used elsewhere in the
   same compose file.

Four new external Docker secrets added (`database_url`,
`redis_auth_streams_url`, `celery_broker_url`, `celery_result_backend_url`)
— each secret's content is the full, pre-assembled DSN, not just a bare
password (see `poc/backend_prod_secret_config_env_exposure/README.md`'s
own "Operational contract" section for the exact provisioning commands a
real deployer needs).

**Tests.** `tests/unit/test_config.py` (11 tests) and
`tests/unit/test_migrations_db_url.py` (10 tests) — 21 new tests, all
against the real installed pydantic-settings, not mocked.

**Verification — independently re-run by the orchestrator, not trusted
from the subagent's own report:**
- Full suite: **2025 passed, 2 skipped** (re-run personally in both the
  subagent's worktree and, after merge, in the main checkout — identical
  result both times). `ruff`/`black`/`mypy` clean on every touched file
  (pre-existing, unrelated lint debt confirmed identical with/without this
  change via `git stash`).
- Reviewed the actual code diff line-by-line; independently confirmed
  pydantic-settings 2.14.2's real `secrets_dir` option exists
  (`python3 -c "from pydantic_settings import SettingsConfigDict; print(
  'secrets_dir' in SettingsConfigDict.__annotations__)"` → `True`) and the
  exact SIEM sink name strings used elsewhere in this same milestone.
- Reviewed the real captured PoC output
  (`poc/backend_prod_secret_config_env_exposure/output.txt`): a real
  Docker build of `docker/Dockerfile`, a real disposable Postgres+Redis, a
  real `alembic upgrade head` run (23 tables created), a real bare-
  `Settings()` script opening real `asyncpg`/`redis.asyncio` connections —
  and `docker inspect --format '{{json .Config.Env}}'` on both real
  running containers showing the real passwords **zero** times anywhere in
  the output.
- `docker compose -f docker/docker-compose.prod.yml config` (dummy values
  exported for every referenced var) resolves cleanly — verified directly.

**Real, disclosed drift found along the way (not fixed here):**
`pyproject.toml` only floors `pydantic-settings>=2.3` — a fresh `docker
build` picked up `2.15.0` versus this repo's dev venv's `2.14.2`. The
`secrets_dir` API is identical in both (re-verified working end-to-end
against the 2.15.0-based image), so no functional gap resulted, but it's a
real, separate dependency-pinning looseness worth its own future fix.

**Honest scope limit** (same shape as Milestone LL's own): this closes the
`docker inspect`/Docker-API-level exposure (`Config.Env`) — the actual
scoped threat model (a read-only, inspect-level Docker access principal).
It does not, and cannot, prevent the resolved plaintext DSN from being
visible in the running process's own `/proc/PID/environ` once `Settings()`
has legitimately read it into memory — confirmed via a real, separate test
(an `alpine:3.20` container exporting a resolved secret then exec'ing a
real process: `docker inspect Config.Env` showed nothing, `docker exec ...
cat /proc/1/environ` showed the plaintext) — that requires actual
shell/exec access inside the container, a materially higher-privilege
position than `docker inspect`, out of scope here exactly as it was for
Milestone LL. Commit `077b5b7`.

---

## 3. Stale long-running dev-stack image — FIXED (no code change)

**Investigation.** While verifying item 2's compose changes,
`docker compose -f docker/docker-compose.dev.yml up -d nginx` (naive form,
Milestone KK) had already surfaced that `db-migrate` failed with `exec:
"alembic": executable file not found in $PATH` — traced (Milestone LL) to
a 3+-week-stale cached `kronos-backend:dev` image, not a real Dockerfile
defect (a fresh rebuild worked immediately). The four long-running
containers built from that same image (`kronos-backend`, `celery-worker`,
`celery-beat`, `celery-worker-plaso`) were still running on that stale
image at the start of this milestone.

**Action.** Rebuilt `kronos-backend:dev` and `docker-celery-worker-plaso`
fresh from current HEAD (confirmed via a direct in-image import check that
the rebuilt image actually contains the Milestone LL `case_id` fix).
Recreated all four containers one at a time with `--no-deps` (the safe
form established in Milestone KK), confirming healthy logs at each step
(FastAPI startup complete; both Celery workers registered all tasks and
connected to Redis; beat scheduler started cleanly). All four now run on a
single consistent, current-HEAD image.

**Verification.** A real end-to-end evidence-upload smoke test
(`poc/evidence_download_ui/run_poc.py`, reused as-is) against the freshly
recreated pipeline: real login, real case, real upload, real autonomous
promotion, real download with a byte-for-byte-correct SHA-256 match —
**9/9 checks passed**, confirming the recreated containers work correctly
end to end, not just that they started.

No commit for this item — it is a live infrastructure operation
(container recreation), not a code change; the images were already built
from already-committed source.

---

## 4. `revoke-session`/`sync-to-siem` containment UI — FIXED

**Finding.** `POST /api/detections/{id}/contain/revoke-session`
(`ORG_ADMIN`/`CASE_LEAD`) and `POST /api/detections/{id}/sync-to-siem/
{sink_name}` (`ORG_ADMIN`/`CASE_LEAD`/`ANALYST`) were both real, audited,
already backend-tested — and completely unreachable from the frontend
(confirmed via grep: zero references to either path, or to
`step-up/ticket`, anywhere under `frontend/src/`).

**Fix.** New `frontend/src/api/containment.ts`
(`mintStepUpTicket`/`revokeKeycloakSession`/`syncDetectionToSiem`) and a
new `ContainmentPanel` component on the detection detail page, mirroring
the existing "Triage" section's own role-gated-buttons pattern:
- **Sync to SIEM** (all three roles): a dropdown over this codebase's
  three real, configurable sink types (`splunk`/`cef`/`sentinel` —
  verified against the exact strings `src/external/dependencies.py`
  registers them under; there is no backend endpoint to discover which
  are actually configured in a given deployment, a known, accepted gap
  not solved here). A real 404 renders as an honest "not configured"
  message, never a fabricated success.
- **Revoke Keycloak Session** (`ORG_ADMIN`/`CASE_LEAD` only, deliberately
  narrower, mirroring the backend's own stricter gate): a two-step
  approval form — "Request Approval" mints a step-up ticket scoped to the
  exact `sessionId` about to be revoked (never a second, independent
  field — Gap Audit Milestone JJ's resource-mismatch fix is respected by
  construction); "Confirm Revoke" then fires the real route with that
  ticket.

**A real, significant bug found and fixed while verifying live** (not
assumed from reading the code — CLAUDE.md §F's own standard): the step-up
flow was **completely non-functional** end to end before this fix, for a
reason unrelated to the new containment code itself. Root cause, found by
reading `keycloak-js`'s real source: `keycloak.login()`/`.logout()`/
`.register()` all depend on private instance state that only
`keycloak.init()` ever populates. `initKeycloak()`'s cookie-resume fast
path (an intentional optimization — adopt a token from the backend's
HttpOnly refresh cookie immediately, skipping a redundant Keycloak round
trip) returned without ever calling `keycloak.init()`, so
`keycloak.login()` silently did nothing on every page except the very
first login — this codebase never had a second real caller of it until
this milestone's own containment UI became the first. A second, related
race: a page reached by *returning* from a step-up redirect still carries
the OLD, still-valid refresh cookie, which could win the race against the
fresh `code=` callback and silently keep the stale, pre-step-up token.
Fixed via a new `hasPendingRedirectCallback()` check plus a background
`keycloak.init()` call on the fast path; both behaviors locked in with new
tests in `keycloak.test.ts`. Without this fix, the entire revoke-session
action would have been permanently unreachable via the real UI regardless
of how correct the new `ContainmentPanel` code was.

**Tests.** `ContainmentPanel.test.tsx` (mocks only `../api/containment`):
role gating for all four roles, the sync-to-SIEM success/404 paths, the
full mint-ticket → confirm-revoke flow with correct argument threading,
the Confirm-Revoke button staying disabled until a ticket exists, and an
audited denial rendering honestly rather than as a fake success. Two new
`keycloak.test.ts` tests lock in the bug fix above.

**Verification — independently re-run by the orchestrator:**
- Full frontend suite re-run personally (both in the subagent's worktree
  pre-merge and in the main checkout post-merge): **84 passed, 0
  failures** (10 new — 8 in `ContainmentPanel.test.tsx`, 2 in
  `keycloak.test.ts`). `tsc --noEmit` clean. `oxlint` clean (same one
  pre-existing, unrelated warning as every other milestone this session).
- Reviewed the real captured PoC output personally
  (`poc/detection_containment_ui/output.txt`, 16 checks) rather than
  trusting the subagent's own summary: real `case-lead` login, real
  detection page rendering both Containment subsections; a real
  Sync-to-SIEM call returning a real 404 (confirmed no SIEM sink env vars
  are set on `docker-kronos-backend-1`); a real Revoke-Session flow
  including a real 401, a real Keycloak redirect, a real interactive TOTP
  step-up re-authentication, a real return to the app, the (expected,
  brief-anticipated) loss of in-flight form state across the redirect, a
  real retry, a real 201 ticket, and a real successful revoke — confirmed
  by a **fresh, independent** Keycloak Admin API re-check (not the call
  the backend itself made) that the target session was actually gone. A
  second, independently-logged-in `analyst` session confirmed live: Sync
  to SIEM works identically; Revoke Session's inputs/buttons are entirely
  absent from the DOM, replaced by the role-restriction message.
  **16/16 checks passed.**
- Rebased the subagent's single commit onto this milestone's own item-2
  tip (`077b5b7`) before merging — clean rebase, no conflicts (frontend-
  only vs. backend/infra-only file sets) — then fast-forward merged.

No backend (`src/`) file was touched for this item — scope stayed
frontend-only. `frontend/src/keycloak.ts` is the one file changed outside
the new Containment feature itself, and is directly load-bearing for that
same feature actually working. Commit `ac58f07`.

---

## Recommendation for the next wake-up cycle

All four of Task #30's items are now closed. Remaining real,
not-yet-actioned items carried forward from prior milestones:

1. **The broader client-side secret-in-`environment:` exposure across
   every OTHER service** (not `kronos-backend`/`celery-worker`/
   `db-migrate`, which item 2 above just fixed) — none identified as
   remaining at this time; re-grep `docker-compose.prod.yml` for
   `${.*PASSWORD}`/`${.*SECRET}`/`${.*TOKEN}` interpolation in a future
   pass to confirm no other service was missed.
2. **No backend endpoint to discover configured SIEM sink names** — a
   known, accepted gap; the UI works around it with a fixed dropdown of
   this codebase's three real sink types. Worth a small follow-up if it
   proves confusing in practice (surfacing a real "not configured" error
   is arguably fine UX for an admin-facing panel, not urgent).
3. The Postgres sync-replica ops-policy decision
   (`docs/POSTGRES_MINIO_HA_RESEARCH.md` §1.6, Milestone LL item 4)
   remains open for the project owner — not a technical blocker.
4. `pyproject.toml`'s floating `pydantic-settings>=2.3` pin (found this
   milestone) allowed a real, if currently-harmless, version drift
   between the dev venv and a fresh Docker build — worth tightening in a
   future dependency-hygiene pass.

A reasonable next full pass is a fresh repo-wide gap audit (Milestone NN),
given the second multi-scenario assessment's own findings (JJ through MM)
are now fully worked through.
