# Gap Audit — Milestone KKKK (2026-09-01)

**Scope:** not a new feature milestone — a multi-scenario assessment cycle
(security / CI-reliability / coverage-gap lenses, each a separate `haiku`
subagent per the project owner's explicit instruction to use lighter
models for assessment work while decision-making stays with the
supervising agent) reviewing the state left by Milestones CCCC–JJJJ. Each
finding below was independently re-verified against real source/config/a
real live measurement before being acted on or dismissed — several
haiku-generated claims turned out to be imprecise on inspection, which is
exactly why this cycle's own process requires re-derivation rather than
trusting an assessment report at face value.

---

## 1. Security assessment — no critical/high findings

Reviewed the full RBAC/authz boundary matrix, cross-tenant isolation,
Keycloak coexistence (Milestone GGGG), and every mutation route added
since Milestone CCCC. Result: **no auth-bypass, privilege-escalation, or
cross-tenant path found.** Two low-severity items, both assessed and
accepted as-is this cycle (not fixed — genuinely low real-world risk, and
fixing either would be scope creep against a supervised assessment cycle):

1. **MEDIUM→accepted: `add_case_member` (`src/external/routes/cases.py`)
   takes a caller-supplied `userId` with no server-side existence/org
   check.** A case lead could add a `userId` string that doesn't
   correspond to a real user in their org. Low exploitability: the value
   only ever grants read/comment-style membership scoped to that one
   case, is itself an audited mutation (`case.member_added`), and
   `assert_case_access`'s own membership check re-validates against the
   *caller's* JWT `sub` on every subsequent request — a bogus `userId`
   grants nothing to anyone, it just adds a dead row. Left as a named,
   tracked gap (see §4) rather than fixed reactively — the correct fix
   (server-side Keycloak Admin API existence/org lookup) touches the same
   code path Milestone EEEE's own membership-grant spec exercises, and
   deserves its own verification cycle, not a rushed addition here.
2. **LOW→accepted: `poc/admin_totp_enrollment/output.txt` contains a real
   captured TOTP secret for the dev-only fixture `admin` account**
   (`JB3US4TBJNBEO32BOJJTSZCEI5WGYMKG`). Consistent with the
   already-established, already-accepted `case_lead_totp_secret.txt`
   precedent (dev/CI-only fixture credential, never a real credential,
   never used outside a throwaway stack) — no action needed.

## 2. CI-reliability assessment — one real fix, one claim corrected on inspection, two already-documented

Five findings reported; each re-verified against the actual workflow file
and/or a real timed run rather than accepted as stated:

1. **HIGH, real, fixed this cycle: `timeout-minutes: 70`'s justification
   comment undercounted real image-build steps.** The report's own phrasing
   ("claims 4 image builds, job actually has 6") was imprecise on
   inspection — re-derived directly against `docker-compose.test.yml`:
   the *later* `--build` step really does build 4 services
   (`kronos-backend`/`celery-worker`/`celery-worker-plaso`/`nginx`, as
   Milestone UUU's comment already said), but the *earlier*
   `opensearch-init`/`keycloak-init`/`db-migrate` step also has real
   `build:` stanzas that were never itemized by name anywhere in the
   comment chain — `keycloak-init` has its own distinct Dockerfile
   (`docker/init/Dockerfile.keycloak-init`) never mentioned before now,
   and `db-migrate` shares `docker/Dockerfile` with `kronos-backend`/
   `celery-worker` (so it pays that image's first real cold-build cost;
   the two later `--build` calls for the same Dockerfile are cache hits
   within the same job, not 3 independent cold builds). Corrected in
   `.github/workflows/security-integration-tests.yml` with an accurate
   inventory (6 `build:` stanzas across 4 distinct Dockerfiles) — the 70
   number itself is unchanged, since the dominant unbounded variable was
   already, correctly, flagged as unmeasured real GHA cold-build time in
   general, not a specific per-image count.
2. **MEDIUM, checked live, not a real issue: TOTP-check adds
   "unmeasured 10s-per-login latency" risk across every spec.** Re-read
   `LoginPage.ts`'s `completeConfigureTotpIfPresented()`: it's a
   `Promise.race` between "URL changed to `/cases`" and "Keycloak showed
   the CONFIGURE_TOTP page", each with a 10s timeout — but `Promise.race`
   resolves on whichever settles *first*, it does not wait for the slower
   arm. For every account that doesn't need enrollment (the common case),
   the URL-change branch should win quickly. Verified empirically rather
   than reasoned about only: ran `e2e/login.spec.ts` live against the
   real dev stack — `1 passed (2.7s)`, `real 0m4.29s` wall time for the
   whole Playwright process (browser launch + full spec, not just login).
   No 10s-class overhead observed. No code change made — this finding is
   assessed and dismissed, not silently dropped (recorded here so a future
   cycle doesn't re-raise it without re-checking).
3. **MEDIUM, already documented, still open:** `evidence-intake-retry.spec.ts`'s
   test-stack twin still hasn't been run against a real isolated stack.
   Re-checked this cycle's own real constraint before concluding anything:
   `free -h` showed 172Mi free / 2.0Gi available / 2.3Gi already swapped,
   with the already-running dev stack alone (16 containers, `docker ps`)
   consuming ~2.9GiB (`docker stats`, OpenSearch alone at 1.23GiB). Standing
   up a second full isolated stack (own Postgres/OpenSearch/Keycloak/MinIO/
   Redis/Celery) on top of that is not safe on this host right now — same
   real, measured constraint Milestone FFFF hit, re-confirmed rather than
   assumed still true. Left open; see §4.
4. **MEDIUM, already documented, still open:** real GHA resource headroom
   (disk/memory on an actual runner) remains unverified — unchanged since
   Milestone BBBB, no new information this cycle.
5. **LOW / no issue:** the health-check poll loop (30×2s) is correctly
   bounded. Confirmed, no action needed.

## 3. Coverage-gap assessment — doc accuracy confirmed, two new gaps named

- **`docs/PRODUCT_STATUS_AND_V2_PREVIEW.md` independently re-checked
  against current repo state: no material inaccuracies found.** Confirms
  the document written at the end of the prior directive-driven phase of
  this initiative is still an honest snapshot, not stale marketing copy.
- **`StatusPill`'s 7-uncovered-states claim (Milestone JJJJ) reconfirmed
  accurate.**
- **`assert_case_lead_or_admin`'s ALLOW branch is still only implicitly
  exercised** (as a setup step inside another spec), never asserted on as
  its own named scenario — a real, pre-existing gap, unchanged this cycle.
- **Two genuinely new gaps surfaced, not previously named in any milestone
  doc** (see §4 for disposition):
  1. No spec covers a role changing while a session is already active
     (e.g. an admin demotes a case lead mid-session) — every existing RBAC
     spec tests a role/membership state that's already fixed before login,
     not a live transition.
  2. There is no `DELETE /cases/{id}/members/{user_id}` endpoint at all
     (case-member removal is simply not implemented, additive-only
     membership); the existing *org*-member-removal endpoint
     (`admin.py::remove_user`) exists but has no E2E spec covering the
     removal-then-access-revocation flow.
- **Top recommendation from this assessment:** finish the intake-retry
  test-stack CI-wiring, since it's code-complete and blocked purely on a
  transient resource constraint rather than a design question — this
  converges independently with the CI-reliability assessment's own finding
  (§2.3), which is itself a meaningful signal (two independently-run
  assessments naming the same item without seeing each other's report).

## 4. Disposition — what's fixed vs. deferred, and why

**Fixed this cycle:**
- `.github/workflows/security-integration-tests.yml`'s `timeout-minutes: 70`
  build-step inventory (§2.1).

**Assessed and correctly dismissed (documented so it isn't re-raised
without re-checking):**
- TOTP-check per-login latency (§2.2) — measured, not a real cost.

**Deferred, named, tracked (not fixed this cycle — each has a stated
reason, not silently dropped):**
1. `add_case_member` unvalidated `userId` (§1.1) — low exploitability;
   the real fix (Keycloak Admin API existence/org lookup) deserves its own
   verification cycle against a real Keycloak instance, not a rushed
   addition inside an assessment-synthesis cycle.
2. Intake-retry test-stack CI-wiring (§2.3/§3) — still genuinely blocked
   by measured host memory, re-confirmed rather than assumed this cycle.
   Highest-priority item for the next cycle where host memory allows a
   dry run (e.g. after temporarily stopping non-essential dev-stack
   containers, or on a host with more headroom) — both independent
   assessments agree this is the single most valuable next step.
3. Real GHA resource-headroom verification (§2.4) — unchanged, needs an
   actual `workflow_dispatch`/merge-to-`main` run (Milestone RRR's own
   still-open item) to produce.
4. `assert_case_lead_or_admin`'s explicit ALLOW-branch spec (§3) — real,
   scoped, small; good candidate for the next feature (not assessment)
   cycle.
5. Mid-session role-change coverage (§3, new) — real design question first
   (does the platform even re-validate role on each request from a live
   JWT, or does the token need to expire/refresh for a demotion to take
   effect? — this needs to be answered by reading `keycloak_auth.py`'s
   real token-validation path before a spec can be written that asserts
   the *correct* behavior, not just *a* behavior).
6. Case-member removal (new) — `DELETE /cases/{id}/members/{user_id}`
   doesn't exist yet; this is a real, un-built feature gap, not just a
   test gap. Belongs in a feature cycle, not this assessment cycle.

## Real verification summary

- `docker ps` / `docker stats` / `free -h`: real, live re-check of host
  resource state before concluding the intake-retry stack still can't be
  attempted (not assumed carried-over from Milestone FFFF).
- `grep`/`awk` against the real `docker-compose.test.yml` to re-derive the
  actual `build:` stanza inventory for the `timeout-minutes` fix, rather
  than accepting the assessment's "6" claim or the prior comment's "4"
  claim at face value.
- `npx playwright test e2e/login.spec.ts --reporter=line`, live against
  the real running dev stack: `1 passed (2.7s)`, `real 0m4.29s` — real,
  captured timing used to dismiss the TOTP-latency finding, not reasoning
  alone.

## Recommendation for the next cycle

1. Re-attempt `evidence-intake-retry.spec.ts`'s test-stack twin once host
   memory allows — both independent assessments name this as the top
   remaining item.
2. Add `assert_case_lead_or_admin`'s explicit ALLOW-branch spec — small,
   well-scoped, real gap.
3. Investigate `keycloak_auth.py`'s real token-validation path to answer
   the mid-session-role-change design question before writing a spec for
   it.
4. Design and build `DELETE /cases/{id}/members/{user_id}` (feature work,
   not assessment work) with its own E2E coverage, following this
   initiative's established PoC-first/OOP/audit-on-mutation discipline.
5. `add_case_member`'s server-side `userId` validation — real fix, low
   urgency, needs its own verification cycle against a real Keycloak
   Admin API call.
