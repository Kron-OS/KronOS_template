# KronOS — Handoff & Orchestration Guide

**Purpose:** two things in one document. Part 1 is a priority-ordered list
of what's actually left to do. Part 2 is everything about *how this
initiative runs* that isn't written down anywhere else — the process,
conventions, and host-specific gotchas a fresh agent (or a human) would
otherwise have to re-derive the hard way. Written 2026-09-01 at the end of
a long continuous session (Milestones AAAA→UUUU); update it as state
changes rather than letting it go stale.

---

## Part 1 — What's left, in priority order

### Tier 1 — real, actionable, small-to-medium scope (do these next)

1. **Retroactively reindex existing evidence for the OpenSearch dynamic-field
   fix (Milestone UUUU)** — `scripts/reindex_kronos_dynamic_fields.py --dry-run`
   first, then for real, if you want already-parsed evidence's previously-dropped
   fields to become searchable. Deliberately not run automatically; a
   real operator decision, not a bug.
2. **`admin.py`'s `_is_org_member`/`_assert_user_in_org` vs
   `KeycloakAdminClient.is_org_member`** — two separate, parallel
   implementations of the same real Admin API check, in two different
   parts of the codebase (named in Milestone QQQQ). A real, contained
   refactor — good candidate for a maintainability-focused cycle.
3. **Persist pending form state across a step-up (MFA) redirect** — named
   in Milestone TTTT. `apiClient`'s step-up flow is a full browser
   redirect to Keycloak; it silently discards whatever the user had typed
   (confirmed live for the quota form; equally affects `inviteUser`/
   `updateUserRole`, which were never even UI-tested before TTTT). Real
   architectural question (e.g. stash pending form values in
   `sessionStorage` before redirecting, restore on return) spanning three
   existing features — needs a deliberate design pass, not a quick patch.
4. **Real E2E coverage for `inviteUser`/`updateUserRole`'s own step-up
   completion** — `completeStepUpReauth()` (the window-aligned-retry TOTP
   helper, `frontend/e2e/admin-quota-ui.spec.ts`) is proven and reusable;
   these two actions have never been driven through a real step-up in a
   browser before, despite having identical `_assert_aal2` gating.
5. **`assert_case_lead_or_admin`'s trilogy is done, but two adjacent gaps
   remain named**: mid-session role-change (answered/covered, Milestone
   NNNN) and case-member removal (built, Milestone OOOO) are BOTH closed
   — don't redo these. What's still open: convenient user discovery for
   adding a case member (item 6 below) and the Dashboards field-list
   spot-check (item 7).
6. **Convenient user discovery for "Add Member"** (named in Milestone
   RRRR) — a case-lead currently has to know a raw Keycloak user id to
   add a member (manual text entry, deliberate v1 scope decision — see
   Part 2's "decisions already made" list). If this becomes a real
   product ask, the design question is: does a case-lead get a
   *lightweight*, case-scoped user-search endpoint (new, narrow RBAC
   surface), or does the UI just guide them to ask an org-admin to look
   the id up on the Admin page (zero new surface, worse UX)? **This is a
   decision for the project owner, not something to build unilaterally**
   — it's a real RBAC boundary question, not just a UI gap.
7. **Spot-check that OpenSearch Dashboards' field list actually reflects
   Milestone UUUU's fix** — the Discover/Timeline tab derives its field
   list from the same live index mapping; a quick manual check (or a
   `dashboards-embed.spec.ts` extension) that a newly-auto-indexed field
   shows up there too, not just via a raw OpenSearch query, would close
   the loop completely.

### Tier 2 — blocked on something outside this session's control

8. **`evidence-intake-retry.spec.ts`'s test-stack-profile twin never run
   against a real isolated stack** — blocked on host memory every single
   time it's been checked this session (most recently: 307Mi free, 2.9Gi
   swapped, dev stack alone ~2.9-5GB). Re-check `free -h` before assuming
   this is still blocked; it may become feasible on a host with more
   headroom, or if the dev stack is temporarily stopped first.
9. **No workflow in this repo has ever executed on GitHub's own
   infrastructure** — every CI job is real and locally verified, but
   GitHub only evaluates `schedule:`/`push`/`pull_request` triggers from
   `main`, and this work has never been merged. Needs either a manual
   `workflow_dispatch` by someone with repo access, or a merge to `main`
   — **not something an agent should do unilaterally**; flag it, don't
   force it.
10. **Real Kubernetes deployment** (`helm install` against a real
    cluster) and **real Helm chart lint/template re-confirmation** are
    now current (Milestone PPPP re-confirmed `helm lint`/`template` both
    clean, `helm` IS installed at `/usr/local/bin/helm` — an earlier "not
    installed" claim was simply wrong). A real cluster `helm install` has
    still never been attempted; no cluster is available in this
    environment.

### Tier 3 — deliberately out of scope right now (don't re-litigate without a reason)

- **SIEM wiring** (Wazuh/Falco/Fluent-bit) — explicit standing directive
  from the project owner, "no SIEM wiring for now." Don't build UI or
  backend work assuming this is coming; treat any SIEM-adjacent route
  (`detections.py`'s `sync-to-siem`) as intentionally unfinished.
- **v2 features** (advanced timeline search, case collaboration/comments,
  automated forensic detection rules distinct from Sigma, DFIR report
  generation, API rate limiting) — see
  `docs/PRODUCT_STATUS_AND_V2_PREVIEW.md` §2 for the full, still-accurate
  list. Standing directive: "no v2 features for now."
- **`audit.py`'s `/export`/`/verify`/`/merkle-proof` routes have no web
  UI** — confirmed **deliberate**, not a gap (Milestone RRRR's own
  sweep): they exist specifically to feed the standalone, third-party-runnable
  `kronos-attest` CLI for independent forensic verification, per the
  original spec (`roadmap.md` §4.3 / Prompt 4.3). Do not build a web UI
  for these without first re-reading that design intent.
- **`StatusPill`'s 7 transient pipeline states** (uploading/scanning/
  hashing/etc.) have no visual-regression coverage — a documented, sized
  gap (would need a materially heavier fault-injection mechanism per
  state), not urgent.
- **Two-simultaneous-dependency-failure fault injection** has no
  coverage — every existing fault-injection spec targets exactly one
  dependency, fully down. Named, not urgent.

---

## Part 2 — Orchestration: how this initiative actually runs

### 2.1 The core discipline (read `CLAUDE.md` §F if you haven't)

**Nothing is "done" without being run against the real thing and the
output inspected.** Not the backend suite, not a UI change, not an
OpenSearch mapping fix. This session's own real bugs were *found* by
following this rule and would have shipped broken otherwise:
- A stale-cache bug in the case-archive UI (found because a live E2E
  assertion genuinely failed, not because it was reasoned about).
- TOTP-timing flakiness in step-up E2E tests (found by running the same
  spec 4 times, not trusting one green run).
- The OpenSearch dynamic-mapping bug itself (confirmed live against a
  real, already-populated case index before touching any code).

For a **UI change**: `npm run build` passing is necessary but not
sufficient. The dev stack's `nginx` serves a *built* image
(`docker/Dockerfile.frontend`), not a live Vite dev server — you must
`docker compose -p docker -f docker-compose.dev.yml build nginx && ... up
-d nginx` and then run a real Playwright spec against `https://kronos.local`
before calling a UI change verified. (CI's own `frontend-e2e-smoke` job
already rebuilds this fresh every run by design — the manual rebuild is
only needed because the local dev stack persists across sessions.)

For a **new integration** (parser↔OpenSearch, backend↔Keycloak, etc.):
build a throwaway PoC under `poc/<component>/` first, run it against the
real, pinned-version dependency, capture the output (`output.txt` or a
`README.md`), *then* write the real `src/` code informed by what was
actually observed. See `poc/opensearch_auto_index_fields/` for a recent,
complete example of the expected shape (reproduce the bug live → prove
the fix live → capture both).

### 2.2 The milestone-doc convention

Every real cycle of work gets a doc: `docs/GAP_AUDIT_2026-08-28_MILESTONE_<LETTERS>.md`
(the date in the filename is fixed/historical — don't change it; only the
letters increment). Sequence so far: `AAAA` → `UUUU` (4-letter, next is
`VVVV`). Each doc follows the same shape:

```
# Gap Audit — Milestone <LETTERS> (<real date>)
**Scope:** ...
## The real issue / what changed
## Real, live verification (commands + actual captured output, not descriptions)
## Status
## Recommendation for the next cycle
```

Every milestone also touches, in the same pass:
- **`PROGRESS.md`**'s §2.8 ledger — one new dated bullet, same level of
  detail as the milestone doc's own summary (this ledger is the
  "recent work log" for the whole initiative, not just CI/CD despite the
  section heading).
- **`docs/PLAYWRIGHT_E2E_TEST_PLAN.md`**'s top-of-file pointer — *only*
  when the milestone touches E2E specs. New entry goes above the
  previous one, which gets relabeled "for the prior cycle." Don't touch
  this file for backend-only or docs-only cycles (e.g. Milestone UUUU,
  PPPP).

**Git pattern**: two commits per cycle — one for the actual fix/feature
(`feat(...)`/`fix(...)`), one for the docs (`docs: Milestone <X> gap-audit
summary`), both with `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`.
Push directly to `feat/nextgen-soc-cert-platform`. **Never open a PR** —
this has been an explicit, repeated standing instruction the whole
session.

### 2.3 Host environment realities (this specific machine)

- **Memory is chronically tight.** `free -h` has shown as low as ~170-300Mi
  free with 2-3GiB already swapped, even with only the dev stack (16
  containers, ~2.9-5GB total) running. This is *the* recurring reason the
  test-stack-profile specs can't be verified — always check `free -h`
  fresh before assuming it's still blocked, but don't be surprised if it
  still is.
- **Docker Compose commands against the dev stack need `-p docker`
  explicitly** (e.g. `docker compose -p docker -f docker-compose.dev.yml
  build nginx`) — the project name doesn't default correctly otherwise.
- **Container names**: `docker-kronos-backend-1`, `docker-nginx-1`,
  `docker-opensearch-1`, `docker-keycloak-1`, `docker-postgres-1`, etc.
  (the `docker-` prefix comes from the `-p docker` project name).
- **`kronos-backend` auto-reloads on source changes** (`uvicorn --reload`,
  volume-mounted `src/`) — confirmed via `docker logs docker-kronos-backend-1
  | grep StatReload`. A backend Python change doesn't need a manual
  restart, just a moment to reload; a *frontend* change does need the
  manual nginx rebuild described in 2.1.
- **Python 3.14 works fine on this host now** — an old, previously-real
  `asyncpg`/`greenlet` deadlock (`SIGABRT`) is **no longer reproducible**
  (re-verified Milestone PPPP: full suite, `2063 passed, 2 skipped`,
  90%+ coverage, ~30s). Use `~/venv/bin/python3 -m pytest tests/` freely;
  don't assume you need a 3.11 toolchain. CI still correctly pins 3.11 —
  that's unrelated and unchanged.
- **`helm` is installed** at `/usr/local/bin/helm` (`v3.16.4`) — another
  previously-stale "not installed" claim, corrected Milestone PPPP.
  `helm lint`/`helm template` both run clean against `charts/kronos`.
- **OpenSearch is real, live, version 2.11.1** on `docker-opensearch-1`,
  reachable at `https://localhost:9200` (`admin`/`admin`, self-signed
  cert — `verify_certs=False`/`-k` needed). Real `kronos-*` indices exist
  from months of prior work; be careful with wildcard deletes.
- **Keycloak** is real, live, 26.2, at `http://keycloak:8080` internally
  / `https://kronos.local:8443` externally. Dev users: `case-lead`,
  `analyst`, `admin` (all in the `kronos-dev` org) — passwords in
  `frontend/e2e/fixtures.ts`'s `DEV_USERS`. `admin` requires TOTP even
  for ordinary login (`requiredActions: ["CONFIGURE_TOTP"]` in
  `kronos-realm.json`) — this is a **different** thing from step-up/aal2
  (see 2.4).

### 2.4 Real, load-bearing facts about this app's own behavior (learned by testing, not obvious from reading the code)

- **Step-up (MFA) is a full browser redirect, not an in-page refresh.**
  `apiClient`'s interceptor catches a real `401` +
  `WWW-Authenticate: ...acr_values="aal2"` and calls
  `keycloak.login({acrValues: 'aal2', prompt: 'login'})` — this navigates
  the whole page away and back. Consequences: (a) the original mutation
  is abandoned, the user must retry the action after returning; (b) any
  local React state (a typed form value) is lost, a full remount; (c) a
  normal login (even one requiring TOTP, like `admin`'s) does **not**
  imply `acr=aal2` — they're different Keycloak flows. See
  `frontend/e2e/admin-quota-ui.spec.ts`'s docstring for the full,
  live-confirmed sequence and `completeStepUpReauth()` for the working
  test pattern (password → OTP, with a window-aligned retry — a naive
  fixed-delay retry is NOT reliable, TOTP codes replay-reject within the
  same 30s window).
- **OpenSearch index names are keyed to each record's own *event*
  timestamp**, not wall-clock time
  (`timeline_normalization.build_index_name`,
  `kronos-{org}-case-{case_id}-{yyyymm}`). A case's index for a given
  historical month is created once, ever, and essentially never rotates
  again. Any "just wait for the next index" reasoning about template
  changes is **wrong** for this platform — always check whether a fix
  needs to reach already-existing live indices too (see
  `OpenSearchClient.ensure_index_template()`'s current pattern).
- **`add_case_member`/`remove_case_member` are idempotent by design** —
  adding an already-present member or removing a non-member both succeed
  (200), not error. This was a deliberate choice (Milestone OOOO), not an
  oversight — don't "fix" it into erroring.
- **`delete_case` is a soft archive** (`CaseStatus.ARCHIVED`), never a row
  deletion. Evidence and audit history both survive it untouched.
- **The evidence FSM cannot go from `COMPLETE` back to `PARSING`** — there
  is no built-in way to re-parse already-successfully-completed evidence.
  Retry only exists for `ERROR` states. If a future need requires
  re-parsing complete evidence (e.g. to pick up a parser fix), that's a
  real, new FSM capability, not something already there.
- **`list_cases` (the `/cases` list endpoint) returns every case in the
  org regardless of membership** — already-existing, pre-existing
  behavior (title/owner/status visible to every org member), not
  something introduced by recent work. Relevant context if you're ever
  evaluating whether exposing another case-scoped field is a new
  information-disclosure risk — it usually isn't, given this precedent.

### 2.5 Testing conventions (frontend E2E, `frontend/e2e/`)

- Page-object pattern: `KronosPage` base class (protected
  `getFreshAccessToken()`/`fetchJson()`/`postJsonWithStatus()`/
  `deleteWithStatus()`), concrete subclasses per page
  (`CasesPage`, `CaseDetailPage`, etc.).
- `DEV_USERS` fixture (`case-lead`/`analyst`/`admin`) for the three
  static dev accounts; `SecondCaseLeadSeeder`/`SecondOrgSeeder` for
  throwaway accounts needed to exercise a boundary the static accounts
  can't (e.g. "a case-lead who does NOT own this case").
  `SecondCaseLeadSeeder` now also returns a real `userId` (Milestone
  NNNN) for tests that need to act on that exact account afterward via
  the Admin API (e.g. `UserRoleUpdater`).
  `UserRoleUpdater`/`update_user_realm_role.py` swaps an *existing*
  user's realm role — unlike every other `seed_*` fixture, which
  provisions a fresh one.
- Real UI changes always get **both** a rebuild+redeploy of
  `docker-nginx-1` **and** a live Playwright run before being called
  done — see 2.1.
- Every spec run should be sanity-checked against the broader RBAC/
  membership cluster (grep for `.spec.ts` files touching the same
  boundary) before considering a change complete, not just its own new
  spec — this session caught two real regressions this way (a
  placeholder-UUID spec breaking once `add_case_member` gained real
  validation; the OTP retry logic itself needing a second look after an
  initial "looks fixed" run).
- `a11y.spec.ts` scans specific page **states**, not just page URLs — a
  new tab/section inside an existing page (e.g. the Settings tab's new
  Case Members UI) needs its *own* scan, the existing page-level scan
  won't catch it.

### 2.6 Backend testing

- `~/venv/bin/python3 -m pytest tests/` runs the *whole* suite (unit +
  integration) in ~30s, 2063+ tests, 90%+ coverage gate. Run this after
  any backend change, not just the narrowly-affected file — it's fast
  enough that there's no reason not to.
- Mocking convention: mock only *external* dependencies (Keycloak Admin
  API, OpenSearch, S3/MinIO) via a fake/mock class implementing the real
  ABC (e.g. `FakeKeycloakAdminClient` in
  `tests/unit/test_cases_routes.py`); never mock domain objects — use
  Pydantic factories (`tests/fixtures/factories.py`) instead.

### 2.7 Decisions already made — don't re-litigate without new information

- **Manual Keycloak-user-id entry for "Add Member"/"Add Quota"-adjacent
  admin actions**, not a name/email picker — a case-lead has no
  org-user-listing access today (`GET /api/admin/users` is
  org-admin-only) and expanding that RBAC boundary was explicitly treated
  as a separate design question (Tier 1 item 6 above), not bundled into
  either UI pass.
- **`remove_case_member` does NOT get the same `userId` org-validation
  `add_case_member` got** (Milestone QQQQ) — removing a non-existent/
  non-member id is already a safe no-op by design; validating it would
  cost a real Admin API round trip to guard against something already
  harmless.
- **No automatic retroactive reindex** after the OpenSearch mapping fix
  (Milestone UUUU) — a real, potentially large/slow operation against
  live data; left as an explicit, operator-run script, not automatic.
- **`dynamic: false` → `true` was NOT a revert to OpenSearch's naive
  default** — it's paired with an explicit `strings_as_keyword`
  dynamic_template forcing pure `keyword` mapping, specifically to avoid
  reintroducing the *original* bug (`text`+`.keyword` multi-field
  breaking bare-name `term` queries) that `dynamic: false` was invented
  to fix in the first place. If you ever see a reason to touch
  `index_template.json` again, re-read
  `poc/opensearch_auto_index_fields/README.md` and
  `poc/ecs_schema_hardening/README.md` first — this is a two-layered fix
  and it's easy to accidentally undo the first layer while adjusting the
  second.

### 2.8 Where things live (quick index)

| What | Where |
|---|---|
| Priority-ordered TODO + this orchestration guide | `docs/HANDOFF_AND_ORCHESTRATION.md` (this file) |
| Product-level status snapshot (v1 done / v2 planned / known gaps) | `docs/PRODUCT_STATUS_AND_V2_PREVIEW.md` |
| Detailed, sourced progress ledger (the "recent work log") | `PROGRESS.md` §2.8 |
| E2E scenario catalogue + latest-cycle pointer | `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` |
| Every milestone's own real verification record | `docs/GAP_AUDIT_2026-08-28_MILESTONE_*.md` |
| Binding process rules (OOP, layering, PoC-first, pipeline autonomy) | `CLAUDE.md` (project root) |
| Original design spec / DFIR module system | `Project_Specifications.md`, `reviews/*.md` |
| Throwaway integration PoCs, one dir per component pair | `poc/<name>/` |
| Real E2E specs | `frontend/e2e/*.spec.ts` + `frontend/e2e/pages/*.ts` |
