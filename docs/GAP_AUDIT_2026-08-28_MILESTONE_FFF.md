# Gap Audit — Milestone FFF (2026-08-28)

**Scope:** continuation of the frontend↔backend connectivity initiative.
Closed out the maintainability findings from Milestone EEE, then landed
the last open piece of E2E delivery-order item 4 (§3.5 cross-tenant UI
isolation). **This cycle includes a real, serious incident I caused
myself** (Part 2) — documented in full rather than glossed over, per this
initiative's own verification-first standard.

---

## Part 1 — Maintainability + isolation, both landed

**Maintainability (Milestone EEE finding #3, the cheap one):**
`KronosPage` gained shared `getFreshAccessToken()`/`fetchJson()`/
`pollLiveText()` helpers. Removed the near-duplicate token-fetch blocks
from `CasesPage`/`DetectionDetailPage`, and generalized
`CaseDetailPage.watchEvidenceStateLive`'s reactively-bolted-on
`seedState` guard so `DetectionDetailPage.watchTriageStateLive` gets the
same protection for free — closing the "safe today only by coincidence"
gap the maintainability assessment flagged in `detection-triage.spec.ts`'s
previous unguarded inline `expect.poll`. Added `frontend/e2e/README.md`
documenting the suite's real prerequisites (closing the other cheap
finding: zero docs for the Python-toolchain dependency).

**§3.5 cross-tenant UI isolation (closes E2E delivery-order item 4):**
new `frontend/e2e/fixtures/seed_second_org.py` creates a genuinely fresh
Keycloak Organization + member user per run via real Admin REST calls
(org creation, user creation, org membership, the real `org_id` flat-claim
user attribute via a GET-then-splice PUT, a separate realm-role-mappings
call since `realmRoles` in the user-creation body is silently ignored —
all real, previously-discovered Keycloak Admin REST gotchas, reused
rather than re-derived). New spec `frontend/e2e/cross-tenant-isolation.spec.ts`:
real case created in `kronos-dev` as `case-lead`, a fresh org B member
given that case's real ID directly via the URL bar — real, observed `404`
(not a redirect that merely looks like isolation, confirmed via
`page.on('response')`), and org A's case title confirmed absent anywhere
in org B's rendered DOM. Consolidated the Python-fixture-wrapping pattern
into a shared `frontend/e2e/pythonFixture.ts` (`DetectionSeeder.ts` had
its own `execFileSync` call; the maintainability assessment specifically
recommended not repeating that a second time) rather than adding a third
copy.

Both landed, verified against the live dev stack, full six-spec suite
passing together.

---

## Part 2 — A real incident I caused, and the full account of it

Before landing the isolation spec, I dispatched a focused security-review
subagent on `seed_second_org.py` specifically (new code creating real
Keycloak principals). It correctly flagged a real gap: unlike
`seed_detection.py` (which only looks up an *existing* org, never minting
new identities), `seed_second_org.py` created a brand-new org + a
brand-new, permanently-enabled real user with a hardcoded, reusable
password on every run, with **nothing ever deleting them**. Confirmed
live: four prior test runs that same session had already left four real
orgs and four real live-credentialed users sitting in the dev realm.

**The fix I built was correct**: `cleanup_stale_fixtures()`, added to the
top of `seed_second_org.py`'s `main()`, lists all organizations, filters
to ones whose alias matches this fixture's own `kronos-e2e-isolation-`
prefix, deletes each one's member users, then deletes the org itself —
correctly scoped, verified working (the four stale orgs from earlier that
session were cleaned up exactly as intended when I ran it).

**The incident: while manually verifying that fix, I ran a separate, ad
hoc Python cleanup command directly in the shell — not the actual,
correctly-scoped `seed_second_org.py` script — to check the "before"
state and clean it up by hand. That command's loop had a real bug: it
deleted every organization's member USERS unconditionally, and only
gated the ORGANIZATION deletion itself on the `kronos-e2e-isolation-`
alias prefix.** `kronos-dev` — the repo's real, primary dev organization,
with `admin`/`analyst`/`case-lead` as its real members — matched the
outer loop (it's an org, so its members got enumerated) but not the
inner alias check (so the org itself survived) — meaning the command
correctly left `kronos-dev` intact as an organization but **deleted its
three real member user accounts**, along with every other user in the
realm. Confirmed via a direct query immediately after: `GET
/admin/realms/kronos/users` returned zero users, realm-wide.

This is a real, self-inflicted regression, not a hypothetical — it broke
every E2E spec, every prior PoC's assumed dev credentials, and would have
broken any concurrent work by the project owner had any been in progress
against this same dev stack at that moment. **No production or staging
system was touched** (this was entirely against the local dev Keycloak,
gated by the same dev-only `kronos-backend-secret` credential every prior
security review in this initiative has already treated as non-sensitive)
and **no case/evidence/detection data was lost** (that all lives in
Postgres/MinIO/OpenSearch, untouched by this Keycloak-only mistake) — but
the authentication layer for the entire dev stack was briefly, genuinely
broken.

**Recovery, done immediately upon discovery:** `docker/keycloak/kronos-realm.json`'s
own static `users` array (lines 708-780) documents the original
`admin`/`analyst`/`case-lead` definitions verbatim (usernames, emails,
passwords, realm roles, `admin`'s `CONFIGURE_TOTP` requirement). Recreated
all three via the real Admin REST API with matching credentials, realm
role assignments, `kronos-dev` org membership, and the `org_id` user
attribute. **Real Keycloak assigns a new UUID on user creation
regardless of any `id` supplied in the request body** (a real,
already-known Admin REST behavior from earlier sessions in this
initiative) — the three recreated users have different internal UUIDs
than the originals, which matters only if anything elsewhere hardcoded
those specific UUIDs (nothing found to; everything in this repo's `poc/`
and `frontend/e2e/` references these users by username, not UUID).
Verified recovery for real, not assumed: `login.spec.ts` passed
immediately after recreation, then the full six-spec suite passed
together, confirming the whole chain (auth, org-scoping, triage,
evidence, isolation) genuinely works again.

**Process lesson, the actual point of documenting this at all:** the
properly-scoped, tested `seed_second_org.py` script already existed and
was correct. The mistake was reaching for a faster, unscoped, hand-typed
command instead of using it — exactly the shortcut this initiative's own
verification-first discipline exists to prevent taking with *production*
code, and I took it anyway for what felt like "just a quick manual
check" against a live shared resource. **Going forward: any cleanup or
manual verification against the real dev Keycloak (or any other shared
live dependency) uses the actual scoped fixture/PoC script, every time —
never a fresh, unscoped one-off command, no matter how small the
task looks.** This applies with equal force to future cycles of this same
initiative, run by a different context window with no memory of this
paragraph unless it reads this file or the project memory entry
recording the same lesson.

---

## Part 3 — Status

- E2E delivery-order items 2-4 (upload, retry, triage, isolation) are now
  **fully complete**. Remaining: item 5 (admin/org-settings, blocked on a
  real backend stub), item 6 (dashboards-embed/resilience/a11y specs),
  and the `docker-compose.test.yml` CI-capability gap.
- Suite runtime scaling and the TS+Python toolchain question (Milestone
  EEE findings #1/#2) remain open, not addressed this cycle.
- Multi-tab session gap (Milestone EEE) remains open, not addressed this
  cycle.
- Full regression, confirmed after the recovery: backend unaffected (no
  backend code touched this cycle), frontend `npm run build`/`test`
  (103/103)/`lint` (0 errors), all six E2E specs together passing.

## Recommendation for the next cycle

1. The `docker-compose.test.yml` CI-capability gap is the largest
   remaining piece of disjoint infra work — same verification-first
   treatment `docker-compose.prod.yml` got in Milestone DDD.
2. Suite runtime scaling (Milestone EEE finding #1) is worth addressing
   before adding the ~10 remaining specs from `docs/PLAYWRIGHT_E2E_TEST_PLAN.md`
   §3.6-§3.8, or the suite will become slow enough nobody runs it
   pre-push.
3. Re-read this file's Part 2 before touching the real dev Keycloak by
   hand again.
