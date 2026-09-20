# Gap Audit — Milestone QQQQ (2026-09-01)

**Scope:** closes the real, named security finding from Milestone KKKK's
security assessment — `add_case_member` (`src/external/routes/cases.py`)
took a caller-supplied `userId` with no server-side existence/org check
at all. Low severity (`CaseRepository.get_by_id` is itself org-scoped, so
a member id belonging to a different org's user still can't reach this
case through that org's own query path), but a real data-hygiene/feedback
gap: an unvalidated id could add a dead membership row with no error at
all.

## The fix — reuse, not reinvent

`src/adapter/keycloak/admin_client.py`'s `KeycloakAdminClient.is_org_member(org_id,
user_id)` already existed, already DI-wired
(`get_keycloak_admin_client`), and is already the exact real Admin API
check `admin.py`'s own route-local `_assert_user_in_org` relies on for
the same underlying concept elsewhere in this codebase. `add_case_member`
now takes `admin_client: KeycloakAdminClient | None` and, when configured
(the "None means not configured" contract every other optional-Keycloak-
Admin-API feature in this codebase already uses, e.g.
`get_revoke_keycloak_session_action`), rejects with a real `403` if
`body.userId` isn't confirmed as a member of the caller's own org —
matching `admin.py`'s own message text ("Target user is not a member of
your organization") for consistency.

**`remove_case_member` deliberately not changed**: removing a
non-existent/non-member id is already a safe, well-defined no-op (its own
idempotent design, Milestone OOOO) — adding the same check there would
cost a real Admin API round trip to guard against something that's
already harmless by construction. Named in Milestone OOOO's own
recommendation list as "the same gap now also applies to
remove_case_member," but re-examined here rather than applied
mechanically — it doesn't actually apply the same way.

## Real, caught-live regression: `case-lead-ownership-access-grant.spec.ts`

The first live E2E run after this fix landed against the dev stack found
a genuine break, not assumed: `case-lead-ownership-access-grant.spec.ts`
(Milestone LLLL) called `attemptAddMember` with a placeholder UUID
(`"00000000-0000-0000-0000-000000000002"`), which the new validation
correctly rejects — the spec's own `expect(grantStatus).toBe(200)`
started failing with a real `403`. Grepped every `attemptAddMember` call
site across `frontend/e2e/` before fixing anything: three others already
used a real, in-org userId (`case-membership-access-grant.spec.ts`,
`case-member-removal-revokes-access.spec.ts`), and the one other
placeholder user (`case-lead-ownership-access-denial.spec.ts`) is a DENY
spec where `assert_case_lead_or_admin` rejects before the new check is
ever reached — genuinely unaffected, confirmed by re-running it. Fixed
`case-lead-ownership-access-grant.spec.ts` to decode the analyst dev
user's real Keycloak `sub` first, same established pattern.

## New backend unit coverage

`tests/unit/test_cases_routes.py::TestAddCaseMemberOrgValidation` (new) —
a `FakeKeycloakAdminClient` (mocks the external Keycloak dependency per
CLAUDE.md §B.5, not a domain object) confirms both branches: a
non-member `userId` gets a real `403` with the expected message; a
confirmed in-org `userId` succeeds and persists (verified via a direct
repository read, not just the response). `cases_client` (the existing
shared fixture) leaves `get_keycloak_admin_client` at its default `None`
— already exercising the "honestly skipped" path for every other test in
the file, confirmed by re-running the full file (36/36 pass, unchanged
from before this cycle plus the 2 new tests).

## `frontend/e2e/case-member-add-userid-validation.spec.ts` (new)

The real, live proof this fix actually works against the real dev
stack's real Keycloak — not just the mocked unit test. A real case-lead
who owns a case attempts to add a fresh, syntactically-valid,
real-nowhere UUID (`crypto.randomUUID()`, Node's own global, no new
dependency) as a member; asserts a real `403`. Confirms the actual
`HttpxKeycloakAdminClient` wired at real startup
(`configure_keycloak_admin_client_from_settings()`) genuinely rejects it,
not a fabricated/mocked backend.

## Real verification

- `~/venv/bin/python3 -m ruff check src/external/routes/cases.py`: clean.
- `~/venv/bin/python3 -m mypy src/external/routes/cases.py`: clean.
- `~/venv/bin/python3 -m pytest tests/` (full suite): `2058 passed, 2
  skipped in 30.90s`, coverage gate passed at 90.40% (up from 2056/90.39%
  before this cycle's 2 new tests).
- Confirmed the dev stack's `kronos-backend` picked up the change via its
  own live `--reload` (`docker logs`: `StatReload detected changes in
  'src/external/routes/cases.py'. Reloading...`).
- Confirmed the dev stack's `kronos-backend` genuinely has a live
  `KeycloakAdminClient` configured (`docker inspect
  docker-kronos-backend-1`: real `KEYCLOAK_URL`/`KEYCLOAK_CLIENT_ID`/
  `KEYCLOAK_CLIENT_SECRET` env vars; `configure_keycloak_admin_client_from_settings()`
  confirmed wired into the real startup sequence, not just defined) —
  this is what makes the E2E spec above a genuine live proof, not an
  accidental no-op against an unconfigured client.
- New E2E spec: `1 passed (2.7s)` on the first real run.
- Full 10-spec RBAC/membership cluster re-run after the
  `case-lead-ownership-access-grant.spec.ts` fix: `10 passed (32.1s)`, no
  interference.
- `login.spec.ts`/`cross-tenant-isolation.spec.ts`: `2 passed (6.6s)`,
  confirming no wider regression outside the RBAC cluster.
- `npx tsc -b`: clean. `npx oxlint`: 0 errors, 1 pre-existing unrelated
  warning. `npm run test` (vitest): 104/104 passed. `npm run build`:
  clean production build.
- Wired into `security-integration-tests.yml`; `timeout-minutes: 70`'s
  justification comment updated with the real measured cost.

## Status

Closes the last open item from Milestone KKKK's security assessment.
Both real, named findings from that cycle (this one, and the already-
accepted low-severity dev-only TOTP fixture secret) are now either fixed
or explicitly accepted as-is with a stated reason.

## Recommendation for the next cycle

1. Intake-retry test-stack CI-wiring — still blocked on host memory as of
   this cycle's own last check; re-check periodically.
2. `admin.py`'s own `_is_org_member`/`_assert_user_in_org` and
   `KeycloakAdminClient.is_org_member` are two separate, parallel
   implementations of the same real Admin API check, in two different
   parts of the codebase. Not consolidated this cycle (out of scope for a
   focused security fix), but worth a dedicated refactor pass — a good
   candidate for the next maintainability-focused cycle rather than a
   feature/coverage one.
