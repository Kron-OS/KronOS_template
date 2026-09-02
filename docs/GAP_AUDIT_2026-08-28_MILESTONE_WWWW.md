# Gap Audit — Milestone WWWW (2026-09-02)

**Scope:** Tier 1 item 2 from `docs/HANDOFF_AND_ORCHESTRATION.md`: `admin.py`'s
`_is_org_member`/`_assert_user_in_org` and `KeycloakAdminClient.is_org_member`
were two separate, parallel implementations of the same real Admin API
check, named as a maintainability gap back in Milestone QQQQ (which fixed
`cases.py::add_case_member`'s own missing validation by reusing the
DI-wired `KeycloakAdminClient`, but left `admin.py`'s own older,
independent implementation of the identical check untouched).

## The real duplication

`admin.py::_is_org_member` made its own raw `httpx` call against
`/organizations/{org_id}/members/{user_id}` via a private
`_keycloak_admin_request` helper that fetches a **fresh, uncached** service-
account token on every single call. `KeycloakAdminClient.is_org_member`
(`src/adapter/keycloak/admin_client.py`) hits the exact same endpoint but
through the already-DI-wired, **token-caching**
(`HttpxKeycloakAdminClient._admin_token`, reused until near expiry) client —
the same one `cases.py::add_case_member` already switched to in Milestone
QQQQ. Two independently-maintained implementations of one security check
(AUTH-003: the mandatory org-scoping guard before any realm-role-mapping
Admin API call) is a real drift risk — a future fix to one could silently
not apply to the other.

## The fix

`_is_org_member` now prefers the DI-wired `KeycloakAdminClient` when one is
configured, delegating to its `is_org_member`. Because this guards a
**mandatory** security boundary (unlike `add_case_member`'s optional
check), it does **not** silently skip when no client is configured — it
falls back to the original raw Admin REST call in that case, preserving
the always-available guarantee the code had before. A malformed/
non-UUID `user_id` (a route path parameter, attacker-controllable per
`update_user_role`) is now caught and treated as "not a member" rather
than raising an unhandled `ValueError` past the check.

`_assert_user_in_org`, `_find_user_by_email`, and `_create_or_get_user`
all thread the new `admin_client: KeycloakAdminClient | None` parameter
through explicitly (mirroring `cases.py`'s own `Depends(get_keycloak_admin_client)`
pattern) rather than reaching for the module-level singleton getter
directly — deliberate: this codebase's tests for `admin.py` share a single
process-wide module state, and a route handler explicitly declaring and
threading the dependency keeps behavior independent of whatever some
*other* test file's fixtures happened to configure earlier in the same
pytest run.

## Real, live verification (not assumed)

`tests/integration/test_admin_routes_real_keycloak.py` — the suite that
already runs these routes against the real dev-stack Keycloak 26.2 — now
constructs a real `HttpxKeycloakAdminClient` (`real_admin_client` fixture,
same service-account credentials `admin.py`'s own fallback path uses) and
passes it into all four `invite_user`/`update_user_role` call sites,
proving the new **preferred** path works end-to-end against live Keycloak,
not just the pre-existing fallback. Ran live: **6 passed**. New unit tests
(`tests/unit/test_admin_routes.py`, `FakeKeycloakAdminClient`) cover the
DI-client path directly, including the malformed-UUID case. Full backend
suite: `2066 passed, 2 skipped`. `ruff`/`mypy` clean on all changed files
(two pre-existing, unrelated `mypy` findings in `test_admin_routes.py`
confirmed via `git stash` to predate this change, not introduced by it).

## Status

The duplication is closed for the actual security-relevant check
(`is_org_member`). `admin.py` still has its own separate `_keycloak_admin_request`
machinery for every *other* Admin API operation (create user, role
mapping, org settings, quota) that `KeycloakAdminClient`'s narrow ABC
doesn't cover — expanding that ABC to absorb all of `admin.py`'s
functionality was considered and rejected as out of scope for this cycle
(a much larger abstraction change than the named gap called for; see
Recommendation below).

## Recommendation for the next cycle

`KeycloakAdminClient`'s ABC is deliberately narrow (containment-focused:
sessions, org membership, org lookup — see its own module docstring). If a
future cycle wants to fully retire `admin.py`'s private
`_keycloak_admin_request`/`_get_service_account_token` machinery too, that
is a materially larger, separate refactor (new abstract methods for user
creation, role mapping, org settings, quota — touching every `admin.py`
route, not just the two named here) and should be scoped and reviewed on
its own, not bundled into "the same real Admin API check" cleanup this
cycle closed.
