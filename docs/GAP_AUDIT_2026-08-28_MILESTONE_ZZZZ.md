# Gap Audit — Milestone ZZZZ (2026-09-02)

**Scope:** Tier 1 item 6 from `docs/HANDOFF_AND_ORCHESTRATION.md`: convenient
user discovery for "Add Member." Milestone RRRR shipped case-membership UI
with a deliberate v1 gap — a case-lead had to know a raw Keycloak user id,
since case-leads had no org-user-listing access at all. That doc explicitly
flagged the fix as a real RBAC-boundary decision, not something to build
unilaterally. **Asked the project owner directly** (`AskUserQuestion`)
rather than guessing; answer: build a new, narrow, case-scoped search
endpoint rather than widening `admin.py`'s existing org-admin-only listing
or leaving it UI-guidance-only.

## What was built

1. **`KeycloakAdminClient.list_org_members`** (new abstract method +
   `HttpxKeycloakAdminClient` implementation, `src/adapter/keycloak/admin_client.py`)
   — same real `/organizations/{org_id}/members` endpoint `admin.py`'s own
   `_list_keycloak_org_users` already uses, but deliberately without that
   function's per-member realm-role fetch (this caller doesn't need it,
   and shouldn't pay for it — O(1) Admin API calls regardless of org
   size, not O(n)). New `OrgMember` dataclass (`user_id`/`username`/
   `email` only — no roles).
2. **`GET /api/cases/{case_id}/member-candidates`** (`src/external/routes/cases.py`)
   — gated by the exact same `assert_case_lead_or_admin` check
   `add_case_member` already uses (a case-lead only ever sees this for a
   case they actually lead, never a general org directory browse). `q` is
   a **required**, `min_length=1` query param — deliberately does not
   allow an empty-query "list everyone" call. Substring match,
   case-insensitive, on username or email; capped to 20 results. Returns
   the narrower `CaseMemberCandidateOut` (no roles), not `admin.py`'s
   `OrgUserOut`.
3. **`CaseMembersSection`** (`frontend/src/pages/CaseDetailPage.tsx`) — the
   raw-userId text field is replaced with a debounced (300ms)
   search-as-you-type picker backed by the new endpoint. Already-added
   members are filtered out of suggestions client-side. Manual id entry
   is fully removed, not kept as a fallback — the search endpoint covers
   the full real org directory, so there's no remaining case a fallback
   would serve.

## Real, live verification

- Backend: 9 new unit tests (`tests/unit/test_cases_routes.py::TestListCaseMemberCandidates`)
  — real matches by username/email substring (case-insensitive), no-match
  returns empty (not an error), empty query rejected `422`, results
  capped at 20, unconfigured `KeycloakAdminClient` returns empty (not an
  error, matching `add_case_member`'s own contract), case-lead who
  doesn't own the case gets `403`, case-lead who does own it succeeds,
  unknown case returns `404`. Full backend suite: `2075 passed, 2
  skipped`. `ruff`/`mypy` clean on all changed `src/` files (pre-existing,
  unrelated `mypy` gaps in the test file confirmed via `git stash`, not
  introduced here).
- Frontend: `case-member-search.spec.ts` (new, 2 tests) against the real
  dev-stack Keycloak — real matches surfaced in the UI, a no-match state,
  already-added members correctly hidden from suggestions after being
  added, and a real second case-lead account (`SecondCaseLeadSeeder`)
  genuinely denied with `403` when it doesn't own the target case.
  `case-members-ui.spec.ts` updated for the new picker (was typing a raw
  id; now searches by the real dev-seeded `analyst` username) and
  reverified live. Both pass standalone and inside a 10-spec
  case-membership/RBAC regression cluster (39.2s, no interference). A11y
  scan of the Settings tab (`a11y.spec.ts`) reverified clean with the new
  picker markup. `tsc`/`oxlint`/`vitest` (110/110)/production build all
  clean. Required a real `docker compose build nginx && up -d nginx`
  (this is a UI behavior change), and the backend picked up the
  `admin_client.py`/`cases.py` changes via its own live `--reload`
  (confirmed via `docker logs`).

## Status

Tier 1 of `docs/HANDOFF_AND_ORCHESTRATION.md` is now fully closed. Item 1
(retroactive reindex) was run for real this same session; items 2–5 and 7
closed across Milestones WWWW/YYYY/XXXX/VVVV; item 6 closes here.
