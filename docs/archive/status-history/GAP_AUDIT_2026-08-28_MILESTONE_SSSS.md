# Gap Audit — Milestone SSSS (2026-09-01)

**Scope:** small, immediate follow-up to Milestone RRRR — the cases LIST
view (`CasesPage.tsx`) never showed the "Archived" badge the detail page
just gained, an easy inconsistency named in RRRR's own recommendation
list. Extending the check surfaced a real, previously-unknown bug along
the way.

## `CasesPage.tsx` — real "Archived" badge on the list card

Mirrors the detail page's own badge exactly (`CaseCard`, same
`bg-red-100`/`text-red-700` classes). Extended
`case-delete-archive-ui.spec.ts`'s existing flow to assert on it,
scoped to the specific case's own card by title (the dev stack's
`/cases` list already has other archived cases from unrelated prior spec
runs across this whole session — a bare page-wide `"Archived"` text match
would have proven nothing specific).

## A real, found-live bug: the list never refetched after archiving

The first live run of the extended assertion failed for a genuine
reason, not flakiness: right after `DeleteCaseSection`'s mutation
succeeds and navigates to `/cases`, the freshly-archived case's own card
still showed no badge. The cases list's `useQuery` has `staleTime: 30_000`
— the mutation's `onSuccess` only ever called `navigate()`, never
invalidated the `['cases']` query, so a `/cases` fetch already cached
within the last 30s (as it usually is, since the case-lead was just on
that page before opening the case) kept serving pre-archive data. The
archive itself worked correctly server-side the whole time — a *prior*
test run's own card, from outside the 30s window, already showed
"Archived" correctly in the same page snapshot that caught this,
confirming the feature itself was never broken, only this one path's
cache invalidation. Fixed with `queryClient.invalidateQueries({queryKey:
['cases']})` before the navigate call, mirroring the pattern
`CaseMembersSection`'s own mutations already used correctly for
`['case', caseId]`.

## Real verification

- `npx tsc -b`: clean. `npx oxlint`: 0 errors, 1 pre-existing unrelated
  warning. `npm run test` (vitest): 104/104 passed. `npm run build`:
  clean.
- Real rebuild + redeploy of `docker-nginx-1` (`docker compose build
  nginx && up -d nginx`) before each live check, same as RRRR's own
  established practice for UI changes.
- First live run of the extended spec: real, reproducible failure (the
  bug above), not flakiness — confirmed via the captured page snapshot
  showing a prior archived case's card correctly badged while this run's
  fresh one wasn't, isolating the cause to caching, not the underlying
  feature.
- Fixed, rebuilt, redeployed, re-ran: `1 passed (3.4s)`.
- Broader regression check (13 specs: the delete/members UI pair, both
  `case-delete-ownership-*` API-level specs, `case-lead-ownership-access-grant`,
  `login`, all 7 `a11y` tests): `13 passed (29.3s)`, no interference.

## Status

Closes RRRR's own small named follow-up, plus a real bug the follow-up
itself surfaced — the kind of thing this initiative's verification-first
discipline exists to catch (an untested code path silently shipping with
a real, user-visible staleness bug).

## Recommendation for the next cycle

RRRR's other named items remain open and unchanged: convenient user
discovery for adding a member, intake-retry test-stack CI-wiring,
`admin.py`/`KeycloakAdminClient` duplication.
