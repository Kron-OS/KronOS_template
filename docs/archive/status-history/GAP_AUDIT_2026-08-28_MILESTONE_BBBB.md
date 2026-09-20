# Gap Audit — Milestone BBBB (2026-08-31)

**Scope:** the fifth multi-scenario subagent assessment (security/
CI-reliability/coverage-gap — same pattern as Milestones EEE, KKK+LLL,
PPP, TTT, XXX) run against Milestones YYY, ZZZ, and AAAA's landed work.
One concrete security regression fixed (introduced by Milestone AAAA's
own fix), one cheap CI-reliability improvement applied, and — the main
event — RBAC/authz access-denial E2E coverage finally closed after being
carried, unclosed, across five straight milestones (OOO through AAAA).

---

## Fixed this cycle

### 1. `source.address` had no length guard — a real regression in Milestone AAAA's own fix (security review's own MEDIUM finding)

Milestone AAAA fixed a real bug where `CloudTrailParser` mapped AWS's
`sourceIPAddress` straight into OpenSearch's strictly `ip`-typed
`source.ip`, breaking on AWS-service-linked events. The fix added
`source.address` (`keyword`, no constraint) to always hold the raw value.
The security reviewer caught what that fix itself introduced: unlike
`event.original` (deliberately truncated to 32768 bytes AND mapped
`index: false` specifically to dodge Lucene's immense-term limit),
`source.address` had no `ignore_above` at all — a `sourceIPAddress` value
over ~32766 UTF-8 bytes would throw the exact same class of
`IllegalArgumentException` (immense term) the original fix was written to
eliminate, just via string length instead of type mismatch. A crafted or
malformed evidence file is a real, if narrow, path to reproducing the
same "permanent ERROR after Celery retries exhaust" failure.

**Fixed**: added `"ignore_above": 256` to `source.address`'s mapping
(`src/adapter/opensearch/index_template.json`) — comfortably covers any
real IP (max ~45 chars for IPv6) or real hostname (max 253 chars per RFC
1035) with headroom, matching Elasticsearch/OpenSearch's own default
`ignore_above` convention for keyword fields. `ignore_above` (not
`index: false`, event.original's own approach) is the semantically
correct fix here specifically because `source.address` is meant to stay
searchable for real, bounded values — `ignore_above` just stops indexing
(not storing) outlier-length values, which is exactly what's needed.

**Verified live, not assumed**: pushed the updated template to the real
dev OpenSearch and bulk-indexed a real 40,000-byte `source.address`
value (well over the old failure threshold) — `errors: False`, and a
follow-up `GET` confirmed the full value was still stored in `_source`
(nothing silently dropped, just not indexed past 256 chars). Re-ran the
real CloudTrail E2E spec afterward to confirm the legitimate short-value
case still works unaffected.

### 2. CI-reliability: disk/memory headroom snapshot added (cheap, docs-adjacent fix)

The CI-reliability review's own top finding: every other real-margin
claim in `security-integration-tests.yml` (`timeout-minutes`, the >5min
Plaso/Volatility build time) is backed by an actual local measurement;
disk/memory headroom on a real GHA runner never has been, despite the
job now doing 4 image builds plus pulling 5+ more (OpenSearch alone is
~2.3GB). Added a `df -h`/`docker system df`/`free -h` diagnostic step
right after the image-build step, `if: always()` — not a fix (a real
runner can't be measured from here), but ensures the first real GHA run
captures this data point instead of failing opaquely on ENOSPC/OOM with
no trail. The CI-reliability review's other findings (the "stale
template on cold CI start" hypothesis) were investigated and found to be
non-issues — documented below, not fixed, because nothing was broken.

### 3. RBAC/authz access-denial E2E coverage (the main event — closes a gap carried across 5 milestones)

Coverage-gap review's own top recommendation, and the only remaining
open gap that's a real security boundary (CLAUDE.md §A.6), not a UX/
resilience nicety. Every prior spec in this suite only ever proved a
*privileged* user succeeding; nothing had ever confirmed a real,
deliberately less-privileged user actually gets denied.

New `frontend/e2e/rbac-access-denial.spec.ts`, using a new
`casesPageAsAnalyst` fixture (`frontend/e2e/fixtures.ts`) — the first
time this suite has ever logged in as the dev-seeded `analyst` account
(it existed in `DEV_USERS` since this file's own creation but had never
actually been used). Real, confirmed premise (read directly from
`docker/keycloak/kronos-realm.json`'s own user→role assignments, not
assumed): `analyst` carries only `Role.ANALYST`, never
`Role.CASE_LEAD`/`Role.ORG_ADMIN`. `POST /api/cases`
(`src/external/routes/cases.py`) is gated
`requires_role(Role.ORG_ADMIN, Role.CASE_LEAD)` — a real, deterministic
403 case.

**Real, previously-unverified finding along the way**: `CasesPage.tsx`
has no frontend-side role gate on the "New Case" button/modal at all
(confirmed by reading the component, not assumed) — every authenticated
user, regardless of role, can open and submit the create-case form. The
real security boundary is enforced entirely server-side. This spec is
what actually proves that boundary holds end-to-end (not just that the
backend route handler has the right decorator) and that the frontend
surfaces the resulting real 403 as a visible, non-crashing error rather
than hanging.

New `CasesPage.attemptCreateCase()`/`waitForCreateCaseError()` page-object
methods (mirroring `CaseDetailPage.startUpload()`'s established "don't
assume success" pattern from Milestone QQQ). Also caught and fixed a real
assumption error before it shipped: the spec's first draft asserted on
Keycloak's default nested `realm_access.roles` JWT claim shape, but this
backend actually reads roles from a flat top-level `roles` claim
(`src/external/middleware/keycloak_auth.py`, AUTH-006 — OpenSearch
Security's `roles_key` can't walk nested paths) — caught by reading the
backend source before trusting the assertion, not by a failed test run.

Wired into `security-integration-tests.yml` right after
`cross-tenant-isolation` (same "no extra services needed" shape).
Verified live: passes alone (1.2-1.3s) and alongside `login.spec.ts`,
`evidence-upload.spec.ts`, `evidence-upload-fast-parsers.spec.ts` (7
tests total) with no interference.

## Documented, not fixed this cycle

### Security: otherwise clean

No exploitable findings beyond the `source.address` regression (now
fixed) across all three milestones. The `chrome_history/History` fixture
(Milestone YYY) was independently checked for real PII by extracting its
actual strings — only synthetic-looking URLs (Plaso's own test data,
already public, already committed elsewhere in this repo via
`kape_triage.zip`) were found, no real personal browsing history. The
`forensic2.E01` relocation (Milestone ZZZ) is a clean file move with no
hardcoded paths/credentials.

### CI-reliability: the "stale index template" hypothesis is a non-issue (investigated, not a false confidence claim)

Worth recording precisely because it was investigated and found NOT to
be a risk, not left as an open question: `ensure_index_template()` PUTs
the template body read fresh from disk on *every* call (no
create-if-missing, no caching), and `TimelineIngestionService` itself is
rebuilt fresh per Celery task — so a genuinely fresh GHA run has no
plausible path to an old template winning a race. The "restarted
celery-worker" step in Milestone AAAA's own verification was needed to
load the new Python code (no hot-reload), not because of template
staleness — a real, if minor, imprecision in that doc's own phrasing,
corrected here.

### Coverage-gap: Suricata's EVE fixture doesn't exercise `dns`/`tls` event types

Self-documented already in the fixture's own `NOTICE.md` — the closest
remaining analogue to the CloudTrail bug class, but honestly disclosed
as unavoidable without running real Suricata against a real pcap, and
the parser's `extra` field mapping is generic enough that no code change
is actually expected. Left open, not urgent.

## Status

Every finding from this assessment cycle that was concretely actionable
is fixed and verified live: a real security regression in the prior
cycle's own fix, a cheap CI diagnostic improvement, and — closing this
initiative's longest-carried open item — real RBAC/authz access-denial
coverage. The two items intentionally left undone were investigated
thoroughly enough to document *why* they don't need fixing, not left as
unexamined gaps.

## Recommendation for the next cycle

1. Broaden RBAC coverage beyond the one case-creation scenario — more
   role×action combinations (e.g. `admin`-only actions, `read_only`
   denials), and the `assert_case_access` ownership-qualifier path
   (`case-lead`/`analyst` restricted to owned/member cases) which is a
   *different* real security boundary from the pure role-check this
   cycle covered.
2. Intake-stage retry E2E coverage (carried since Milestone TTT).
3. `security-stack` also booting `kronos-backend`,
   `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8 (dashboards-embed/
   resilience/a11y).
4. Periodically re-check whether Milestone RRR's CI-never-ran finding has
   changed.
