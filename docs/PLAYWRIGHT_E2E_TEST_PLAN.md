# KronOS — Advanced Playwright E2E Test Plan

**Correction 2026-08-29 (Milestone RRR) — read before trusting any
"nightly CI"/"CI-wired" claim below or in Milestones KKK-QQQ's own
docs.** `.github/workflows/security-integration-tests.yml` has never
actually executed on GitHub Actions: it only exists on
`feat/nextgen-soc-cert-platform` (never merged to `main`), and GitHub
only evaluates a workflow's `schedule:` trigger from the file as it
exists on the repository's *default* branch — a hard platform
constraint, confirmed directly (`git show main:.github/workflows/security-integration-tests.yml`
fails; the GitHub API's workflow list for this repo doesn't include this
file at all). **This turned out not to be specific to this one
workflow**: every workflow in this repo (`build.yml`,
`integration-tests.yml`, `test.yml`) triggers only on `push`/
`pull_request` to `main` — none fire on push to
`feat/nextgen-soc-cert-platform` either, so no commit on this branch has
ever been checked by ANY of this repo's own CI. Every "CI now
runs/covers X" statement in this document and in the KKK-QQQ milestone
docs means "the job definition is real, correct, and locally verified
to work when run" — it does NOT mean an independent, automatic
confirmation has ever actually happened on GitHub's own infrastructure.
See `docs/GAP_AUDIT_2026-08-28_MILESTONE_RRR.md` for the full account
and what would actually close this (a manual `workflow_dispatch` against
this branch, or a merge to `main` — both outside this initiative's
current tooling/authority).

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_GGGG.md` for the latest
cycle** — closes a gap named since Milestone LLL: `security-stack` never
booted `kronos-backend`, so "both real Keycloak consumers coexist" was
never continuously re-proven in one stack instance. Now boots it for
real, then runs a new, honestly-scoped verification
(`poc/ci_security_enabled_stack/verify_backend_keycloak_coexistence.py`):
a real `client_credentials` grant for `kronos-backend`'s own service
account, then a real authenticated call to `kronos-backend` itself,
asserting on the *specific* `"JWT audience claim missing..."` 401 —
confirmed (by reading `keycloak_auth.py`) that this exact message only
fires after JWKS fetch + signature + issuer checks all succeed, so it's
genuine proof the two Keycloak consumers' configs are compatible, not a
generic pass. Real design pivot along the way: password grant (the
original plan, mirroring an older PoC) turned out to be disabled
realm-wide; PKCE would have needed nginx/TLS scaffolding duplicating
`frontend-e2e-smoke`'s own setup — landed on the service-account
approach instead, verified both its positive AND negative path live
(a malformed token produces a different, correctly-rejected message).

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_EEEE.md` for the prior
cycle** — closes the positive counterpart every prior RBAC spec deferred:
`rbac-access-denial`/`case-membership-access-denial`/
`case-lead-ownership-access-denial` each prove a real DENIAL; none
proves `assert_case_access`'s own ALLOW branch actually grants real
access once a real, successful `POST /api/cases/{id}/members` grant
lands. New `case-membership-access-grant.spec.ts`: `case-lead` grants
`analyst` (its real Keycloak `sub`, read off a fresh access token, not a
placeholder — confirmed from `keycloak_auth.py` that `add_case_member`
never does a server-side lookup) real membership, then a **fresh**
analyst session confirms genuine access — every response a real `200`,
the case title visible in the DOM, and a fresh independent `GET`
(new `CasesPage.fetchCaseById()`) confirming the grant persisted
server-side, not just within the granting session. Verified live
alongside 4 related RBAC specs, no interference. Every RBAC boundary
this initiative has named now has proof on both the denial AND the
grant side.

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_DDDD.md` for the prior
cycle** — closes Milestone CCCC's recommendation #2:
`assert_case_lead_or_admin`'s stricter "of case"/"own" qualifier, the
third distinct RBAC boundary this initiative has closed (after the pure
role check, Milestone BBBB, and the weaker owner-OR-member read-access
check, Milestone CCCC). The single static `case-lead` dev user can't
exercise this alone (whatever case it creates, it owns), so a new
`SecondCaseLeadSeeder`/`seed_second_case_lead.py` provisions a real,
second, throwaway case-lead account in the SAME org via the Keycloak
Admin API (reusing `seed_second_org.py`'s proven building blocks). New
`case-lead-ownership-access-denial.spec.ts`: the second case-lead
attempts `POST /api/cases/{id}/members` (no frontend UI exists yet — a
new `KronosPage.postJsonWithStatus()`/`CasesPage.attemptAddMember()`
issues the real API call directly) on a case owned by the FIRST
case-lead, and gets a real 403 — first confirming via the decoded JWT
that the second account genuinely carries `case-lead`, so the 403 is
provably `assert_case_lead_or_admin` rejecting, not `requires_role`
rejecting for lack of the role entirely. Verified live alongside 4
related specs, no interference; self-cleanup confirmed across two
consecutive runs.

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_CCCC.md` for the prior
cycle** — closes Milestone BBBB's recommendation #1: broadens RBAC
coverage beyond the pure role check `rbac-access-denial.spec.ts` proved,
to `assert_case_access`'s ownership/membership qualifier (AUTH-007) — a
real, distinct security boundary from both the role check AND
`cross-tenant-isolation.spec.ts`'s different-org 404 (confirmed directly
from the route source: an org-scoped repository lookup runs first, only
THEN `assert_case_access`, so a same-org non-member gets a genuinely
different code path and status than a cross-org caller). New
`case-membership-access-denial.spec.ts`: `case-lead` creates a case,
`analyst` (same org, never added as a member) navigates directly to its
URL, asserts every real response is `403` (not `404`, not `200`) and no
leak of the case title into the denied caller's DOM — mirroring
`cross-tenant-isolation.spec.ts`'s own established network-watching
pattern. Verified live alongside 3 related specs, no interference. The
positive-membership-grants-access counterpart was investigated and
deliberately deferred (no existing UI surface to drive it, would need
new setup machinery) rather than built as a rushed stretch addition.

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_BBBB.md` for the prior
cycle** — the fifth multi-scenario subagent assessment (security/
CI-reliability/coverage-gap), against Milestones YYY-AAAA. One real
security regression fixed: Milestone AAAA's own `source.address` field
had no `ignore_above` length guard, unlike `event.original`'s deliberate
truncation — a crafted oversized value could reproduce the exact
"permanent ERROR sink" failure that fix was meant to eliminate, just via
string length instead of type mismatch; fixed with `ignore_above: 256`,
verified live with a real 40,000-byte value against the dev OpenSearch
(`errors: False`, value still stored, just not indexed past 256 chars).
Added a disk/memory headroom diagnostic step to
`security-integration-tests.yml` (cheap CI-reliability improvement — no
prior real-runner measurement existed for this, unlike every other
margin claim in that job). **Main event**: closed RBAC/authz
access-denial E2E coverage, carried unclosed across five straight
milestones (OOO→AAAA) — the only remaining gap that's a real security
boundary. New `rbac-access-denial.spec.ts` + `casesPageAsAnalyst`
fixture confirms a real, deliberately-less-privileged `analyst` user
gets a genuine 403 attempting case creation, and that the frontend
surfaces it visibly (confirmed along the way: `CasesPage.tsx` has NO
frontend-side role gate at all — the security boundary is 100%
server-side, now actually proven end-to-end). Caught and fixed a real
assumption error before shipping: the JWT role claim isn't Keycloak's
default nested `realm_access.roles`, it's a flat top-level `roles` claim
(AUTH-006) — caught by reading backend source, not a failed test run.

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_AAAA.md` for the prior
cycle** (first 4-letter milestone slug, `AAA`-`ZZZ` exhausted) — closes
Milestone ZZZ's recommendation #1: swap `evidence-upload.spec.ts`'s
synthetic CloudTrail fixture for the real
`tests/fixtures/samples/real/aws_cloudtrail.jsonl` sample, flagged as a
cheap rigor-only follow-up. It surfaced a real, previously-unknown,
previously-latent bug instead: `CloudTrailParser` mapped AWS's own
`sourceIPAddress` straight to ECS's strictly `ip`-typed `source.ip`, but
AWS-service-initiated CloudTrail events (this fixture's own real
`SharedSnapshotVolumeCreated` row) document that field as the calling
service's *hostname*, not an IP — a real `mapper_parsing_exception`
permanently sank the evidence to `ERROR` after Celery's retries
exhausted, confirmed via direct reproduction against the live dev
OpenSearch. Fixed per ECS's own convention for this exact ambiguity:
always populate `source.address` (new `keyword` field in
`index_template.json`) with the raw value, only additionally populate
`source.ip` when it actually parses as a real IP (`ipaddress` stdlib).
Verified at every step (direct bulk-index reproduction before AND after
the fix, a targeted null-value-safety check against the live cluster
before relying on it, worker restart + real E2E re-run, a 6-test FAST-tier
regression, plus a new permanent regression test against the fixture's
real row). This bug had been latent since `CloudTrailParser` shipped —
existing unit tests only ever exercised `parse()`, never the real
OpenSearch write path.

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_ZZZ.md` for the prior
cycle** — closes Milestone YYY's recommendation #1: `TarArchiveParser`
CI-wired coverage. `poc/tar_container_unwrapping/`'s own real,
reproduced-incident fixture (`forensic2.E01` — actually a tar archive,
deliberately misnamed to match the real incident that motivated
`TarArchiveParser`'s existence) predates this initiative and was never
cited in any of Milestones UUU-YYY's "HEAVY-tier now covered" claims.
Relocated the fixture to `tests/fixtures/samples/real/tar_container/`
(matching this repo's established convention, `git mv` preserving
history) and added a 3rd test to `evidence-upload-heavy-parser-archive.spec.ts`.
Verified live: all 3 tests in that spec pass, and the new test's real
`record_count: 20` was cross-checked directly against
`celery-worker-plaso`'s own logs (matching
`poc/tar_container_unwrapping/verification.json`'s own already-documented
figure), not just a green checkmark. Every HEAVY-tier parser this repo
ships now has real, CI-wired browser E2E coverage (Volatility's own
512 MiB fixture remains the one deliberate, documented exception — a
backend-only `poc/` script, Milestone WWW). **Note for future cycles**:
this is the last available triple-letter milestone slug (`AAA`-`ZZZ`);
the next new milestone should move to a 4-letter scheme (`AAAA`, ...).

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_YYY.md` for the prior
cycle** — closes Milestone XXX's coverage-gap review's own top
recommendation: three straight cycles (UUU/VVV/WWW) gave every
HEAVY-tier parser real, dedicated E2E coverage and left FAST-tier
parsers (the platform's actual highest-volume real-world path)
comparatively unverified. New `evidence-upload-fast-parsers.spec.ts`
(4 tests: evtx-rs, nginx, suricata-eve, chrome-history, all real
fixtures) closes that gap — CloudTrail was already covered. New fixture
`tests/fixtures/samples/real/chrome_history/History`, extracted
byte-for-byte from the already-committed `kape_triage.zip`'s own Chrome
History member (the one FAST-tier parser with no existing standalone
real fixture). Also restated the `timeout-minutes: 70` justification
comment to cite the archive spec's real 330s worst-case ceiling instead
of its ~35s typical-case figure (Milestone XXX CI-reliability finding
#1). Verified against the live dev stack (not a fresh isolated
test-stack build) given genuinely tight host memory headroom going into
this cycle — the same judgment call Milestone WWW already established;
all 4 new tests plus 2 adjacent specs passed clean, back to back.

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_XXX.md` for the prior
cycle** — the fourth multi-scenario subagent assessment (security/
CI-reliability/coverage-gap), against Milestones UUU-WWW. Security:
clean. One HIGH-severity, concrete fix: `docker-compose.prod.yml` had no
`celery-worker-plaso` at all — `q.parse.plaso` (every HEAVY-tier parser:
Plaso, archive/EWF container recursion, Volatility) had zero consumer in
**production**, the one profile that actually matters, even though
UUU/VVV/WWW's own coverage claims only ever verified `test.yml`/`.dev.yml`.
Deeper than a missing compose block: `.github/workflows/build.yml` never
built/published an image from `docker/Dockerfile.plaso-worker` at all —
fixed by matrixing `trivy-scan`/`push-image` over `{backend,
plaso-worker}` so both images go through the same scan/SBOM/sign/attest
pipeline, then adding the new service to `docker-compose.prod.yml`,
field-for-field mirroring `celery-worker`'s own already-audited required-
`Settings` set. Verified: `docker compose -f docker-compose.prod.yml
config -q` passes with the new service's resolved fields inspected
directly, and `docker build -f docker/Dockerfile.plaso-worker .`
(the exact repo-root-context invocation `build.yml`'s matrix now uses)
confirmed to build. Four CI-reliability findings and four coverage-gap
findings documented for upcoming cycles — most notably that three cycles
focused on closing HEAVY-tier gaps left FAST-tier parsers (evtx,
suricata, nginx, chrome_history standalone) as the platform's now
*least*-verified tier by comparison.

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_WWW.md` for the prior
cycle** — closes Milestone VVV's own recommendation #1: the last
HEAVY-tier (`q.parse.plaso`) parser with zero full-pipeline verification,
`VolatilityModule` (real memory-forensics via `volatility3`). New
`poc/volatility_pipeline_ingest/` (backend-only, not a frontend E2E spec
— VolatilityModule has no frontend read surface at all, intentional per
`CLAUDE.md` §G.2) drove the real, complete autonomous pipeline against
the dev stack: real login → case → 512 MiB `cridex.vmem` upload →
`finalize_upload` → real Celery `q.intake`/`q.parse.plaso` →
`VolatilityModule.extract_artifacts()` (real `volatility3` subprocess) →
`ArtifactIngestService` → real Postgres `structured_artifacts` rows,
verified by querying Postgres directly (no HTTP read API exists for
`StructuredArtifact` yet). Real result: 2 rows (`volatility.pstree`
correctly empty, `volatility.psscan` with 17 real process rows, matching
the earlier isolated-verification PoC's own already-documented finding),
full provenance match. Hit and fixed a real, recurring friction point
(expired step-ca leaf cert) along the way. Every HEAVY-tier parser this
repo has now has real, captured, full-pipeline verification — closing
the arc Milestone PPP first opened. Not wired into CI (the real fixture
is 512 MiB, deliberately never committed, same reasoning as the earlier
isolated PoC).

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_VVV.md` for the prior
cycle** — closes Milestone UUU's own recommendation #1: real browser E2E
coverage for the two remaining HEAVY-tier (`q.parse.plaso`) code paths,
`ZipArchiveParser`'s real container recursion (a real KAPE-shaped zip,
4 real inner parsers) and `PlasoParser`'s EWF/E01 whole-image routing (a
real FAT16 disk image, 414 real events in prior backend-only
verification) — both fixtures already existed and were already verified
backend-only (`poc/kape_ingestion_test/`), just never driven through a
real browser upload before. New `evidence-upload-heavy-parser-archive.spec.ts`,
wired into CI as a 9th step. Along the way, found and fixed a real,
previously-unknown, live-verified bug: `POST /api/cases` directly
`await`ed both its dashboards-index-pattern and Security-Analytics
detector provisioning calls, contradicting both call sites' own "must
not block case creation" comments — a real backend log showed the
"windows" detector's own create call exceeding its 15s httpx timeout,
hanging the entire case-creation HTTP response for 15+ seconds, caught
because it directly broke this cycle's own new spec. Fixed with FastAPI
`BackgroundTasks` (both provisioners are self-contained, safe to run
after the response is sent); verified live — case creation across every
spec in a full 10-test regression became near-instant. Confirmed
(by grepping every route and frontend component) that VolatilityModule's
`StructuredArtifact` output has no frontend surface at all yet, but this
is intentional per `CLAUDE.md` §G.2, not a gap to rush to fill.

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_UUU.md` for the prior
cycle** — closes the heavy-parser CI coverage gap carried since
Milestone PPP and named again in Milestone TTT's own recommendation #1:
`docker-compose.test.yml` had no consumer for `q.parse.plaso` at all, so
a real `ParserType.HEAVY` upload (Plaso, archive EWF/ZIP routing,
VolatilityModule) would sit in `RECEIVED`/`PARSING` forever in CI with
zero error. Added `celery-worker-plaso` (mirroring the dev-profile
service), a new `evidence-upload-heavy-parser.spec.ts` exercising a real
Windows 10 prefetch sample through the real Plaso subprocess end-to-end
to `Complete`, and wired both into `security-integration-tests.yml`
(`timeout-minutes: 55 → 70`, grounded in the measured >5min Plaso image
build). Verified live: confirmed real Plaso execution and 5 extracted
timeline records in worker logs, not just a passing green check. Two
real issues surfaced during verification, both documented honestly
rather than hidden: a corrected setup mistake (forgot the pre-existing
`celery-worker` service, needed for intake/dispatch before a task ever
reaches `q.parse.plaso`), and one unreproduced transient
`evidence-upload.spec.ts` failure (could not reproduce after
investigation; most likely host resource contention, not a regression —
flagged for anyone who sees it recur). Coverage is still Plaso-only;
archive/Volatility HEAVY-tier paths sharing the same queue remain
untested end-to-end.

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_TTT.md` for the prior
cycle** — third multi-scenario subagent assessment (security/
CI-reliability/coverage-gap), against Milestones QQQ-SSS. Two real fixes:
`ContainerFaultInjector.ensureRunning()` never actually waited for
health before returning (only checked `.State.Status`), a genuine gap
in the shared restore-safety mechanism every fault-injection spec
relies on — fixed and verified by running the exact declared CI step
order (`evidence-upload-storage-outage` immediately followed by
`evidence-parse-retry`) back-to-back for real. Also committed
`docker/docker-compose.test.local-verify.override.yml`, a documented,
reusable local-verification override — closing the exact recurring
process risk that caused Milestone OOO's incident and recurred in
Milestone SSS (a fresh throwaway override each cycle, missing a port
publish). `timeout-minutes` re-derived (not just re-bumped) from the two
fault specs' own real worst-case ceilings. Security: clean. Two new
real coverage gaps documented (intake-stage retry has zero E2E coverage;
no spec covers two simultaneous dependency failures or a degraded-not-down
dependency) for the next cycle.

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_SSS.md` for the prior
spec-coverage cycle** — `frontend-e2e-smoke` now runs all 7
`frontend/e2e/` specs. New `evidence-parse-retry.spec.ts` (test-stack
profile, via new `TestStackOpenSearchFaultInjector`) is the test-stack
analogue of `evidence-retry.spec.ts`, completing error/retry coverage
for both failure shapes (MinIO upload-request, OpenSearch parse-stage)
on both compose profiles. Verifying it hit a real methodology near-miss
worth remembering: several other specs briefly looked broken when
re-run afterward, but it was this cycle's own local-verification stack
missing Postgres/Keycloak port publishing — the exact class of
self-inflicted false positive Milestone OOO's incident was about — caught
immediately via the specific error messages this time, not chased as a
phantom bug.

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_QQQ.md` for the prior spec-coverage cycle**
— `frontend-e2e-smoke` now runs all 6 `frontend/e2e/` specs, the entire
existing suite. New spec `evidence-upload-storage-outage.spec.ts`
(test-stack profile, via new `TestStackFaultInjector`) closes the
"only happy-path coverage" gap Milestone PPP flagged. The originally
suggested approach (mirror `evidence-retry.spec.ts`'s OpenSearch-outage
pattern but for MinIO/`q.intake`) turned out not to transfer directly —
MinIO sits in the upload's own first synchronous step, unlike
OpenSearch, so a genuinely reliable test targets a different, real,
fully-deterministic failure shape (storage down from the start of the
upload attempt) instead of forcing a race. Investigating it live found
a real, previously-shipped bug: `UploadDrawer.tsx` never cleared a
file's stale error text on a successful retry, so a user who fixed the
underlying problem and clicked Upload again would see "Request failed
with status code 500" forever even though the upload had genuinely
succeeded. Fixed and verified live. Also extracted a shared
`ContainerFaultInjector` base class (`DevStackFaultInjector` and the new
`TestStackFaultInjector` both extend it) per this initiative's own
lesson from Milestone PPP — create the shared module at the *second*
instance of a pattern.

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_PPP.md` for the prior cycle**
— second multi-scenario subagent assessment (security/CI-reliability/
coverage-gap) of Milestones MMM-OOO's landed work. Two structural fixes:
a shared `frontend/e2e/fixtures/_e2e_env.py` config module (both
`seed_detection.py` and `seed_second_org.py` had independently
duplicated the same env-var-override pattern — exactly the class of gap
that caused Milestone OOO's incident — now consolidated so a third
fixture script can't repeat it), and `frontend-e2e-smoke`'s bundled
5-spec CI step split into 5 separate named steps with `if: always()`
for real per-spec failure attribution instead of one buried
list-reporter block. Security review: clean, no exploitable findings.
Three real, larger-scope gaps newly documented for the next cycle:
heavy parsers (`PlasoParser` etc.) are structurally unexercised by any
CI path, only happy-path error/retry coverage exists, and RBAC
access-denial paths remain zero-coverage (already tracked).

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_OOO.md` for the prior cycle**
— wired `cross-tenant-isolation.spec.ts` into `frontend-e2e-smoke`,
completing all viable existing specs (5 of 6; `evidence-retry.spec.ts`
remains deliberately unwired, see Milestone LLL). A real, cautionary
debugging account: what looked exactly like Keycloak silently deleting
freshly-created users within ~1 second turned out to be a much simpler
cause — `seed_second_org.py` was missing the same
`KRONOS_E2E_KEYCLOAK_URL` override its sibling `seed_detection.py` got in
Milestone NNN, so local verification was silently creating fixtures on
the **live dev stack's** Keycloak while checking the isolated test-stack
instance. Fixed (one line, same pattern as the sibling script), verified
by printing the resolved constant before trusting it again, and all five
now-relevant specs confirmed passing together. The live dev stack's
accidental fixture debris was cleaned up using the script's own
`cleanup_stale_fixtures()` function, not an ad hoc delete.

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_NNN.md` for the prior cycle**
— wired `detection-triage.spec.ts` and `detection-triage-race.spec.ts`
(pure Postgres/OpenSearch CRUD, no Celery) into `frontend-e2e-smoke`.
Found one real, confirmed blocker before either could run against
`docker-compose.test.yml` for the first time: their shared
`DetectionSeeder` fixture's underlying Python script
(`seed_detection.py`) hardcoded the DEV stack's own Postgres DSN
(different password AND database name from the test profile) and
default org alias (`kronos-dev` vs. this profile's own
`kronos-test`). Fixed with env-var overrides
(`KRONOS_E2E_POSTGRES_DSN`/`KRONOS_E2E_SEED_ORG_ALIAS`/`KRONOS_E2E_KEYCLOAK_URL`),
matching the pattern already established by `KRONOS_E2E_PYTHON`. Also
added the CI job's first-ever Python setup step (`actions/setup-python` +
`pip install -e ".[dev]"`), since these fixture scripts run on the
runner directly, not inside a container. All four now-wired specs
(login, evidence-upload, detection-triage, detection-triage-race)
verified passing together against a freshly-built isolated stack.

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_MMM.md` for the prior cycle**
— wired `evidence-upload.spec.ts` (the first flow-tier spec) into
`frontend-e2e-smoke`, needing `celery-worker` added to that CI job.
Running it for the first time against `docker-compose.test.yml` surfaced
**six real, previously-undiscovered bugs** that meant NO real evidence
upload could ever have completed in this profile before now: three
`MinIO` env-var mistakes (a full-URL-vs-bare-host format bug that crashed
every real MinIO call, `MINIO_USE_TLS` defaulting to a scheme this
profile's plain-HTTP MinIO doesn't speak, a missing browser-facing
`MINIO_PUBLIC_ENDPOINT`), nginx never publishing MinIO's dedicated `:9444`
port or setting its CSP `connect-src` for it, MinIO having no CORS
configuration for the genuinely cross-origin presigned PUT, and — the
most severe — `celery-worker` never consuming the `q.intake` queue the
current intake pipeline actually uses, meaning every real upload would
have sat in `UPLOADING` forever with zero error anywhere. All six fixed
and verified via a real upload reaching `Complete` over live SSE, then a
full mirror of the exact final CI job sequence run fresh end to end.

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_LLL.md` for the prior cycle**
— multi-scenario subagent assessment (security/CI-reliability/coverage-gap)
of Milestone JJJ+KKK's landed work. Fixed two real, cheap findings: a
previously-unguarded safety-rule risk in `DevStackFaultInjector.ts`
(hardcoded dev-stack container name, now asserts the Compose project
label before acting) and several `frontend-e2e-smoke` CI-reliability gaps
(timeout-cancelled jobs were silently skipping failure diagnostics,
`--reporter=list` was dropping the configured HTML report, log capture
was too thin across 9 services). Documented, not yet fixed: the exact
refresh-token race Milestone III fixed isn't re-exercised by CI,
`security-stack` never boots `kronos-backend` so the "both consumers
coexist" claim isn't itself continuously re-proven, and wiring in the
next flow-tier spec needs `celery-worker` + Python-fixture tooling this
job doesn't yet set up.

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_KKK.md` for the prior cycle**
— wired a new `frontend-e2e-smoke` job into
`.github/workflows/security-integration-tests.yml` (nightly + manual
dispatch, same as the existing `security-stack` job): builds the real
frontend, brings up the full `docker-compose.test.yml` profile, and runs
the real, unmodified `login.spec.ts` against it. Verified by locally
re-running the exact same step sequence (fresh `npm ci`, fresh
`playwright install --with-deps`, the real spec) against a freshly-built
isolated stack before committing. `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §4's
prerequisite is now fully closed, both halves.

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_JJJ.md` for the prior cycle**
— folded Milestone HHH's proven `tls-init`/`nginx`-build/
`opensearch-dashboards`-stub PoC pieces into the real
`docker/docker-compose.test.yml` permanently (Milestone III's own
recommendation #1). Found and fixed two more real bugs while
re-verifying: dead `KEYCLOAK_ISSUER`/`KEYCLOAK_JWKS_URL` env vars on
`kronos-backend` (never read by the actual code), and a real
`kronos-backend` `/auth/refresh` failure (`REFRESH_TOKEN_ERROR "Invalid
token issuer"`) caused by `KC_HOSTNAME` being left unset — fixed by
pinning it (mirroring `docker-compose.dev.yml`'s already-proven config),
which in turn required fixing `tests/integration/
test_security_enabled_stack.py` and `poc/ci_security_enabled_stack/
verify_security_stack.py` to read Keycloak's real issuer from its own
discovery document instead of assuming it equals `KRONOS_SECURITY_STACK_KC_BASE`.
Verified for real: a real browser PKCE login + `/auth/refresh` round trip,
the real unmodified `login.spec.ts`, and the real pytest security-stack
suite (3/3) all pass together against the same stack.

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_III.md` for the prior cycle**
— root-caused and fixed Milestone HHH's one open item: a real (not
timing-artifact) frontend bug where two independent, uncoordinated
`/auth/refresh` callers (`api/client.ts`'s 401 interceptor and
`keycloak.ts`'s own silent-refresh timer) could race Keycloak's real
refresh-token rotation, and the loser forced a real, valid session
through an unwanted full re-login. Fixed with a shared single-flight
promise in `keycloak.ts`; verified via a new unit test locking in the
mechanism plus a full, green six-spec E2E regression.

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_HHH.md` for the prior cycle**
— real PoC (`poc/test_stack_frontend_https/`) got `frontend/e2e/`'s real
PKCE login + navigation working against `docker-compose.test.yml` over
genuine HTTPS, finding and fixing 5 real bugs along the way. Also
promoted a real, separate, permanent fix into the shared file:
`kronos-backend`/`celery-worker` had never fully booted there at all
(6 missing required `Settings` fields — `celery-worker` couldn't boot at
all, `kronos-backend` silently 500'd on every real `/auth/refresh` call).
One precise item still open: a reproduced (not flaky) refresh-token race
on the PoC's own final assertion, not yet root-caused.

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_GGG.md` for the prior cycle**
— corrected a stale claim this plan (and PROGRESS.md) had carried since
its first research pass: the "`docker-compose.test.yml` has no
OpenSearch-security/Keycloak scaffolding" gap was already closed by an
unrelated prior session (commit `ba91a24`) before this initiative even
started, and is already CI-wired (nightly). Re-verified live, 3/3 real
tests still pass today. What's genuinely still missing is narrower and
now precisely scoped in §0/§4 below.

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_FFF.md` for the prior cycle**
(closed the maintainability findings + §3.5 cross-tenant isolation,
completing E2E delivery-order item 4 — but also documents a real incident
worth reading before touching the dev Keycloak by hand: an ad hoc cleanup
command run outside the proper fixture script briefly deleted every real
user in the realm, fully recovered, full account in that file's Part 2).

**See `docs/GAP_AUDIT_2026-08-28_MILESTONE_EEE.md` for the full account of
this cycle's multi-scenario subagent assessment** (security, maintainability,
adversarial coverage-gap review) run once items 2-4 below landed, including
a real concurrent-triage-race bug found and fixed
(`ConcurrentModificationError`, 409 not 503), a real Compose
project-name-collision security finding (fixed: explicit `name:` in all
three compose files — with a loud operator warning in
`docker-compose.dev.yml` about the already-running legacy-named stack),
and three maintainability findings, of which the cheapest
(page-object duplication + missing E2E toolchain docs) was closed the
same day as a follow-up cycle: `KronosPage` gained shared
`getFreshAccessToken()`/`fetchJson()`/`pollLiveText()` helpers (removing
duplicate token-fetch blocks from `CasesPage`/`DetectionDetailPage` and
generalizing `watchEvidenceStateLive`'s reactively-bolted-on `seedState`
guard so `DetectionDetailPage.watchTriageStateLive` gets it for free
instead of the previous unguarded inline `expect.poll`), and
`frontend/e2e/README.md` now documents the Python-toolchain prerequisite
`DetectionSeeder.ts` depends on. Suite runtime scaling and the TS+Python
toolchain-consolidation question remain open — see the milestone doc.

**Status (updated 2026-08-28, Gap Audit continuation):** partially proven,
not yet a maintained suite. Correcting this doc's own earlier "nothing
implemented yet" claim — untrue as of this update. Between this plan being
written and now, **six separate real-browser (Python Playwright) passes
already ran against the real dev stack** and proved most of §3's flow-tier
scenarios work at least once: `poc/keycloak_browser_login/` (real PKCE
login/logout), `poc/evidence_sse_realtime/browser_verify.py` (real upload →
live SSE status flip), `poc/detection_containment_ui/` (real step-up MFA
with real TOTP), `poc/detection_risk_score_ui/` (real triage UI),
`poc/evidence_download_ui/` (real download round-trip, hash-verified),
`poc/dashboards_embed/autoload_verification/` (real Dashboards iframe
embed, zero-click autoload). One more, `poc/frontend_theme_fix/`, used a
real browser but a **mocked** backend/auth harness — do not cite it as
end-to-end evidence for anything auth-related.

The maintained `frontend/e2e/` suite §1 below describes now exists and has
its first real, passing spec (§5 item 1, done) — this closes the "no
maintained suite" gap structurally, though only one of §3's many scenarios
is covered so far; the rest of §5's delivery order is still open. Before
this suite existed, all six real passes above were scattered, one-off
scripts, several of them fighting the same recurring friction (see the new
§0.1) independently instead of sharing
fixtures. This update's job is to promote that proven-but-scattered
coverage into the real suite, per §5's own delivery order, still following
CLAUDE.md's §F verification-first / OOP discipline: pin the real version,
build the smallest real thing first, capture real output, only then grow
the suite.

## 0. Where this starts from (verified facts, not assumed)

- `playwright` (Python) **1.61.0** is installed in this host's venv with
  `chromium-1228` cached and working — this is what all six real passes
  above actually used. **`@playwright/test` (the TypeScript runner) is a
  different story**: `frontend/package.json` lists a bare `playwright`
  (not `@playwright/test`) devDependency added incidentally by
  `frontend_theme_fix` — **but `frontend/node_modules/playwright` does not
  exist on a fresh checkout**, no `playwright.config.*` exists anywhere,
  and no `frontend/e2e/` directory exists. That `package.json` entry is
  dead weight, not a working install — §1 replaces it with a real,
  verified one rather than building on top of it.
- Real pages that exist today (`frontend/src/pages/`): `LoginPage`,
  `CasesPage`, `CaseDetailPage`, `DetectionsPage`, `DetectionDetailPage`,
  `AdminPage`. Real components: `UploadDrawer`, `EvidenceDetailDrawer`,
  `RbacGuard`, `AuthGuard`, `StatusPill`/`TriageStatePill`,
  `ErrorCatalogue`. **Correction: `UploadDrawer` is NOT Uppy/TUS** despite
  this doc previously saying so and `@uppy/*` sitting in `package.json`
  dependencies — `grep -rn uppy frontend/src` returns zero matches. The
  real, shipped mechanism is hand-rolled: client-side magic-byte + SHA-256
  pre-check, `POST /api/evidence/upload/request` for a single presigned
  PUT URL, a raw `XMLHttpRequest` PUT of the whole file, then
  `finalizeUploadWithHash()`. Six real-browser PoCs have exercised this
  exact real path successfully — treat the Uppy dependencies in
  `package.json` as unused residue, not as documentation of how upload
  actually works.
- Auth is real Keycloak 26.2 (`keycloak-js`), PKCE, with real step-up
  (aal2/TOTP) for privileged actions — any E2E suite touching admin/triage/
  destructive actions must drive the real step-up flow, not bypass it.
- **Correction 2026-08-28 (Milestone GGG) — this section previously said
  `docker-compose.test.yml` "disables the OpenSearch security plugin and
  has no step-ca/kronos.local/keycloak-init scaffolding," citing I1's
  investigation. That claim was already stale when this plan was
  written**: commit `ba91a24` (`feat(ci): V3 -- CI-realistic
  security-enabled test compose profile`, Gap Audit P1-14), predating
  this whole frontend-connectivity initiative, had already closed it —
  `docker-compose.test.yml`'s OpenSearch security plugin is genuinely
  enabled, real Keycloak org provisioning runs
  (`opensearch-init`/`keycloak-init`), and
  `.github/workflows/security-integration-tests.yml` already exercises
  the real profile against `tests/integration/test_security_enabled_stack.py`
  — deliberately **nightly + manual-dispatch, not per-PR** (a documented,
  reasoned scoping choice in that workflow file's own comments: tax
  proportionality, untested-locally GHA cold-pull risk, matching this
  initiative's own "verify locally now, CI wiring as an explicit scoped
  follow-up" precedent — not an oversight). Re-verified live, for real,
  this same day: brought the exact profile up in an isolated,
  port-remapped project (`kronos-test`, never touching the running dev
  stack), ran `opensearch-init`/`keycloak-init`/`provision_ci_org_b.py`,
  then `pytest tests/integration/test_security_enabled_stack.py` — 3/3
  passed, confirming this still works today against the current
  codebase (including this initiative's own recent
  `ConcurrentModificationError` changes). **What §4 below actually still
  needs, now correctly scoped and smaller than originally stated**: the
  OpenSearch-security/Keycloak-org-provisioning half of the original
  claim is closed, real, and CI-wired (nightly). What's genuinely still
  missing — see §4 for the full, precise account — is that
  `docker-compose.test.yml`'s `nginx` service never builds/serves the
  frontend SPA at all (API-proxy-only, no `Dockerfile.frontend`), plus no
  `kronos.local`/TLS scaffolding and a build-time-baked
  `VITE_KEYCLOAK_URL`. None of this blocks the backend-only integration
  test above; all of it blocks running `frontend/e2e/` against this
  profile.

### 0.1 Recurring friction found independently by 3+ of the six real passes (fix once, in shared fixtures, not per-spec)

- **`kronos.local`'s step-ca leaf cert has a 24h TTL** and had expired mid
  session for both `poc/keycloak_browser_login/` and
  `poc/detection_containment_ui/`, each independently working around it
  with `docker compose ... up -d tls-init && docker restart docker-nginx-1`.
  A maintained suite needs a shared pre-flight fixture that checks/refreshes
  this once, not N specs rediscovering the same expired-cert error.
- **Org IDs churn across dev-stack recreations** (`poc/detection_risk_score_ui/README.md`
  flags this explicitly) — any fixture must resolve `org_id` live via the
  Keycloak Admin API at setup time, never hardcode a value copied from a
  previous session.
- **TOTP secrets are reusable** — `case-lead`'s real enrolled TOTP secret
  from `poc/detection_containment_ui/case_lead_totp_secret.txt` avoids
  re-enrolling on every run; a shared fixture should read/seed this once
  rather than each spec re-deriving it.

## 1. Framework choice: `@playwright/test`, not more Python scripts

**Decision: adopt `@playwright/test` (TypeScript) in `frontend/`, in a new
`frontend/e2e/` directory, as the maintained E2E suite. Keep
`poc/evidence_sse_realtime/browser_verify.py`-style Python scripts for what
they're good at (a one-off, throwaway verification during a bug-hunt) —
they are not a substitute for a suite that runs on every change.**

Why not keep extending the Python pattern:
- `@playwright/test` gets test isolation (fresh browser context per test),
  parallelization, trace/video-on-failure, and HTML reporting for free —
  all real, maintained-suite necessities the hand-rolled `check()`/`PASS`/
  `FAIL` pattern in `browser_verify.py` doesn't provide.
- It lives next to the frontend it tests, in the same TypeScript project,
  so it can import real frontend types (e.g. the `OrgSettings`/
  `EvidenceOut` interfaces) instead of re-deriving field-name contracts by
  hand — the exact class of bug (`evidenceId` vs `evidence_id`) that
  `browser_verify.py` was built to catch in the first place.
- CI-friendliness: `npx playwright test` is the standard, well-documented
  GitHub Actions integration; a Python-script suite would need its own
  bespoke runner/reporter.

Concretely: `npm install -D @playwright/test` (pin whatever the real
current 1.6x release is at implementation time — don't assume, check
`npm view @playwright/test versions` against the already-installed Python
1.61.0 so browser binary versions don't drift between the two), then
`npx playwright install --with-deps chromium` (start with one real browser,
add firefox/webkit only if a real cross-browser bug is ever found —
speculative multi-browser coverage is not worth the CI time cost up front).

## 2. Layered proof discipline (mirrors roadmap §2, applied to E2E)

Not every test is worth writing at the same depth. Three tiers:

- **Smoke (L1-shaped):** does the app boot, can a real user log in, does
  the shell render. Fast, run on every PR.
- **Flow (L2/L3-shaped):** a real, complete user journey against the real
  backend + real Keycloak + real OpenSearch/Postgres/MinIO (`docker-compose
  .dev.yml`, not a mocked API layer) — evidence upload to COMPLETE,
  detection triage, admin user management. These are the heart of the
  suite and should be the majority of test count.
- **Adversarial/isolation (L4-shaped):** two real tenants, one browser
  context each, proving the UI itself never leaks cross-tenant data —
  the browser-level analogue of `poc/global_l4_e2e/`'s own backend-level
  isolation assertions. Fewer of these, but non-negotiable given how
  central tenant isolation is to this platform (roadmap invariant #3).

## 3. Concrete test scenarios (the actual "advanced" list)

Grouped by area; each bullet is one real spec file's worth of scope, not
one test — a `describe` block, several `test()`s inside.

### 3.1 Auth & session
- Real PKCE login (happy path) → lands on `CasesPage`, real JWT claims
  reflected in the UI (org name, role-gated nav items via `RbacGuard`).
- Real step-up challenge: an aal1-only session attempting a privileged
  action (e.g. triage, admin user removal) gets the real step-up prompt;
  completing real TOTP unlocks it; a second attempt without re-entering
  TOTP is correctly one-shot (mirrors the backend's own ticket
  one-shot-consumption invariant, proven at the UI layer this time).
- Session expiry / token refresh mid-session (real short-lived token,
  wait for real expiry, confirm the UI's `axios` refresh-interceptor path
  works rather than silently logging the user out or looping).
- Logout clears real client-side state (no case/evidence data visible
  after logout+back-button).

### 3.2 Evidence lifecycle (the platform's core loop)
- Real case creation → real file upload via the actual `UploadDrawer`
  (hand-rolled presigned-PUT, not Uppy — see §0) → **no manual reload** → `StatusPill` transitions
  live via real SSE, UPLOADING → ... → COMPLETE (this is exactly what
  `browser_verify.py` proved once by hand; promote it into the suite so a
  future regression is caught automatically, not by another bug report).
  Fixture: a small real EVTX/CloudTrail sample already in
  `tests/fixtures/samples/`, not a synthetic blob.
  - Not part of this test's own assertions, but note the fixture choice
    should also exercise a client-side magic-byte pre-check path (a real,
    previously-found bug class — `docs/NEXTGEN_SOC_ROADMAP.md` mentions
    the frontend's magic-byte check missing E01 support at one point).
- A genuinely oversized/corrupt/unsupported file → real, correct error
  surfaced via `ErrorCatalogue`, not a silent hang.
- Retry-intake / retry-parse buttons: `docs/NEXTGEN_SOC_ROADMAP.md`'s own
  Part 1 table flags "a real browser click-through of the parse-stage
  Retry button *succeeding* ... is still unverified" — this is a named,
  already-known gap this plan should close, using a deliberately-broken
  dependency (e.g. temporarily point at a bad ClamAV host, or intercept the
  request) to force a retryable error, then click Retry, then confirm real
  recovery to COMPLETE.
- Legal hold toggle in the UI reflects the real backend state and blocks
  deletion (a real 409/403, not just a disabled button — click the
  disabled button's underlying action via the API directly in-test to
  confirm the *server*, not just the UI, enforces it).
- Evidence detail drawer: real hash values, real chain-of-custody audit
  entries rendered, matching a fresh `GET /api/audit` call made
  independently in the test (not trusted from the same page load).

### 3.3 Detections & triage
- `DetectionsPage` real list + filter by triage state, real ATT&CK tags
  rendered from real `Detection` rows (reuse data already seeded by this
  session's own `poc/detection_api_triage_ui/`-style real backend calls
  as fixtures, or seed fresh via the real API in a `beforeAll`).
- `DetectionDetailPage` → real triage transition (`NEW` → `INVESTIGATING`)
  via the UI, confirm `TriageStatePill` updates without reload, confirm
  independently via a real API call that the transition and its audit row
  actually persisted.
- Illegal transition attempt (a terminal-state Detection) → UI correctly
  disables/hides the action, not just relying on a 409 the user never sees.
- Role-gated triage: a read-only role's session sees no triage buttons at
  all (RBAC UI gating, not just a 403 experienced as a dead click).

### 3.4 Admin & org management
- Real user invite → real role assignment → real removal, each step
  confirmed via a fresh page load (not just optimistic UI state).
- Org settings page — **note for whoever implements this section**:
  `src/external/routes/admin.py`'s `OrgSettingsOut`/`update_org_settings`
  is currently a complete stub with no real persistence (confirmed
  2026-08-08, see the tenant-quota work landing alongside this plan) — an
  E2E test against it today would only be testing that stub, not real
  behavior. Sequence this test to land *after* real settings persistence
  ships (the storage-quota work is the first real consumer of that), not
  before, or it will be testing something intentionally fake.

### 3.5 Cross-tenant isolation at the UI layer (L4-shaped, small in count, high value)
- Two real orgs, two real browser contexts (Playwright's per-context
  isolation is exactly suited to this — no shared cookies/localStorage
  between them by construction). Org A's authenticated session, given
  org B's real case/evidence/detection ID typed directly into the URL bar,
  gets the real 404 (not a client-side redirect that merely *looks* like
  isolation) — the browser-level version of `poc/global_l4_e2e/`'s own
  backend isolation assertions.
- Confirm no org-B-identifying string (case title, evidence filename,
  detector name) ever appears in org A's rendered DOM at any point,
  including transient loading states.

### 3.6 Dashboards embed
- The real OpenSearch Dashboards iframe embed (`cases.py`'s
  `get_dashboard_url`) actually loads inside the app shell for a real case,
  with the real case's own timeline data visible — this closes the one
  open question `poc/dashboards_embed/` flagged as needing "a live browser
  to observe" and never got (per its own README).

### 3.7 Resilience / error states
- Backend temporarily unreachable (block the `/api/*` route at the
  Playwright network-interception layer) → the UI shows a real, legible
  error state, not a blank screen or an unhandled promise rejection in the
  console (assert on `page.on("pageerror")` staying empty across the
  scenario).
- SSE connection drop mid-upload → UI recovers (reconnects or falls back
  to a poll) rather than silently freezing the status pill forever.

### 3.8 Accessibility & visual (lighter-touch, still real)
- `@axe-core/playwright` real automated a11y scan on each of the 6 pages
  (not a subjective pass — a real, automated WCAG rule-set check, catching
  e.g. missing form labels, contrast issues in `StatusPill`/
  `TriageStatePill` color coding).
- Visual regression on the pill/badge components specifically (they encode
  meaning through color — `toHaveScreenshot()` snapshots catch an
  accidental Tailwind class change that silently breaks the color coding
  without breaking any functional assertion).

## 4. Prerequisite: a CI-capable, security-enabled compose profile

**[RESOLVED 2026-08-28, Milestone JJJ]** Both halves of this prerequisite
are now done. The OpenSearch-security/real-Keycloak-org-provisioning half
was already done (commit `ba91a24`, predating this initiative) and already
CI-wired: `.github/workflows/security-integration-tests.yml` runs
`docker-compose.test.yml`'s real security-enabled profile nightly (+
manual dispatch, deliberately not per-PR) against
`tests/integration/test_security_enabled_stack.py`. The frontend-serving
half (real TLS, `kronos.local`, the compiled SPA) — tracked as the
remaining gap since Milestone GGG — is now folded into the shared file
too: `nginx` builds `docker/Dockerfile.frontend` on standard ports
`80`/`443`/`8443`, with a `tls-init` cert-generation service and an
`opensearch-dashboards` stub nginx needs to parse its shared config
template. `KC_HOSTNAME` is pinned (mirroring `docker-compose.dev.yml`) so
that `kronos-backend`'s own `/auth/refresh` token redemption — which goes
through the internal `keycloak:8080` short-circuit, not through nginx —
gets a matching issuer against browser-minted tokens. See
`docs/GAP_AUDIT_2026-08-28_MILESTONE_JJJ.md` for the two real bugs found
fixing this (dead backend env vars, and the KC_HOSTNAME/refresh-issuer
mismatch) and the four-step real verification (browser PoC, the real
`login.spec.ts`, the real security-stack PoC script, and the real pytest
suite — all passing together against the same stack).

**[RESOLVED 2026-08-28, Milestone KKK]** All three E2E tiers (smoke,
flow, isolation) can run against this profile; the smoke tier
(`login.spec.ts`) is now wired into
`.github/workflows/security-integration-tests.yml` as a
`frontend-e2e-smoke` job (nightly + manual dispatch, same as the existing
`security-stack` job). The flow/isolation tiers are not yet CI-wired —
deliberately scoped smaller for this pass; see Milestone KKK's own
recommendation for adding them incrementally.

## 5. Suggested delivery order (verification-first, smallest real thing first)

1. **[DONE 2026-08-28]** Stood up real `@playwright/test` 1.62.1 (pinned
   to match the already-installed Python 1.61.0 line as closely as npm's
   real published versions allowed) in `frontend/`, with
   `frontend/playwright.config.ts` and an OOP page-object suite
   (`frontend/e2e/pages/KronosPage.ts` base class, `LoginPage`,
   `CasesPage`) reusing the exact selectors
   `poc/keycloak_browser_login/run_poc.py` already proved
   (`#username`/`#password`/`#kc-login`, `text=Sign in with SSO`). One real
   spec, `frontend/e2e/login.spec.ts`, run for real against the live dev
   stack (`docker compose -f docker-compose.dev.yml`, already up) —
   **passed**: real PKCE login through Keycloak's real hosted form, lands
   on `/cases`, real client-side nav to `/detections` without a re-login
   prompt, real decoded access-token claims fetched via the app's own
   `/auth/refresh` cookie proxy. Two real, previously-unknown integration
   bugs found and fixed in the same pass: (a) Vitest's default include
   glob was also picking up `e2e/*.spec.ts` and failing trying to run
   Playwright's `test()` as a Vitest test — fixed via
   `vite.config.ts`'s `test.exclude`; (b) `oxlint`'s `react-hooks/rules-of-hooks`
   false-positived on Playwright's fixture `use()` callback param (not a
   React hook) — fixed via a new `.eslintignore` excluding `e2e/`. Also
   removed the residual, entirely-unused `playwright` (bare) devDependency
   and all five `@uppy/*` dependencies (confirmed zero real usage,
   `grep -rli uppy frontend/src` → nothing — see §0's correction) as a
   direct byproduct of getting this right rather than building on top of
   stale dependency residue. Full existing suite re-confirmed green after:
   `npm run build`, `npm run test` (101/101), `npm run lint` (0 errors, 1
   pre-existing benign warning).
2. **[DONE 2026-08-28]** §3.2's core upload-to-COMPLETE flow. Added
   `CaseDetailPage` (case creation, `uploadEvidence()`, and
   `watchEvidenceStateLive()` — polls the real evidence row's own text
   without reloading, exactly what proves the live SSE push path works)
   and `CasesPage.createCase()`, reusing the exact selectors
   `poc/evidence_sse_realtime/browser_verify.py` already proved. New spec
   `frontend/e2e/evidence-upload.spec.ts`, real fixture
   `tests/fixtures/samples/cloudtrail.json` — **passed**: real case
   creation, real upload, real live state transition to `Complete`
   observed without a reload. Found a real, reproduced (not flaky) bug in
   the same pass: Playwright runs separate spec *files* concurrently
   across workers by default even with `fullyParallel: false` (which only
   serializes within one file) — two specs each logging in as the same
   shared dev-seeded `case-lead` account at nearly the same instant caused
   a genuine Keycloak `"Invalid username or password"` rejection on the
   second login. Confirmed via `--workers=1` passing cleanly. Fixed by
   pinning `workers: 1` in `playwright.config.ts`, documented inline —
   this suite intentionally reuses one real shared fixture account per
   §0.1, so concurrent runs of it are never safe until specs are split
   across `DEV_USERS.caseLead`/`analyst`/`admin`.
3. **[DONE 2026-08-28]** §3.2's Retry-button spec — closes the exact
   already-named gap `poc/evidence_parse_retry/README.md` left open ("a
   real browser click-through of the Retry button succeeding ... was not
   worth burning further effort on" after selector/routing trouble).
   Added `DevStackFaultInjector` (`frontend/e2e/DevStackFaultInjector.ts`)
   reusing that same PoC's own proven trigger — stop real
   `docker-opensearch-1` before upload to force a real, transient
   `ERROR/ingest_failed`, restart it and wait for real `healthy`, then
   drive the real Retry button. New spec
   `frontend/e2e/evidence-retry.spec.ts`.
   **First three real runs found a genuine, previously-unknown product bug,
   not a test bug** (confirmed by cross-referencing real `celery-worker`
   logs showing the backend actually reached `finalize_evidence_done` while
   the UI stayed frozen on `Parsing`/stale `Error`): `useEvidenceSSE.ts`
   permanently closes its SSE stream the first time all evidence reaches a
   terminal state (`src/external/routes/sse.py`'s own "stop streaming once
   all evidence is terminal" `done` event) and had no mechanism to reopen
   it — so a successful retry recovered silently on the backend with the
   UI never finding out short of a manual reload. Real fix: `EvidenceDetailDrawer.tsx`'s
   retry mutation now dispatches a `kronos:sse-reconnect` CustomEvent
   (reusing the exact bridge pattern the existing `kronos:sse-poll`
   fallback already established) on success; `useEvidenceSSE.ts` listens
   for it and reconnects with a fresh ticket. Verified the fix by rebuilding
   and redeploying the real `docker-nginx-1` image
   (`docker compose -f docker-compose.dev.yml build nginx && ... up -d nginx`)
   and re-running the spec against the real running dev stack — passed,
   real live recovery to `Complete` observed without a reload. Also fixed
   a real, reproduced bug in `CaseDetailPage.ts`'s own `watchEvidenceStateLive()`
   test helper along the way: re-watching a row already sitting on a
   terminal state (re-watching after Retry) read the *stale* terminal text
   on its first poll and returned immediately, before the backend had done
   any work — added a `seedState` parameter so only a genuine transition
   away from the seeded state counts. Added unit coverage
   (`EvidenceDetailDrawer.test.tsx`) for the event-dispatch side of the fix
   (the reconnect side itself is only realistically provable against a
   real `EventSource`/backend, which the E2E spec covers). Full suite
   reconfirmed: `npm run build`, `npm run test` (103/103), `npm run lint`
   (0 errors), all three E2E specs together (`login` + `evidence-upload` +
   `evidence-retry`, serialized) passing in one run.
4. **[DONE 2026-08-28, triage half only]** §3.3's core triage transition
   (NEW -> INVESTIGATING). New `frontend/e2e/fixtures/seed_detection.py`
   seeds a real Detection for the E2E suite, reusing two already-proven
   patterns rather than re-deriving them: live `org_id` resolution via
   Keycloak Admin REST (`poc/detection_containment_ui/setup.py`'s own
   pattern — org_id churns across dev-stack recreations, confirmed
   unchanged from `poc/detection_risk_score_ui/`'s original but resolved
   live regardless, not hardcoded) and insertion through the real
   `PostgresDetectionRepository`/`DetectionRiskScorer` domain code
   (`poc/detection_risk_score_ui/seed_detection.py`'s own pattern) rather
   than hand-written SQL, so it can't silently drift from the real schema.
   `frontend/e2e/DetectionSeeder.ts` wraps it (`execFileSync`, parses its
   JSON stdout). New `DetectionDetailPage`/`DetectionsPage` page objects,
   new spec `frontend/e2e/detection-triage.spec.ts` — real click-through
   of "Start Investigating", confirmed both live in the DOM (`expect.poll`,
   no reload) and independently via a fresh real
   `GET /api/detections/{id}` call per this section's own requirement.
   **Real, reproduced finding along the way**:
   `PostgresDetectionRepository.stream_by_org` sorts ascending by
   `synced_at` (not descending) — a freshly-seeded detection lands on the
   LAST page of `/detections` (default `pageSize=50`), not the first, given
   this repo's accumulated PoC history has seeded far more than 50 real
   detections into `kronos-dev` over time. Not fixed (untested whether
   ascending is intentional, e.g. "oldest unresolved first" triage
   priority) — worked around by having `DetectionDetailPage.openById()`
   navigate directly to the real per-detection URL instead of paging
   through the list, which is also more realistic for what this spec
   actually tests. Full suite reconfirmed: `npm run build`, `npm run test`
   (103/103), `npm run lint` (0 errors), all four E2E specs together
   (`login` + `evidence-upload` + `evidence-retry` + `detection-triage`,
   serialized) passing in one 2.7-minute run.
   **§3.5 isolation — [DONE 2026-08-28]**: new
   `frontend/e2e/fixtures/seed_second_org.py` creates a genuinely fresh,
   real Keycloak Organization + member user per run (real Admin REST
   calls: org creation, user creation, org membership, the real `org_id`
   flat-claim user attribute via a GET-then-splice PUT — `PUT
   .../users/{id}` is NOT a partial update, a known real gotcha this repo
   already hit once — and a separate realm-role-mappings call, since
   `realmRoles` in the user-creation body is silently ignored). New spec
   `frontend/e2e/cross-tenant-isolation.spec.ts`: real case created in
   `kronos-dev` as `case-lead`, a fresh org B member given that case's
   real ID directly via the URL bar — real, observed `404` (not a
   redirect that merely looks like isolation), and org A's case title
   confirmed absent anywhere in org B's rendered DOM. Consolidated the
   Python-fixture-wrapping pattern (`DetectionSeeder.ts` had its own
   `execFileSync` call) into a shared `frontend/e2e/pythonFixture.ts`
   rather than repeating it a second time, per the maintainability
   assessment's own recommendation for the *next* fixture need. This
   closes item 4 completely.
5. §3.4 admin/org-settings — sequenced after real settings persistence
   ships (see the note in §3.4).
6. §3.6 dashboards embed, §3.7 resilience, §3.8 a11y/visual — lower
   urgency, pick up opportunistically.
7. §4's CI-wiring prerequisite can be tackled in parallel with 1-3 (it's a
   disjoint infra surface) so the suite isn't blocked waiting on it to
   start being written, only on it to start running unattended.

Each numbered item above should land as its own PoC-first pass (a
throwaway proof that the exact Playwright API/selector strategy works
against the real running app, captured output, per CLAUDE.md §F) before
being folded into the permanent `frontend/e2e/` suite — no different from
how every backend integration in this repo has been built this session.
