# Gap Audit — Milestone BBB (2026-08-25)

Per Milestone AAA's own recommendation: extended the "actually run it,
don't just read it" method into two new areas -- re-confirming a Milestone
ZZ scenario against real, executable test coverage, and checking whether
any other floating/broken reference exists in the repo's infra config
beyond the GitHub Actions case Milestone AAA already fixed.

---

## 1. Approval-ticket replay scenario: confirmed via real, existing tests

Milestone ZZ round 2 reasoned through (but did not execute) whether a
step-up approval ticket minted for one containment-action resource could be
replayed against a different one. Checked for real, executable coverage of
this exact scenario rather than re-deriving it: `tests/unit/application/
test_approval_gate.py::test_ticket_cannot_be_replayed_against_a_different_real_resource`
and `::test_denies_a_ticket_scoped_to_a_different_action` already exercise
this precisely, against the real `StepUpApprovalGate` + real
`InMemoryTicketStore` (not mocked) -- both are the actual Milestone JJ
regression tests for this exact attack class. Ran them directly: all 10
tests in the file pass. Only one real `ContainmentAction` subclass exists
(`RevokeKeycloakSessionAction`) so a true cross-action-type replay can't be
exercised with two distinct real actions today, but the resource-id and
action-name mismatch dimensions are both covered live. No new finding here
-- confirms Milestone ZZ's reasoning was correct, with real test execution
behind it now, not just analysis.

## 2. Frontend tooling versions: checked for the same drift Milestone AAA found in Python -- confirmed NOT exposed

**Investigation.** Milestone AAA found Python's `ruff`/`black`/`mypy` were
pinned as open-ended `>=` lower bounds, so `pip install -e ".[dev]"`
(no lockfile mechanism) silently drifts to whatever's newest. Checked
whether `frontend/package.json`'s `oxlint`/`vitest` (also declared with
caret ranges, e.g. `^1.69.0`) have the same exposure.

**Finding: no.** `frontend/package-lock.json` is committed
(`git ls-files` confirms it's tracked, not gitignored), and
`.github/workflows/test.yml`'s `frontend-build` job runs `npm ci` (not
`npm install`) -- `npm ci` installs exactly what the lockfile records,
ignoring `package.json`'s caret ranges for resolution. Confirmed the
currently-installed `node_modules/.bin/oxlint --version` (1.71.0) and
`vitest --version` (4.1.9) match the lockfile's own recorded versions
exactly. This is npm's built-in reproducibility mechanism working as
designed -- unlike pip, which has no equivalent lockfile for a plain
`pip install -e ".[dev]"`. No fix needed; documenting the check itself
since a plausible-but-wrong assumption ("caret ranges = same risk as `>=`
pins") would have been an easy, unverified guess to make here.

## 3. `docker-compose.test.yml`'s `tsa` service referenced a nonexistent image — FIXED

**Finding.** `image: freetsa/freetsa:latest`. Queried the real Docker Hub
API directly (`GET /v2/repositories/freetsa/freetsa` → `"object not
found"`; `GET /v2/repositories/freetsa/` → the namespace itself has zero
repositories) -- this image does not exist and, per the evidence, never
has. This service could never actually start from a clean pull. Its own
healthcheck (`openssl s_client -connect localhost:318` against what's
actually plain HTTP, with a trailing `|| true` that makes it report
healthy unconditionally regardless of whether either command inside it
succeeds) confirms nobody ever ran this against a real container --
guessed at, not verified, exactly the anti-pattern CLAUDE.md §F exists to
name.

`docker-compose.dev.yml`'s own `tsa` service comment already recorded the
same root fact independently ("freetsa/freetsa has no public Docker image;
use a lightweight stub for dev") -- but its stub returns a bare HTTP 200
with an empty body, which `poc/rfc3161/README.md` (an earlier, thorough PoC
already in this repo) separately proved can never decode as a real DER
`TimeStampResp`, so it can't exercise `RFC3161TimestampService.verify()` at
all. That same PoC also found and fixed a real, separate, critical bug --
`.verify()`'s pyasn1 field access was completely wrong and had never
successfully parsed any real TSA response, ever (confirmed already applied
in `src/application/timestamping.py`, not re-broken).

**Fix.** New `docker/init/Dockerfile.tsa-mock` +
`tsa-mock-entrypoint.sh` + `tsa_mock_server.py`: a real RFC 3161 responder
that shells out to `openssl ts -reply` per request (the exact technique
`poc/rfc3161/run_poc.py` already proved end-to-end against the real,
unmodified `RFC3161TimestampService`), generating a throwaway CA/TSA
cert at container startup. Wired into `docker-compose.test.yml`'s `tsa`
service in place of the dead image reference.

**Verification (two rounds, one real bug found in the fix itself).**
1. Built the image directly, ran it standalone (`docker run`), and drove a
   full `timestamp()`/`verify()` round trip via the real, unmodified
   `RFC3161TimestampService` class against it: 2328-byte real DER
   `TimeStampResp`, `verify()` succeeded with the correct `genTime`,
   wrong-digest negative test correctly rejected.
2. Verified the *actual compose service definition* (not just the image
   in isolation) via `docker compose run` (host port 318 was already bound
   by the real running dev stack's own `docker-tsa-1`, so this used a
   non-host-published run rather than colliding with it) -- found a real,
   second bug in the process: the healthcheck's `wget
   http://localhost:318/` resolved `localhost` to `::1` first and got a
   genuine connection-refused every time (the Python responder only binds
   IPv4), while `http://127.0.0.1:318/` succeeded. Fixed by using the
   explicit IPv4 loopback address instead of a hostname. Confirmed via
   `docker inspect`: Docker's own healthcheck now reports `healthy`.
   Re-ran the full round trip a second time against the compose-built
   container over its real internal Docker network to confirm the fix
   didn't change anything about the actual responder behavior.
3. All verification containers/images/networks (`kronos-poc-tsa-*`)
   cleaned up afterward. The real running dev stack
   (`docker-compose.dev.yml`) was never stopped, restarted, or otherwise
   touched at any point.

## 4. `docker-compose.prod.yml` has the identical dead image reference — a real production blocker, documented not fixed

`docker-compose.prod.yml`'s own `tsa` service (line 345-347) is the same
`image: freetsa/freetsa:latest`, with **no healthcheck at all** (even less
verified than test.yml's already-broken one). The real backend's
`TSA_URL: http://tsa:318` (line 515) is a genuinely load-bearing
environment variable -- per `BatchSealingService`'s own documented
contract (referenced elsewhere in this codebase's docs), a *configured*
TSA that fails aborts the whole batch-seal operation rather than silently
proceeding without a timestamp, unlike `AuditLogService.anchor_day()`
where TSA is best-effort. This means: **a fresh `docker compose -f
docker-compose.prod.yml up` would either fail to pull the `tsa` service at
all, or (if the pull step is somehow skipped/cached) leave every
timestamp-anchoring code path permanently failing at runtime** with no
warning until the first real evidence-sealing operation is attempted.

**Deliberately not fixed with the same swap this milestone used for
test.yml.** A throwaway, self-signed CA (what `docker/init/Dockerfile.
tsa-mock` generates fresh per container start) has zero evidentiary value
in production -- the entire point of RFC 3161 timestamping for
chain-of-custody is a timestamp attested by a party the evidence's eventual
audience (a court, an auditor, a regulator) independently trusts, not a
timestamp KronOS's own infrastructure signed for itself. Which real TSA to
use in production -- a self-hosted responder with a properly-issued,
externally-trusted certificate; a commercial TSA vendor (DigiCert, Sectigo,
GlobalSign, etc.); or the real public `freetsa.org` HTTP endpoint (a real,
existing public service -- distinct from the nonexistent
`freetsa/freetsa` *Docker image* that was likely confused for it when this
was first written) -- is a genuine compliance/business decision, not a
technical bug fix. Flagging this here, with the underlying technical fact
already confirmed (the current reference is unconditionally broken), so
whoever makes that call doesn't have to re-discover it from scratch.

---

## Recommendation for the next wake-up cycle

1. **This production TSA gap (§4) is the most severe, concrete finding in
   the JJ-BBB chain to date** -- worth surfacing prominently, alongside the
   other still-open project-owner decisions, rather than letting it get
   buried among routine gap-audit findings.
2. Continue the "actually run it" method into one more area before
   returning to either per-file review or scenario tracing: the `docker/
   pki/`, `docker/kes/`, `docker/vault/` directories and
   `docker-compose.prod.yml`'s remaining secrets/KMS wiring have not had a
   dedicated real-execution check this chain (most attention so far has
   gone to the application/adapter/domain/frontend/CI layers, not the
   production secrets-management infra itself).
3. Check CronCreate job `0b6703d2` (created 2026-08-23, ~2.5 days old as of
   this pass) -- not yet urgent, but the next cycle or two should re-arm it
   proactively.

Still open, unchanged from prior milestones: the lower-value optional
SIEM/EDR plaintext secrets in `docker-compose.prod.yml`, Keycloak's own
admin/DB password file-secret gap, the Postgres sync-replica ops-policy
decision, `AdminPage.tsx`'s missing `onError` handling,
`SecurityAnalyticsCorrelationRuleProvisioner._rule_name()`'s truncation
edge case, and `main`'s own frozen/failing CI state (Milestone AAA §3) --
out of this initiative's scope to fix directly.
