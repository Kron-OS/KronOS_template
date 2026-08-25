# Gap Audit — Milestone AAA (2026-08-25)

Per Milestone ZZ round 2's own recommendation: switched from scenario-based
security tracing back to direct review of a real, never-independently-
reviewed artifact -- the five CI workflow files under `.github/workflows/`.
This turned into the most consequential milestone in the JJ-AAA chain by
volume of real findings, once the review of the workflow *files themselves*
led to actually re-running what they run.

---

## 1. `build.yml`: Trivy scan pinned to a floating branch reference — FIXED

**Finding.** `aquasecurity/trivy-action@master` -- every other action in the
same workflow is pinned to at least a semver tag; `@master` meant any new
commit landing on that action's default branch would run immediately in a
job holding `security-events: write` + Docker build access, with zero
reviewed release boundary at all.

**Fix.** Looked up the real, current release via the GitHub API (not
assumed): `v0.36.0`, a verified/signed annotated tag dereferencing to
commit `ed142fd0673e97e23eac54620cfb913e5ce36c25`. Confirmed that commit's
`action.yaml` still accepts every input this workflow uses
(`image-ref`/`format`/`output`/`severity`/`exit-code`) unchanged before
pinning to it.

## 2. `test.yml`: frontend-build job never ran lint or tests — FIXED

**Finding.** The job ran `npm ci && npm run build` only. `npm run lint`
(oxlint) and `npm test` (vitest, 101 tests) are both real, already-used
`package.json` scripts, exercised manually in every frontend fix across the
whole JJ-ZZ chain -- but CI itself never ran either. A regressed test or a
newly-introduced lint violation could merge to main with a fully green CI
run.

**Fix.** Added both steps before the build step. Verified by running the
exact three commands locally in the same order the workflow now runs them:
101/101 tests passed, one pre-existing unrelated oxlint warning (exit 0),
build succeeded.

## 3. Real GitHub Actions API check surfaced two bigger, unexpected facts

While looking for a way to verify #1/#2 against a real triggered run
(no `gh` CLI/token available in this sandboxed environment), queried the
public GitHub API directly (`curl https://api.github.com/repos/.../actions/runs`)
and found:

- **Neither `build.yml` nor `test.yml` has ever fired against this feature
  branch, at all**, in the branch's entire history. Both only trigger on
  push to `main`/`ai-implementation` or a PR targeting `main` -- and this
  initiative works exclusively on `feat/nextgen-soc-cert-platform` per its
  own standing instructions, never opening a PR. Every commit across the
  entire JJ-AAA gap-audit chain has been verified locally (pytest/ruff/
  black/mypy/vitest run by hand) but never by real CI.
- **`main`'s own last real run (2026-07-29, commit `673b29ef`) already
  failed** -- `Build & Security Scan`, `Test`, and `Integration Tests` all
  show `conclusion: failure`. Job-level detail (also via the public API):
  the `lint` job failed specifically on `ruff check src/ tests/`, which
  cascaded into `unit-tests` being skipped (it `needs: lint`). This
  predates the JJ-onward gap-audit chain entirely and `main` is out of
  this initiative's authorized scope to touch (per CLAUDE.md's own branch
  rule) -- documented here, not fixed, per the "document blockers
  honestly" precedent.

## 4. Root cause investigation: `ruff check` and `black --check` would genuinely fail right now on this branch too — FIXED

Given #3's finding that CI has never actually run against live code in a
long time, checked whether the *current* tree would pass its own lint gate
if it ever did. It would not have, for reasons unrelated to any of this
session's own edits:

**Investigation.** `pyproject.toml` pins `ruff>=0.4`, `black>=24.4`,
`mypy>=1.10` -- open-ended lower bounds, no upper bound. A fresh
`pip install -e ".[dev]"` (exactly what `test.yml`'s `lint` job runs, and
what this investigation reproduced in a scratch venv to avoid touching the
host's system Python) resolves to whatever the latest release of each tool
is *that day*. That resolved to ruff 0.16.4 and black 26.5.1.

- **`ruff check src/ tests/` under 0.16.4: 68 real, currently-existing
  violations** across ~20 files (62 `E501` line-too-long, 2 `F401` unused
  imports, 2 `N802` non-lowercase test names, 1 `N815` missing
  per-file-ignore entry, 1 `UP037` stale quoted type annotation under
  `from __future__ import annotations`). Confirmed these are real (not a
  ruff-version artifact) by hand-checking several flagged lines' actual
  character counts -- e.g. `src/domain/stream.py:78` is genuinely 106
  characters against the configured 100-char limit, a file read closely
  for logic correctness in Milestone YY without anyone having run a linter
  against it since.
- **`black --check src/ tests/` under 26.5.1: wanted to reformat 27+
  files**, including files nobody touched this session. Diffed a sample
  (`test_parsing.py`) and confirmed this was pure black-version-formatting-
  heuristic drift (collapsing multi-line expressions an older black had
  intentionally split, even though both forms fit under 100 characters) --
  not a real style violation. Reformatting the whole tree under whatever
  black happens to be newest today would have been unjustified scope creep
  with no clear "correct" answer.
- Bisected: black 24.4.2 through 25.1.0 (the four versions tried) all
  agree with each other and flag only 10 genuinely non-compliant files (4
  from this pass's own hand-wrapped `E501` fixes not exactly matching
  black's own algorithm, 6 pre-existing and unrelated to this session).

**Fix.**
1. Closed all 68 ruff findings by hand with minimal, targeted line-wraps
   (never a blanket auto-reformat) -- verified each ruff category's real
   root cause first (e.g. `N815` in `src/external/routes/collector_ingest.py`
   turned out to be a missing per-file-ignore entry, not a real bug: its
   `EventOutcomeOut.messageId` DTO is structurally identical to the
   already-ignored `integration_source_push.py`'s own, both genuinely
   collector-facing routes with no frontend consumer at all -- confirmed
   via `grep -rn messageId frontend/src/` returning nothing).
2. Ran black 24.4.2 (the verified-compatible version, not the newest) to
   reformat exactly the 10 genuinely non-compliant files.
3. Pinned `mypy==2.3.1`/`ruff==0.16.4`/`black==24.4.2` exactly in
   `pyproject.toml`'s dev dependencies, so this class of silent,
   date-dependent drift stops recurring for any future contributor or CI
   run. mypy's own error count reproduced the pre-existing, already-
   documented 29-error baseline exactly under the now-pinned version --
   zero new mypy issues from anything in this pass.

**Verification.** Full unit suite: 1920 passed, 1 skipped, 89.49% coverage
(gate 80%) -- no regressions from any of the ~30 touched files. `ruff
check`/`black --check` both clean under the pinned versions. `mypy`: 29
errors, unchanged. Committed as `4743afe` (workflow files) and `dce7737`
(lint fixes + version pins).

## 5. Remaining workflow files reviewed, no new gap

`deploy.yml`'s `workflow_run` trigger is correctly gated to fire only after
`Build & Security Scan` completes successfully on `main` -- genuinely
post-merge-only, matching CLAUDE.md's own claim. Its `helm upgrade` step is
a deliberate, documented stub (no real Helm chart or K8s target exists in
this repo yet, consistent with the `poc/prod_helm_parity` investigation
from an earlier milestone) -- not a bug, a known, honest incomplete state.

`integration-tests.yml` and `security-integration-tests.yml` both reviewed
in full: correct real-service health-check gating, correct nightly-not-
per-PR cadence for the heavier security-enabled stack (with a real,
measured resource-fit PoC backing that decision), correct teardown
(`down -v --remove-orphans` on `always()`). No issues found in either.

---

## Recommendation for the next wake-up cycle

The most load-bearing finding this milestone: **this initiative's own
"ruff/black/mypy clean" verification claims, repeated in nearly every
prior gap-audit doc, were true only relative to whatever tool version
happened to be installed at the moment each check ran** -- now pinned, so
future claims are reproducible. This is worth remembering as a general
caution: any other unpinned tooling in this repo (e.g. frontend's `oxlint`/
`vitest` versions in `package.json` -- spot-checked, both already
exact-pinned there, so not a live concern) could have the same latent
issue.

Candidates for the next milestone:
1. **`main`'s own frozen, failing CI state** (§3 above) is real but out of
   this initiative's scope to fix directly (never touch a branch other than
   `feat/nextgen-soc-cert-platform`) -- flagged here for the project owner;
   if/when this branch is eventually merged, main's CI will need the same
   ruff/black fixes this milestone already made on the feature branch.
2. Return to Milestone ZZ's scenario-based assessment for a second round
   (candidates already named in that chain: approval-ticket replay across
   containment actions already covered, but "an org-admin approval-ticket
   generated for one containment action is replayed against a different
   action/detection" specifically, and other cross-cutting flows not yet
   tried).
3. A fresh per-file review pass, since Milestone AAA's own method (running
   the actual tool rather than reading files) proved more productive this
   cycle than either of the last two milestones' pure-reading approaches --
   consider extending this "actually run it" discipline to `mypy --strict`
   or a broader static-analysis pass beyond the current `select=` rule set
   in `pyproject.toml`'s `[tool.ruff.lint]`.

Still open, unchanged from prior milestones: the lower-value optional
SIEM/EDR plaintext secrets in `docker-compose.prod.yml`, Keycloak's own
admin/DB password file-secret gap, the Postgres sync-replica ops-policy
decision, `AdminPage.tsx`'s missing `onError` handling, and
`SecurityAnalyticsCorrelationRuleProvisioner._rule_name()`'s truncation
edge case.
