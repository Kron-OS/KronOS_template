# Gap Audit — Milestone RRR (2026-08-29)

**Scope:** not a new spec or a new bug in application code — a
verification-infrastructure finding, several cycles overdue. Checked,
for the first time in this initiative, whether ANY of this repo's five
GitHub Actions workflows have ever actually executed against
`feat/nextgen-soc-cert-platform`. None have, and — as every one is
currently configured — none structurally can, until this branch merges
to `main` or someone with repo access manually dispatches one.

---

## The finding

`gh` CLI isn't available in this environment, but the GitHub REST API
(unauthenticated, public) lists every workflow GitHub Actions currently
recognizes for this repo:

```
$ curl -s https://api.github.com/repos/Kron-OS/KronOS_template/actions/workflows
```

Four workflows: `build.yml`, `deploy.yml`, `integration-tests.yml`,
`test.yml`. **`security-integration-tests.yml` (added Milestone KKK,
extended every cycle since through Milestone QQQ) is not among them.**
Confirmed why directly:

```
$ git show main:.github/workflows/security-integration-tests.yml
fatal: path '.github/workflows/security-integration-tests.yml' exists on disk, but not in 'main'
```

The file has only ever existed on `feat/nextgen-soc-cert-platform` — now
193 commits ahead of `main` and never merged. This matters specifically
because of a real GitHub Actions platform behavior: **a workflow's
`schedule:` trigger is only ever evaluated against the copy of the file
on the repository's *default* branch.** Not a bug in this repo's YAML;
how the platform works, full stop. Consequence: the nightly `0 3 * * *`
cron this workflow declares has **never fired, not once**, for any of
the work landed in Milestones KKK through QQQ.

**Checking further widened this, not narrowed it.** Every workflow's
own `push:`/`pull_request:` trigger, read directly:

| Workflow | Trigger |
|---|---|
| `build.yml` | `push: branches: [main]`, `workflow_dispatch` |
| `deploy.yml` | `workflow_run` (chained off `build.yml`, `branches: [main]`) |
| `integration-tests.yml` | `push: branches: [main]`, `pull_request: branches: [main]` |
| `security-integration-tests.yml` | `schedule` (inert per above), `workflow_dispatch` |
| `test.yml` | `push: branches: [main, ai-implementation]`, `pull_request: branches: [main]` |

**None trigger on push to `feat/nextgen-soc-cert-platform`.** Not one.
`pull_request` triggers only fire for PRs *targeting* `main` — which
CLAUDE.md's own standing instruction for this initiative explicitly
rules out ("push to branch, no PR"). This means **no commit across this
entire branch's ~193-commit history has ever been checked by ANY of
this repo's own CI — not lint, not `mypy`, not the unit test suite, not
the frontend build, nothing** — despite every commit message on this
branch citing real, rigorous local verification (which this repo's
CLAUDE.md §F discipline correctly demands, and which this initiative has
genuinely done at every step). Local verification and CI verification
are not substitutes for each other; this branch has only ever had the
former.

## Why this wasn't caught sooner

Every milestone's own verification correctly followed §F for the thing
each milestone was actually building (a compose fix, a fixture script, a
spec) — but the CI *wiring* itself was always verified by "mirror the
exact job steps locally," never by "confirm the job as committed
actually executes on GitHub." Those are different claims, and
conflating them is exactly the kind of "confident-sounding, unverified
[thing] treated as done" gap §F exists to catch — just applied here to
the verification harness itself (and, as it turns out, the whole
branch's CI posture), not the application code it verifies. Nothing
about this finding invalidates any prior local-verification result. It
only means the "CI now guards this" framing that closed out several
milestones was never actually true in the automatic, unattended sense
implied.

## What CAN still work today, without merging

`workflow_dispatch` is a *different* GitHub Actions mechanism from
`push`/`pull_request`/`schedule`, with a materially different
constraint: it requires the workflow file to exist on whichever
ref/branch you target, but does NOT require that branch to be `main`.
`build.yml` and `security-integration-tests.yml` both declare
`workflow_dispatch`. A repo maintainer with appropriate access could,
right now, get either job's actual first real execution on GitHub's
infrastructure via the Actions UI (select the branch, "Run workflow"),
`gh workflow run <file>.yml --ref feat/nextgen-soc-cert-platform`, or the
REST API's `workflows/{id}/dispatches` endpoint with `"ref":
"feat/nextgen-soc-cert-platform"`.

**Not attempted here**: this session has no `GITHUB_TOKEN`/`GH_TOKEN`
and `gh` isn't installed, so there's no credential available to actually
dispatch anything from within this session. Triggering it would also
consume real GitHub Actions minutes on the user's account — a
real-world resource-use decision this initiative's own standing
authorization (commit + push to this branch, no PR) doesn't clearly
cover. Flagged as the concrete next action for whoever has repo-level
access, not silently worked around or assumed away.

## What this does NOT mean

- Every locally-verified milestone's own findings (real bugs found and
  fixed, real specs passing against real freshly-built isolated stacks)
  remain exactly as valid as documented. This finding is about whether
  an *additional*, independent, automatic confirmation exists on top of
  that — across the whole branch, not just the E2E work, it doesn't yet.
- No workflow YAML needs a fix for this specific issue — every one is
  written correctly for what it's supposed to do. There is no config
  change that makes `schedule:`/`push`/`pull_request` triggers fire for
  a non-default, non-targeted branch; that's a platform constraint, not
  a bug to patch in this repo.

## Recommendation for the next cycle

1. **The real fix is either a manual `workflow_dispatch` (by someone
   with repo access and appropriate GitHub credentials) against this
   branch, or eventually merging this branch to `main`** — both outside
   this session's current authority/tooling. Until one happens, treat
   every "CI now covers X" claim across Milestones KKK-QQQ, and every
   "lint/tests/build clean" claim across this branch's full history, as
   "verified locally, with real rigor, and not yet independently
   confirmed by GitHub's own CI."
2. `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` and `PROGRESS.md` §2.8 corrected
   in place (dated notes, not rewritten history) to reflect this — see
   those files' own changes alongside this doc. The workflow file itself
   now carries an inline comment explaining the same thing at the
   `on:` block, so anyone reading the YAML directly sees it too.
3. Otherwise, Milestone QQQ's own still-open items remain: porting
   `evidence-retry.spec.ts` to the test-stack profile, heavy-parser CI
   coverage, `security-stack` also booting `kronos-backend`, RBAC
   access-denial specs, or `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8.
