# Gap Audit — Milestone ZZZ (2026-08-31)

**Scope:** closes Milestone YYY's recommendation #1 — `TarArchiveParser`
CI-wired coverage. `poc/tar_container_unwrapping/` had already built and
verified a real, reproduced-incident fixture (a tar archive deliberately
misnamed `forensic2.E01`, exactly the real incident that motivated
`TarArchiveParser`'s existence) against the dev stack, but that
verification predates this initiative entirely and was never cited by
name in any of Milestones UUU/VVV/WWW/XXX/YYY's own "HEAVY-tier now
covered" claims — Milestone XXX's coverage-gap review caught exactly this
omission.

---

## Fixed this cycle

### Relocated the real fixture to match this repo's established convention

`forensic2.E01` (a real tar archive: a real 16 MiB ext4 filesystem with 3
real files at 3 real, distinct timestamps, plus a placeholder
`memory.dmp`, packed via Python's `tarfile` and deliberately named with
the misleading `.E01` extension the real incident had) previously lived
directly under `poc/tar_container_unwrapping/`, inconsistent with this
repo's own established convention (`tests/fixtures/samples/real/kape/`,
etc.) of keeping real fixture bytes under `tests/fixtures/` and having
`poc/`/spec files reference them from there. Moved via `git mv` (history
preserved) to `tests/fixtures/samples/real/tar_container/forensic2.E01`,
with a new `NOTICE.md` documenting full provenance.
`build_fixture.py`/`run_ingest.py` updated to reference the new path —
confirmed the PoC's own reproducibility is unaffected (both scripts still
resolve the same real bytes, just at a shared location instead of a
duplicate).

### New test: `TarArchiveParser` added to `evidence-upload-heavy-parser-archive.spec.ts`

A third test alongside Milestone VVV's existing zip/EWF cases — a natural
fit under the same "archive/container routing" theme, not a new spec
file. Uploads the relocated `forensic2.E01` fixture and confirms it
reaches `Complete` live via SSE. This exercises a real, distinct code
path from both existing tests in this file: the outer tar contributes no
records directly (recursion only, mirroring `ZipArchiveParser`'s own
pattern), its one real inner member with a registered parser
(`image.dd`, a raw ext4 disk image) routes through `PlasoParser`'s
raw-disk-image magic-byte detection (added alongside `TarArchiveParser`
itself, a real, distinct routing path from EWF/E01's own whole-image
case), and the second real member (`memory.dmp`, a placeholder, no
registered parser) proves the "recognised container member, no parser
yet" path doesn't crash or silently sink the evidence to `ERROR`.

## Verified live

Ran the updated 3-test spec against the real, live dev stack (same
resource-constrained-host judgment call as Milestones WWW/YYY — `free -h`
showed 285 MiB free / swap in meaningful use going into this cycle). All
3 passed (18.0s / 21.5s / 22.1s). Cross-checked the new test's real result
against `celery-worker-plaso`'s own logs directly, not just the green
checkmark: `record_count: 20` — the exact figure
`poc/tar_container_unwrapping/verification.json` already documented for
this fixture (12 real events from the 3 files' own content plus
filesystem-level events), confirming genuine content extraction, not a
false-positive empty `COMPLETE`. Re-ran alongside
`evidence-upload-heavy-parser.spec.ts`, `evidence-upload-fast-parsers.spec.ts`,
and `login.spec.ts` (6 tests total) with no interference.

`timeout-minutes: 70`'s own justification comment updated again (matching
Milestone XXX's own precedent of keeping this comment's reasoning
current, not stale): the archive spec's combined declared worst-case
ceiling is now 330s + 150s (the new test's own `test.setTimeout`) = 480s
(8min), still well inside the ~5.5min headroom the number already had —
real measured cost for all 3 tests together was ~1.1min.

## Documented, not fixed this cycle

Carried forward from Milestone YYY, still open:

1. `evidence-upload.spec.ts`'s own CloudTrail fixture is still synthetic,
   not the real Plaso-sourced sample (rigor gap, not coverage gap).
2. Intake-stage retry E2E coverage (carried since Milestone TTT).
3. `security-stack` also booting `kronos-backend`, RBAC access-denial
   specs, `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8.
4. Milestone RRR's "no workflow has ever run on real GitHub Actions"
   finding remains true.
5. The immediately-after-case-creation race and background-task-
   concurrency contention risk (Milestone XXX) remain unconfirmed in
   practice.

## Status

Every HEAVY-tier parser this repository has (Plaso direct, `ZipArchiveParser`,
`TarArchiveParser`, EWF/E01 whole-image routing, and `VolatilityModule`)
now has real, dedicated, CI-wired browser E2E coverage, with the one
already-existing exception being the honest, deliberate one (Volatility's
512 MiB real fixture can't be committed, so it's a backend-only `poc/`
script instead — Milestone WWW). Combined with Milestone YYY's FAST-tier
push, this closes the "HEAVY-tier now covered" claim's own remaining gap:
every parser this platform ships now has real, verified, browser-driven
E2E coverage of some kind, not just unit/PoC-level verification.

## Recommendation for the next cycle

1. Swap `evidence-upload.spec.ts`'s synthetic CloudTrail fixture for the
   real sample (cheap, rigor not coverage — carried from Milestone YYY).
2. Intake-stage retry E2E coverage (carried since Milestone TTT).
3. `security-stack` also booting `kronos-backend`, RBAC access-denial
   specs, or `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8.
4. With every parser now covered, this is a natural point to survey
   *what's left uncovered that isn't a parser* — RBAC/authz paths, the
   admin/org-settings surface (blocked since early cycles on "needs a
   real backend stub"), and the dashboards-embed/resilience/a11y specs
   (§3.6-§3.8) are the remaining named categories, not new parser work.
5. This initiative's own ~4-cycle assessment rhythm means the next
   multi-scenario subagent assessment isn't due yet (two implementation
   cycles, YYY and ZZZ, have landed since Milestone XXX) but is worth
   tracking as more land.
