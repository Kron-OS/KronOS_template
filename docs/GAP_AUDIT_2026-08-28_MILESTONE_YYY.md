# Gap Audit — Milestone YYY (2026-08-30)

**Scope:** closes Milestone XXX's coverage-gap review's own top
recommendation — three straight cycles (UUU/VVV/WWW) gave every
HEAVY-tier (`q.parse.plaso`) parser real, dedicated browser E2E coverage
and left FAST-tier (`q.parse.fast`) parsers — the platform's actual
highest-volume real-world ingestion path — comparatively unverified.

---

## Fixed this cycle

### New spec: `frontend/e2e/evidence-upload-fast-parsers.spec.ts`

Four tests, one per FAST-tier parser that had never been driven through a
real top-level upload before this cycle:

| Parser | Real fixture | Prior coverage |
|---|---|---|
| `evtx-rs` (Windows EVTX) | `tests/fixtures/samples/real/system.evtx` | None — never uploaded standalone in any spec |
| `nginx` (access log) | `tests/fixtures/samples/real/apache_access.log` | Only indirectly, as a `kape_triage.zip` member (Milestone VVV) |
| `suricata-eve` (EVE JSON) | `tests/fixtures/samples/real/suricata/eve.json` | None at all — the existing `poc/suricata/` PoC is parser-only, in-process, never driven through a real upload |
| `chrome-history` (SQLite) | `tests/fixtures/samples/real/chrome_history/History` (new — see below) | Only indirectly, as the same `kape_triage.zip` member |

`CloudTrailParser` was already covered (`evidence-upload.spec.ts`, albeit
with a synthetic, not real, fixture) — not duplicated here.

### New fixture: `tests/fixtures/samples/real/chrome_history/History`

The one gap without an existing standalone real fixture. Extracted
directly from the already-committed, already-verified
`tests/fixtures/samples/real/kape/kape_triage.zip`'s own Chrome History
member (Python `zipfile.read()`, byte-for-byte, no modification) — the
exact same real file already independently exercised inside that
container by `poc/kape_ingestion_test/`. Kept its real, extension-less
`History` filename (Chrome's own real on-disk name), confirmed this
routes correctly: `ChromeHistoryParser.supports()` keys purely on the
SQLite magic bytes plus `urls`/`visits` table names appearing in the
schema page — filename/extension-independent — verified directly against
the extracted file's real header bytes before writing the spec, not
assumed.

### `timeout-minutes` justification comment corrected (Milestone XXX CI-reliability finding #1)

The existing comment cited only `evidence-upload-heavy-parser-archive.spec.ts`'s
(Milestone VVV) ~35s *typical*-case measurement, not its own two declared
`test.setTimeout` *worst*-case ceilings (150s + 180s = 330s combined) — a
real regression from this comment's own established practice (cite
declared worst case, not typical measurement) for the fault-injection
specs above it. Restated to cite the real 330s figure explicitly; the
number itself (`70`) is unchanged since real margin remains even folding
this in. The new `evidence-upload-fast-parsers.spec.ts` needed no
equivalent note — none of its 4 tests set a custom `test.setTimeout`, so
each is bounded by Playwright's own 30s per-test default, and measured
live at ~7s each.

## Verified live

Ran the new spec against the real, live dev stack (not a fresh isolated
test-stack build) — a deliberate choice, not a shortcut: `free -h` showed
genuinely tight headroom going into this cycle (266 MiB free, 2.2-2.5 GiB
"available", swap already in meaningful use), and standing up a second
full isolated stack for four lightweight FAST-tier specs would have added
real risk to the host (including to the already-running dev stack other
future cycles depend on) for no corresponding benefit — the same judgment
call and reasoning Milestone WWW already established. All 4 tests passed
cleanly (~6-7s each), then re-ran alongside `evidence-upload.spec.ts` and
`login.spec.ts` back-to-back to confirm no interference — all 6 passed.
The spec code itself is stack-agnostic (same `KRONOS_E2E_BASE_URL`-driven
page objects every other spec in this suite already uses against either
profile), so this is real verification of the same application code the
test-stack profile runs, not a different code path.

## Documented, not fixed this cycle

Carried forward from Milestone XXX, still open:

1. `TarArchiveParser` CI-wired coverage (its own real verification
   predates this initiative, via `poc/tar_container_unwrapping/`, and was
   never cited in any of UUU/VVV/WWW's "HEAVY-tier now covered" claims).
2. Intake-stage retry E2E coverage (carried since Milestone TTT).
3. `security-stack` also booting `kronos-backend`, RBAC access-denial
   specs, `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8.
4. Milestone RRR's "no workflow has ever run on real GitHub Actions"
   finding remains true.
5. The immediately-after-case-creation race and background-task-
   concurrency contention risk (both named in Milestone XXX) remain
   unconfirmed in practice — no spec built for either yet, deliberately,
   until one is actually observed.

New from this cycle:

6. `evidence-upload.spec.ts`'s own CloudTrail fixture is still synthetic
   (`tests/fixtures/samples/cloudtrail.json`), not the real
   Plaso-sourced `tests/fixtures/samples/real/aws_cloudtrail.jsonl` — a
   real, if minor, verification-rigor gap noticed while surveying FAST-tier
   coverage this cycle. Swapping it is cheap but out of scope for this
   cycle (not a coverage gap, a rigor gap on an already-covered parser).

## Status

Every FAST-tier parser this repository has now been driven through a real
top-level browser upload at least once, matching the same standard of
verification the HEAVY tier already had after Milestones UUU/VVV/WWW. The
platform's actual highest-volume real-world ingestion path (evtx, nginx,
suricata, chrome-history, plus the already-covered cloudtrail) is no
longer the comparatively unverified tier the last assessment cycle
flagged it as.

## Recommendation for the next cycle

1. `TarArchiveParser` CI-wired coverage — cheap, fixture-building script
   already exists (`poc/tar_container_unwrapping/`).
2. Swap `evidence-upload.spec.ts`'s synthetic CloudTrail fixture for the
   real `tests/fixtures/samples/real/aws_cloudtrail.jsonl` sample (cheap,
   docs/rigor improvement, not a coverage gap).
3. Intake-stage retry E2E coverage (carried since Milestone TTT).
4. This is the first implementation cycle since the last assessment
   (Milestone XXX) — not yet due for another cross-check on this
   initiative's own ~4-cycle assessment rhythm, but worth tracking as
   more implementation cycles land on top of this one.
