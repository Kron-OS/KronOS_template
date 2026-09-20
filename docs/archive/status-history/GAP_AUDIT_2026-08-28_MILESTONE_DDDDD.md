# Gap Audit — Milestone DDDDD (2026-09-03)

**Scope:** checkpoint 2 of the project owner's "huge work" request — frontend
rendering for Milestone CCCCC's 5 new eager Volatility plugins. Full plan at
`/home/reca/.claude/plans/abstract-imagining-umbrella.md` (approved). This
checkpoint: two-level Artifacts nav (evidence file → kind cluster) and
kind-aware views for the new artifact kinds, including a genuinely new
"suspicious" card layout for `malfind`. The on-demand `dumpfiles`/registry-
drilldown path with new derived-artifact storage (Milestones EEEEE-FFFFF)
is a separate, later checkpoint — not this doc.

## The real issue / what changed

Before this cycle, `ArtifactsTab` (`CaseDetailPage.tsx`) had one nav level
(evidence file) and stacked every artifact's full content vertically for
the selected file — fine for the original 1-2 kinds per file, but Milestone
CCCCC's real pipeline now produces 7 kinds per memory-dump file (confirmed
live: `pstree`/`psscan`/`dlllist`/`cmdline`/`malfind`/`filescan`/
`registry.hivelist`), and stacking a real 2500-row DLL table above a
4-region suspicious-activity card would push the highest-signal content
off-screen.

- `frontend/src/components/ArtifactViews.tsx`: new `DllListView`
  (hex-formatted `Base`), `FileScanView`, `HiveListView` (small, focused
  column sets reusing the existing table pattern — hides volatility3's own
  always-`"Disabled"` `File output` column). New `MalfindView`: a
  genuinely different card layout (not a table) with amber/red accent
  styling, `Protection` surfaced prominently, a collapsed-by-default
  hexdump toggle, and an honest "N suspicious regions found" /
  "no injected/suspicious memory regions detected" banner reusing the
  established honest-empty-state convention. `cmdline`'s real row shape
  (`{PID, Process, Args}`) verified to already render adequately through
  the existing `GenericArtifactView` fallback — no dedicated component
  added for it, per the plan's own "don't build one if the generic table
  already looks right" guidance.
- `frontend/src/pages/CaseDetailPage.tsx`: `ArtifactsTab` gained a real
  second nav level — a clustered pill strip (`ArtifactKindNav`) across the
  kinds a selected evidence file actually produced, grouped the way an
  analyst works a case (Process: tree/scan/cmdline/dlllist; Suspicious:
  malfind; Files & Registry: filescan/hivelist; any future unrecognized
  kind falls into an "Other" cluster, never silently hidden). Same-kind
  `StructuredArtifact` row-batches (`ArtifactIngestService`'s existing
  size-cap-driven splitting) are merged client-side before rendering — a
  storage implementation detail the UI shouldn't expose as separate
  sections. **Real bug caught and fixed during implementation**: the new
  `selectedKind` state/effect were initially placed after the component's
  early-return checks (loading/error/empty states) — a Rules-of-Hooks
  violation (hooks must run unconditionally on every render). Caught before
  any commit by running `tsc`/`oxlint` plus a live browser check; moved
  both to the top of the component alongside the existing `selectedEvidenceId`
  state.

## Real, live verification (commands + actual captured output)

- Real browser check against the actual Milestone CCCCC pipeline-
  verification evidence (`cridex.vmem`, 7 real `structured_artifacts` rows
  already in Postgres from that milestone's own live pipeline run): all 3
  clusters visible, every kind selectable and renders real content without
  error, including the honest zero-state for `malfind` (cridex.vmem's
  already-documented 0-row finding) and real `svchost.exe`/17-process data
  under Process List (scan).
- `frontend/e2e/fixtures/seed_volatility_artifacts.py` extended with real
  row shapes trimmed from `poc/volatility_multiplugin/output.txt`'s own
  captured output against a real 1.6GB user-uploaded Windows 7 image
  (`cridex.vmem` itself legitimately returns 0 rows for the 5 new plugins —
  a real, already-documented XP-era limitation — so it has no real
  non-empty rows to seed from for those kinds).
- `case-artifacts-ui.spec.ts` rewritten for the new nav (7 seeded kinds,
  clicks through Process Tree → Process List (scan) → Loaded DLLs →
  Suspicious Regions → Files in Memory → Registry Hives, asserting real
  content at each step, including the real `PAGE_EXECUTE_READWRITE`
  malfind tell) — **1/1 passed** live, and again inside a 4-spec regression
  cluster with `a11y.spec.ts`'s Detections/Detection-detail scans (no
  interference).
- `a11y.spec.ts`'s Artifacts-tab scan extended to cover both the default
  state (Process Tree, honest-empty) and the new `MalfindView` state (a
  genuinely different, distinctly-styled component from every other
  table/tree already scanned) — **found and fixed a real WCAG AA
  color-contrast violation** in the new cluster-label styling
  (`text-gray-400 dark:text-gray-600` measured 2.48:1, needs 4.5:1) by
  switching to this same file's own already-compliant convention
  (`text-gray-600 dark:text-gray-400`, used consistently elsewhere in
  `CaseDetailPage.tsx`) — required a real `docker compose build nginx &&
  up -d nginx` redeploy before/after to catch and re-verify. Both states:
  **0 violations** after the fix.
- `npx tsc -b`/`npx oxlint`/`npx vitest run` (120/120) clean throughout.
- Full backend suite unaffected (`2099 passed, 2 skipped` — this cycle
  touched frontend only).

## Status

Done and live-verified. All 5 new eager Volatility artifact kinds have
real, kind-aware rendering; the Artifacts tab correctly scales to a
7-kind-per-file real dataset without stacking-into-oblivion; the new
`MalfindView` component is a11y-clean.

## Recommendation for the next cycle

Milestone EEEEE: PoCs for the on-demand path (`windows.dumpfiles` real
byte extraction, scoped `windows.registry.printkey` drilldown,
`S3DerivedArtifactStorage` against real MinIO) per the approved plan's
Stage 3/verification design — the highest-remaining-risk item is the
`dumpfiles` bytes-transport mechanism (temp-file vs. base64), still
undecided pending that PoC's real measurement.
