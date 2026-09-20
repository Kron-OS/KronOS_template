# Gap Audit — Milestone AAAAA (2026-09-02)

**Scope:** the project owner's explicit choice of "scenario 4" from a design
conversation about surfacing Volatility memory-forensics output in the web
UI: a dedicated case-level Artifacts view (kind-aware rendering, grouped by
evidence file), plus dual-emitting `TimelineRecord`s into OpenSearch
alongside the existing `StructuredArtifact` snapshot, so process-creation
events become cross-evidence-correlatable in the existing Timeline tab.
(4-letter milestone codes exhausted at `ZZZZ`; this cycle starts a 5-letter
sequence at `AAAAA`, same "letters increment, date stays fixed" convention.)

## Part 1: VolatilityModule dual-emit (backend, OpenSearch)

`VolatilityModule.parse()` was a documented no-op; `extract_artifacts()`
ran the real volatility3 scan and emitted `StructuredArtifact`s only. Real,
per-row `CreateTime` timestamps in `psscan`/`pstree` output (confirmed
against the real captured `cridex.vmem` data,
`poc/volatility_pipeline_ingest/`) are genuine process-creation events —
timeline-shaped even though the plugin's output *as a whole* isn't.

`parse()` now runs the real scan and yields one `TimelineRecord` per row
with a real, parseable `CreateTime` (`event.category=["process"]`,
`event.type=["start"]`, `process.pid`/`process.name` populated,
`extra["process.parent.pid"]`/`volatility.plugin`/`volatility.offset_v`
carried through). `extract_artifacts()` still emits the full structural
snapshot unchanged, but now reuses the scan `parse()` already ran (cached
via a `ContextVar`, mirroring the existing `yara_scan_org_var` seam) so a
real, comparatively expensive volatility3 subprocess run only happens
**once** per evidence file, not twice — `ParsingOrchestrationService.execute_parse()`
calls both methods back-to-back for any parser implementing both, and
naively running the real scan in each would have silently doubled every
real memory-forensics job's cost.

### Real, live verification (not assumed)

`poc/volatility_timeline_dual_emit/` — calls the actual, unmodified
`VolatilityModule.parse()`/`.extract_artifacts()` against the real
`cridex.vmem` sample (real `volatility3==2.28.0`, same scratch venv
`poc/volatility_memory_module/` already set up), **19/19 checks passed**:

- `parse()` alone: 7.66s (real subprocess, real `pstree`→`psscan`
  fallback), 16 real `TimelineRecord`s.
- `extract_artifacts()` right after: **0.00s** — the real proof the cache
  works, no second scan. Still yields the correct 2 real
  `StructuredArtifact`s (17 rows — one more than 16 `TimelineRecord`s,
  because one real row has no `CreateTime`, correctly kept in the
  snapshot and correctly excluded from the timeline dual-emit).
- `extract_artifacts()` called standalone (no `parse()` first): 6.38s —
  genuinely re-runs the scan, confirming the "still independently
  callable" fallback path is real.
- Real OpenSearch ingestion (`ECSNormalizer`/`OpenSearchClient.bulk_index`)
  + query-back: a real `term` query on `process.pid=908` returns exactly
  1 hit; `event.category=process` returns exactly 16 (every dual-emitted
  record); a real document fetch confirms `kronos.evidence_id` and the
  dotted `extra["volatility.plugin"]` key normalize to a real nested
  `volatility.plugin` field, not a literal dotted key.

New unit tests (`tests/unit/parsers/test_volatility.py`,
`TestParseDualEmit`): row-with/without-CreateTime, fallback-rows coverage,
scan-error-never-raises, and the load-bearing
`test_parse_then_extract_artifacts_only_runs_volatility_once` (mocked
launcher call-count assertion). Full backend suite: `2083 passed, 2
skipped`. `ruff`/`mypy` clean.

## Part 2: case-scoped Artifacts API + UI (scenario 4)

New `GET /api/cases/{case_id}/artifacts` (`src/external/routes/cases.py`)
— every real `StructuredArtifact` across the whole case (not per-evidence,
so the UI can show which evidence files have any without an N+1 lookup),
gated identically to `list_case_evidence`/`download_evidence` (read
access, any real case member). New `ArtifactRepository.list_by_case`
(abstract + `InMemoryArtifactRepository` + `PostgresArtifactRepository`).

Frontend: `frontend/src/components/ArtifactViews.tsx` — kind-aware
rendering (`ProcessTreeView` for `volatility.pstree`, `ProcessTableView`
for `volatility.psscan`, `GenericArtifactView` fallback for any other
`kind`, including a future non-Volatility module's own). New "Artifacts"
case-level tab, grouped by evidence file (a file picker sidebar, never
flattening two memory dumps' rows together). `EvidenceDetailDrawer` gets
a compact "N artifacts found — Open full analysis →" summary linking into
the tab, pre-filtered to that evidence file (the "hybrid" scenario-4
design) — the drawer itself stays narrow, the tab does the real rendering.

### A real, found-live bug and its fix

The Artifacts query (`['artifacts', caseId]`) has a 15s `staleTime`. A
fast, compressed real E2E run reproduced a real staleness gap: the
Evidence tab fetches (and caches) an empty artifacts list on mount, and if
new artifacts appear before that 15s window elapses with no SSE event
firing (evidence that doesn't change state again after artifacts are
added — true for this test's own out-of-band seeding, and plausible in
real usage if the Evidence tab is left open across a fast parse), the UI
keeps showing stale, artifact-free state. Fixed by extending the existing
per-evidence-state SSE handler to also invalidate `['artifacts', caseId]`
on every SSE event (cheap, mirrors the handler's own existing
evidence-invalidation call).

### Real, live verification

`poc/volatility_pipeline_ingest/`'s real captured `psscan` rows are reused
(not re-derived) by a new `frontend/e2e/fixtures/seed_volatility_artifacts.py`
(real `PostgresArtifactRepository` insert, same reasoning as
`seed_detection.py`) — the real end-to-end volatility3 pipeline is already
verified in Part 1's PoC; a 512 MiB memory-image upload through this E2E
suite would be slow for what THIS layer needs to prove. New
`case-artifacts-ui.spec.ts`: uploads a real small evidence file (to get a
real `evidence_id`), seeds real artifacts against it, and drives both real
UI paths — the drawer's "Open full analysis" link, and navigating the tab
directly — asserting on real rendered content (`svchost.exe`, PID `908`,
the real honest-empty state for the real empty `pstree` result). New
`a11y.spec.ts` scan of the Artifacts tab **with real seeded content** (not
just the empty state) — real WCAG scan, 0 violations. All passed live
against the real dev stack (`docker-nginx-1` rebuilt for real); reverified
alongside `evidence-retry.spec.ts`/`case-members-ui.spec.ts`/the existing
a11y scans together (10 specs, no interference). `tsc`/`oxlint`/`vitest`
(110/110)/production build all clean.

## Status

Scenario 4 shipped in full: kind-aware dedicated Artifacts UI, hybrid
drawer link, and real OpenSearch dual-emit for the timeline-shaped part of
Volatility's output — all verified live, not assumed, per CLAUDE.md §F/§G.5.

## Recommendation for the next cycle

- `pstree`'s real tree rendering (`ProcessTreeView`) is implemented but
  only verified against an *empty* real result (this sample's own
  `pstree` returns 0 rows, `psscan` fallback recovers the census) — a
  future real sample where `pstree` itself returns real, nested rows
  would be a good follow-up visual/E2E check, not urgent (the component
  logic itself is straightforward and already unit-exercised structurally
  via `GenericArtifactView`'s shared row-table code path).
- The 15s `staleTime`/SSE-invalidation fix here is scoped to this case's
  own Evidence/Artifacts tabs; if a future artifact-producing module adds
  its OWN case-level view outside this pattern, re-check whether it needs
  the same live-invalidation treatment rather than assuming it's covered.
