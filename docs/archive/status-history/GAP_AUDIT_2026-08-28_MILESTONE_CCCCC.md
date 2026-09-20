# Gap Audit — Milestone CCCCC (2026-09-02)

**Scope:** checkpoint 1 of the project owner's "huge work" request — real
CERT-analyst-facing memory-forensics coverage (DLLs, suspicious executables,
registry keys, dumped files). Full plan at
`/home/reca/.claude/plans/abstract-imagining-umbrella.md` (approved). This
checkpoint: the shared-context multi-plugin worker architecture, the five
new eager plugins landing as real `StructuredArtifact`s, and full backend
verification. Frontend rendering (Milestone DDDDD) and the on-demand
dumpfiles/registry-drilldown path (Milestones EEEEE-FFFFF) are separate,
later checkpoints of the same plan — not this doc.

## The real issue / what changed

`VolatilityModule` previously ran exactly two plugins (`windows.pstree` with
a conditional `windows.psscan` fallback) via a worker script that shelled
out to the `vol` CLI once per plugin, redoing the expensive part (DTB/page-
table detection + kernel symbol table resolution) from scratch every time.
Real-verified this session that volatility3's own framework API lets one
resolved automagic context serve many plugins cheaply — this unlocks running
a real, CERT-analyst-relevant plugin set (loaded DLLs, command lines,
injected/suspicious memory regions via `malfind`, file objects resident in
memory, registry hive enumeration) on every memory-dump upload, not just a
process tree.

- `docker/volatility/kronos-volatility-worker.py`: rewritten to use
  volatility3's framework API directly (`contexts.Context()`,
  `automagic.available()`, looped `plugins.construct_plugin()` reusing one
  context, row extraction via `volatility3.cli.text_renderer.JsonRenderer`'s
  own visitor) instead of shelling out to `vol` per plugin. Per-plugin error
  isolation (one plugin's failure never sinks the others sharing the
  context) and a wall-clock budget guard across the whole plugin set
  (skips remaining plugins honestly if exhausted, never silently absent).
  `pstree`/`psscan` no longer need conditional fallback logic — both are
  simply two of the seven eager plugins now and run unconditionally (cheap
  context reuse, not a second `vol` subprocess).
- `src/external/sandbox/volatility_launcher.py`: `VolatilityPluginResult`
  (single plugin, primary/fallback pair) replaced by
  `VolatilityMultiPluginResult`/`VolatilityPluginOutcome` (one outcome per
  requested plugin, independent status/rows/error). `run()` takes a plugin
  sequence. New `DEFAULT_PLUGINS` constant (7 real plugins). Outer
  wall-clock margin widened 30s→60s and default timeout 300s→600s — real,
  measured reasons (multi-plugin sequential cost), not arbitrary bumps.
- `src/external/parsers/volatility.py`: `extract_artifacts()` loops every
  successful plugin outcome into its own `StructuredArtifact`(s) (existing
  size-capping-into-multiple-artifacts convention, now driven by N results).
  New `kind`s: `volatility.dlllist`, `volatility.cmdline`, `volatility.malfind`,
  `volatility.filescan`, `volatility.registry.hivelist`. `parse()`'s
  `CreateTime` dual-emit unchanged in effect (confirmed live none of the 5
  new plugins carry `CreateTime`) but re-implemented as an explicit
  preference (`pstree` then `psscan`) over the multi-plugin result to avoid
  double-emitting the same process-creation event when both plugins recover
  the same process — a real, new risk the old primary/fallback design
  didn't have to consider (today, if `pstree` succeeded, `psscan` never even
  ran; now both run unconditionally). New `_PLUGIN_KIND_OVERRIDES` for
  `malfind` specifically — its canonical import path moved to
  `windows.malware.malfind.Malfind` in the pinned `volatility3==2.28.0`
  (deprecation warning confirmed live for the old `windows.malfind.Malfind`
  path), and naive kind-derivation would otherwise produce
  `volatility.malware.malfind` instead of the intended, stable
  `volatility.malfind`.

## Real, live verification (commands + actual captured output)

- `poc/volatility_multiplugin/`: real run of the shared-context multi-plugin
  approach against both `cridex.vmem` (public, redistributable) and a real
  1.6 GB user-uploaded Windows 7 image already in this org's MinIO
  (`Challenge.raw`, not redistributed). Confirmed every plugin after the
  first constructs in ~0.08-0.5s regardless of sample, vs. the first
  plugin's full automagic cost (13.2s for `cridex.vmem`, 0.3s for
  `Challenge.raw`). Real, rich data recovered from `Challenge.raw`: 10
  processes (pstree), 53 (psscan), 2547 DLL rows, 53 command lines, **4 real
  suspicious/injected memory regions** (one in `explorer.exe` with
  `PAGE_EXECUTE_READWRITE`), 3232 file objects, 12 registry hives.
- Real worker-script verification (the actual, final rewritten script, not
  just the probe): 3 real runs captured in
  `poc/volatility_multiplugin/output.txt` — full default plugin set against
  `cridex.vmem` (matches PoC numbers exactly), full set against
  `Challenge.raw` plus one deliberately invalid plugin name (confirms
  per-plugin error isolation: 7/8 ok, 1 honest `scan_error`, top-level
  `status: "ok"`), and a deliberately tiny `--timeout-seconds 1` budget
  (confirms honest `skipped_timeout_budget` reporting for the plugin that
  didn't fit).
- Backend unit suite: `tests/unit/parsers/test_volatility.py` and
  `tests/unit/test_volatility_launcher.py` fully rewritten for the new
  `VolatilityMultiPluginResult`/`VolatilityPluginOutcome` shape (using the
  real dataclasses as test fixtures, not hand-rolled fakes, to avoid drift)
  — 41 passed, 1 skipped (the real-sample/real-volatility3 test, gated on
  env vars not set in this run, per the existing `pytest.importorskip`-style
  convention). Full backend suite: `~/venv/bin/python3 -m pytest -q --no-cov`:
  **2099 passed, 2 skipped**. `ruff check`/`mypy` clean on every changed
  file (one confirmed pre-existing, unrelated mypy finding in
  `test_volatility_launcher.py` left alone, verified via `git stash`).
- **Live, real, full autonomous-pipeline verification** (not just a manual
  `docker exec`): rebuilt+redeployed `celery-worker-plaso` (the new worker
  script is baked into the image at build time, not volume-mounted), then
  re-ran `poc/volatility_pipeline_ingest/run_ingest.py` +
  `verify_artifacts.py` (real login → real case → real presigned-PUT upload
  of the real 512 MiB `cridex.vmem` → real `finalize_upload` → real Celery
  `q.intake`→`q.parse.plaso` → the rewritten `VolatilityModule` →
  `ArtifactIngestService` → real Postgres, then polled the real evidence to
  `COMPLETE` and queried `structured_artifacts` directly). Real result:
  **7 real rows landed, one per eager plugin**
  (`volatility.pstree`/`psscan`/`dlllist`/`cmdline`/`malfind`/`filescan`/
  `registry.hivelist`, `psscan` with the real 17-process census), evidence
  state `COMPLETE`, every row's `evidence_id`/`case_id`/`sha256` matched the
  real upload, verdict `PASS` — up from 2 rows pre-CCCCC. See
  `poc/volatility_pipeline_ingest/README.md`'s new addendum and its
  `artifact_verification.json` for the full captured output.

## Status

**Done and live-verified end to end.** Backend architecture, unit tests
(41 passed, full suite 2099 passed/2 skipped), PoC verification (both the
architecture spike and the real worker script), and the real autonomous
pipeline (real upload through to real Postgres rows) are all complete.

## Recommendation for the next cycle

Milestone DDDDD: frontend two-level Artifacts nav (evidence file → kind)
plus kind-aware views for the 5 new artifact types, per the approved plan's
Stage 2/4 design (`DllListView`/`CmdLineView`/`FileScanView` reusing the
existing table pattern, new `MalfindView` card layout for the "suspicious"
framing). Then Milestones EEEEE-FFFFF: the on-demand `dumpfiles`/registry-
drilldown path (new `DerivedArtifactStorage`, Celery task, audit events,
Child Files + registry browser UI).
