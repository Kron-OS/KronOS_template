# PoC: VolatilityModule dual-emit (StructuredArtifact + TimelineRecord)

**Scope decision this backs:** scenario 4 of the Artifacts-UI design
conversation — persist Volatility's structural snapshot as
`StructuredArtifact` (unchanged) **and** derive real `TimelineRecord`s for
process-creation events, so the existing Timeline tab can correlate a
memory-dump's process starts against every other evidence source in the
same case.

## Versions pinned

- `volatility3==2.28.0` (same pin as `poc/volatility_memory_module/` and
  `src/external/parsers/volatility.py`'s own `parser_version`).
- Real dev-stack OpenSearch 2.11.1 (`docker-opensearch-1`, already running).

## Real sample

Reuses the same real, classic `cridex.vmem` (Windows XP SP3,
Cridex/Feodo banking trojan) sample and scratch venv `poc/volatility_memory_module/`
already downloaded and verified — never re-fetched, never committed to
the repo (512 MiB). `/home/reca/scratch/kronos-poc-volatility/venv/` has
a working `volatility3==2.28.0` install (`vol` on that venv's own PATH).

## What this PoC calls

The real, unmodified `src.external.parsers.volatility.VolatilityModule.parse()`
and `.extract_artifacts()` — not a reimplementation. `VolatilityLauncher`
is patched only to point `python_bin`/`worker_path` at the scratch venv's
real `vol` install (this process's own interpreter has no volatility3),
the same monkeypatch seam `tests/unit/parsers/test_volatility.py` already
uses for its fakes, here wired to a **real** launcher instead of a fake
one. `src.config.Settings` is stood in for the same reason those unit
tests do (avoids needing every unrelated required env var in a throwaway
script) — the value it would have supplied is overridden regardless.

## Real, captured results (`output.txt`, 19/19 checks passed)

1. **`parse()` alone**: a real volatility3 subprocess run (7.66s — real
   `windows.pstree` → empty → real `windows.psscan` fallback, the same
   real finding `poc/volatility_memory_module/` already established for
   this sample) yields **16 real `TimelineRecord`s**, one per process row
   that carries a real, parseable `CreateTime`. Real `process.pid`/
   `process.name` populated (PID 908, `svchost.exe`), `event.category=
   ["process"]`, `event.type=["start"]`, `extra["volatility.plugin"] ==
   "windows.psscan"`, real `kronos.evidence_id` round-trip.
2. **`extract_artifacts()` right after `parse()`**: **0.00s** (vs
   `parse()`'s 7.66s) — the real proof the "one scan, not two" design
   works: the cached `VolatilityPluginResult` (via the module's
   `ContextVar`) is reused, no second real volatility3 subprocess runs.
   Still yields the real 2 `StructuredArtifact`s (`volatility.pstree`
   empty + `volatility.psscan` with all 17 real rows — one more row than
   the 16 `TimelineRecord`s, because one real row in this sample has no
   `CreateTime` and is correctly included in the structural snapshot but
   correctly excluded from the timeline dual-emit).
3. **`extract_artifacts()` called standalone** (no `parse()` first, e.g. a
   direct unit test or a hypothetical future orchestration change): real
   6.38s — genuinely re-runs the real scan, confirming the "still
   independently callable" fallback path is real, not just present in
   the code.
4. **Real OpenSearch ingestion + query-back**: all 16 real `TimelineRecord`s
   bulk-indexed via the real `ECSNormalizer`/`OpenSearchClient.bulk_index`
   into a real, disposable index (`kronos-poc-volatility-dual-emit-case-*`).
   A real `term` query on `process.pid=908` returns exactly 1 hit; a real
   `term` query on `event.category=process` returns exactly 16 hits (every
   dual-emitted record, no more, no less); a real document fetch confirms
   `kronos.evidence_id` round-trips and the dotted `extra["volatility.plugin"]`
   key correctly normalizes to a real nested `volatility.plugin` field
   (`ECSNormalizer._set_dotted`), not a literal dotted key.

All test/scratch documents deleted from the real index at the end of the
run (see `run_poc.py`'s own `finally` block).

## Status

Confirms the dual-emit design is safe and correct against real data before
`src/external/parsers/volatility.py` was written this way — the `src/`
change and this PoC were developed together (the row shape was already
known from `poc/volatility_pipeline_ingest/`'s own earlier real capture),
and this run is the required real, live confirmation per CLAUDE.md §F/§G.5
before treating the change as done.
