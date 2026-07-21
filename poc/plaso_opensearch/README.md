# PoC: linking real Plaso output into real OpenSearch

## What this links
- `poc/plaso/` — real Plaso 20260512 parse of a real Windows Prefetch
  sample, JSONL captured in `poc/plaso/output.jsonl`.
- `poc/opensearch/` — real OpenSearch 2.11.1 container, real
  `OpenSearchClient` from `src/adapter/opensearch/client.py`.

## What this actually does
Uses the **real** KronOS classes for every processing step — no
reimplementation of business logic:

- `FirecrackerLauncher._stream_records()` (`src/external/sandbox/firecracker.py`)
- `_annotate_records()` (`src/application/parsing_orchestration.py`)
- `ECSNormalizer.to_document()` / `build_index_name()`
  (`src/application/timeline_normalization.py`)
- `OpenSearchClient.bulk_index()` (`src/adapter/opensearch/client.py`)

The only stand-in is a `_FakeProc` object replacing `subprocess.Popen`,
exposing the real captured JSONL as `.stdout` — substituting the subprocess
plumbing, not any parsing/normalization/indexing logic (per CLAUDE.md B.5:
mock only external dependencies).

Run (with `kronos-poc-opensearch` from `poc/opensearch/` already up):
```
source ~/venv/bin/activate
python poc/plaso_opensearch/run_poc.py
```

## Result

All 5 real Plaso-derived records flowed through the real pipeline and were
indexed and retrieved successfully. Confirms, end-to-end, with the fixes
documented in `poc/plaso/README.md` applied:

- Real forensic timestamps (e.g. `2013-03-10T10:11:49.281250+00:00` for the
  prefetch execution event) survive all the way to the indexed OpenSearch
  document's `@timestamp` field — **not** replaced with ingest-time "now".
- `build_index_name()` correctly buckets records into separate monthly
  indices by their **event** timestamp (2 records from 2013-03 landed in
  `kronos-testorg-case-...-201303`; the other 3, which are filesystem-mtime
  events from when the sample was copied into this repo, landed in a
  separate `...-202607` index) — this is the intended per-tenant/per-month
  index rollover behavior, not a bug.
- The full `kronos.*` provenance block (evidence_id, case_id, org_id,
  org_alias, sha256, parser, parser_version, record_index, ingest_timestamp)
  round-tripped intact.

See `output.txt` for the full captured run.
