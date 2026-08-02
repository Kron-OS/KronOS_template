# PoC: Deterministic rarity/frequency baseline scoring (roadmap M6/G1)

**Objective (roadmap):** "Classic DFIR least-frequency-of-occurrence via
plain OpenSearch aggregations (terms, cardinality, first-seen/last-seen on
@timestamp). No ML. Fully replayable. Ship before any ML -- it delivers most
of the value attributed to UEBA and gives a labelled baseline to measure
models against."

**This starts Milestone M6** (docs/NEXTGEN_SOC_ROADMAP.md). M5 (F1-F4:
enrichment, threat intel, correlation, risk scoring) completed immediately
before this pass.

## Versions pinned (CLAUDE.md SS F.2 step 1)

- OpenSearch: `2.11.1` (`docker-opensearch-1`, already running on this host
  -- confirmed via `docker ps` and `GET /_cluster/health` returning
  `"status":"yellow"`/`"number_of_nodes":1` for real).
- `opensearch-py[async]>=2.6` (`pyproject.toml`) -- the real installed
  version in `~/venv` is `3.2.0`
  (`python3 -c "import opensearchpy; print(opensearchpy.__version__)"`),
  same as every prior PoC in this repo that touched `OpenSearchClient`.
- `httpx` (already a project dependency) -- used directly for the new
  `RarityBaselineClient`, mirroring `CorrelationClient`/`FindingsClient`'s
  own precedent exactly (admin-credentialed `httpx.AsyncClient`, not
  `opensearch-py`'s own `search()` wrapper).

## Real docs/examples used (CLAUDE.md SS F.2 step 2)

`terms`/`cardinality`/`min`/`max` aggregations are old, extremely standard
OpenSearch/Elasticsearch features -- but per CLAUDE.md SS F.1 ("plausible
code... is not verification"), every claim below was confirmed against the
**real, live 2.11.1 cluster's own response JSON**, not assumed from prior
Elasticsearch/OpenSearch familiarity:

1. Ran ad hoc exploratory queries directly against `docker-opensearch-1`
   (`https://localhost:9200`, `admin:admin`) before writing any `src/`
   code -- see `output.txt`'s Appendix ("Exploration A-D") for the raw
   captured JSON from these runs.
2. Only after confirming the real shapes did `src/adapter/opensearch/
   rarity_baseline_client.py` and `src/application/rarity_scoring.py` get
   written, then this PoC's `run_poc.py` was written to drive those real,
   shipped classes (not ad hoc queries) for the final captured run below.

## Real, load-bearing findings from the exploration phase

**Finding 1 -- terms-aggregation ORDER is the single most important design
decision, and the default is backwards for this feature.** OpenSearch's
`terms` aggregation defaults to ordering buckets by `_count` DESCENDING
(most common first). Verified live: a 236-document corpus with 30 distinct
`process.name` values and `size: 10` (Exploration B):

```
DESC top10 keys: ['svchost.exe', 'cmd.exe', 'explorer.exe', 'conhost.exe',
                   'powershell.exe', 'notepad.exe', 'chrome.exe',
                   'outlook.exe', 'teams.exe', 'onedrive.exe']
any rare in desc top10? False
```

Zero of the 20 genuinely rare (single-occurrence) values appear. The
**exact same query** with `"order": {"_count": "asc"}` instead:

```
ASC top10 keys: ['raretool_00.exe', 'raretool_01.exe', ..., 'raretool_09.exe']
all rare in asc top10? True
```

`OpenSearchRarityBaselineClient` (`src/adapter/opensearch/
rarity_baseline_client.py`) always requests ascending order. Getting this
wrong would have silently made the entire feature useless (a "least
frequency of occurrence" hunt that only ever returns the most frequent
values) with no error anywhere -- exactly the class of bug CLAUDE.md SS F
exists to catch before it ships.

**Finding 2 -- a wildcard `index_pattern` matching zero real indices omits
`"aggregations"` from the response entirely** (Exploration C) -- not an
empty dict, not a 404 (unlike `FindingsClient`'s concrete-index 404 case).
`_parse_aggregation_response` (`src/application/rarity_scoring.py`) never
assumes the key exists; confirmed by `tests/unit/application/
test_rarity_scoring.py::test_missing_aggregations_key_handled_honestly_as_empty_result`
and by this PoC's own Scenario 4 against a real brand-new org.

**Finding 3 -- `first_seen`/`last_seen` sub-agg values arrive as
`{"value": <epoch_ms float>, "value_as_string": "<ISO-8601>"}`** (note:
`value` is a **float**, e.g. `1784170800000.0`, not an int) -- the parser
uses `value_as_string` directly rather than re-deriving a datetime from the
epoch-millis float itself (simpler, and avoids a float->int->datetime
round-trip that has its own edge cases).

## Real gap found and fixed during this PoC's own first run

The PoC's first run (see `git log`/local history is not kept, but the
finding is real and worth recording): the first attempt used
`window_end = datetime(2026, 8, 1)`, but the 20 synthetic rare values were
spread from `2026-07-15` to `2026-07-15 + 19 days = 2026-08-03` -- 3 of them
(dated Aug 1-3) fell **outside** the query's own `@timestamp` range filter.
Real captured result: `total_docs=233` (not 236), `distinct_value_count=27`
(not 30) -- exactly 3 missing on both counts. This was the query's range
filter working **correctly** (excluding data genuinely outside the
requested window), not a bug in `RarityBaselineClient`/`RarityBaselineScorer`
-- but it is exactly the kind of "did you actually check the real number,
not just assume it" gap CLAUDE.md SS F is designed to surface. Fixed by
widening the PoC's own window to `2026-08-15`; `run_poc.py`'s comment next
to `window_end` documents this so a future editor doesn't reintroduce it.

## What `run_poc.py` actually does (drives the real, shipped classes)

1. `OpenSearchClient.ensure_index_template()` -- real `PUT
   _index_template/kronos-template` against the live cluster.
2. `OpenSearchClient.bulk_index()` -- indexes 236 real documents into a
   throwaway `kronos-poc-rarity-<hex>-case-scratch-202607` index: 10
   "common" `process.name` values (6-50 occurrences each, spread across a
   28-day cycle) plus 20 genuinely rare single-occurrence values (each on
   its own known day).
3. Confirms the real ordering gap (Finding 1 above) one more time inline,
   directly against this run's own real data.
4. `RarityBaselineScorer.score_field_rarity()` (the real, shipped
   orchestration class) with `max_distinct_values=10` -- proves the cap is
   honestly hit (`returned_value_count=10 < distinct_value_count=30`) and
   that every one of the 10 returned values is genuinely rare
   (`count==1`), matching the exact documented rarity formula
   (`1 - 1/236 = 0.9958`).
5. Same call with `max_distinct_values=100` (uncapped) -- proves
   `raretool_00.exe` (count=1, rarity 0.9958) scores strictly higher than
   `svchost.exe` (count=50, rarity `1 - 50/236 = 0.7881`).
6. First-seen/last-seen correctness against a real, individually-known
   timestamp (`raretool_05.exe`), and confirms a multi-occurrence value's
   `first_seen != last_seen`.
7. Zero-matching-indices edge case against a real, never-ingested-into
   org alias -- honest empty result, no crash.
8. Replayability: re-runs the exact same call twice, asserts byte-identical
   `RarityBaselineResult` -- the defining contrast with G2 (next roadmap
   item), whose RCF/Anomaly-Detection-plugin-based score is an **online
   model that continuously updates its own state**, so it is NOT
   reproducible months later from the same stored input and must never be
   the evidentiary basis of a finding. G1's whole reason for existing is to
   be the opposite: the exact same query against the exact same (unchanged)
   index data always produces the exact same score, full stop.

## Real captured result: 16/16 checks passed

See `output.txt` for the full, unedited run. Headline numbers:

- `total_docs=236`, `distinct_value_count=30` (both exact matches to what
  was actually indexed).
- Capped query (`size=10`, ascending): `returned_value_count=10`, all 10
  genuinely rare (`count=1`, `rarity_score=0.9958` each).
- Uncapped query (`size=100`): all 30 distinct values returned;
  `raretool_00.exe` rarity `0.9958` > `svchost.exe` rarity `0.7881` --
  rare correctly ranks above common.
- `raretool_05.exe` (indexed at a known timestamp) real
  `first_seen == last_seen ==` that exact timestamp.
- `svchost.exe` (50 occurrences across 28 days) real
  `first_seen != last_seen`.
- Zero-matching-indices (brand-new org): honest all-zero empty result.
- Replay: identical call twice -> byte-identical `RarityBaselineResult`.

## Why no in-memory test double was built for `src/`

`CorrelationClient`/`FindingsClient` (the two prior instances of this
"read-only ABC + real httpx impl" shape) do **not** have shared production
`InMemory*` doubles either -- their consuming services
(`CorrelationSyncService`, `DetectionSyncService`) each define a small,
test-local fake subclass in their own test file
(`_FakeCorrelationClient`/`_FakeFindingsClient` in
`tests/unit/application/test_correlation_sync.py` /
`test_detection_sync.py`) rather than a shared class. G1 has **no
consuming application service in this pass** (see roadmap STATUS note --
deliberately standalone, not wired into `DetectionRiskScorer`), so there is
no caller that needs a fake yet. `tests/unit/application/
test_rarity_scoring.py` follows the exact same idiom
(`_FakeRarityBaselineClient`, test-local). If/when G1 gains a real consumer
(a scheduled hunting job, a route), that pass can promote this to a shared
class the way `InMemoryOpenSearchClient` earned shared status by being
reused across many tests -- not before.

## Run it yourself

```
~/venv/bin/python3 poc/rarity_baseline_scoring/run_poc.py
```

Requires `docker-opensearch-1` running and reachable at
`https://localhost:9200` with `admin:admin` (already the case on this
host). Cleans up its own throwaway indices (`kronos-poc-rarity-*`) in a
`finally` block regardless of pass/fail.
