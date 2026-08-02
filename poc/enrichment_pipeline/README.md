# PoC: extensible enrichment pipeline — real asset-context enricher (roadmap M5/F1)

## Versions

- Postgres: `docker-postgres-1` (`postgres:16-alpine`), the same real,
  already-running dev-stack instance every other Postgres-backed PoC this
  session has used.

## Real design decisions (see `src/application/enrichment.py`'s own module
docstring for the full reasoning)

1. **Derived data lives in `TimelineRecord.extra`, namespaced
   `"enrichment.<source_name>."`, not a new top-level domain field.**
   `extra` already exists precisely for this (every parser's own dotted-key
   convention), and `ECSNormalizer` already flattens it into the indexed
   document — a new field would touch the normalizer, the index template,
   and every construction site across six parsers for no real benefit.
2. **Enrichment runs once, at ingest, before a record becomes an
   immutable, indexed artifact** — not as a job that reaches back and
   edits already-indexed OpenSearch documents. This platform's own
   chain-of-custody principle (WORM evidence, the append-only audit log,
   immutable sealed batches) treats an indexed forensic record as never
   mutated after the fact; enrichment computed before indexing is no
   different in kind from any other derived field a parser or the ECS
   field-mapping registry (A2) already attaches. `EnrichmentPipeline.enrich()`
   is deliberately pure/stateless so a *future* re-indexing job (not built
   here, an explicit follow-up) can re-run it against the original record
   and produce a fresh, independently-dated document — never retroactively
   edit history. Scenario (d) below demonstrates exactly that re-run,
   without needing a real scheduled job to exist yet.
3. **One concrete enricher: real, Postgres-backed asset context.**
   Identity-via-Keycloak-admin-API and vulnerability-via-external-feed
   were both explicitly out of scope (no existing Keycloak admin REST
   client in this codebase; an external network feed is arguably F2's own
   territory) — `AssetContextEnricher` proves the extensibility mechanism
   with one real, working, verified source.

## What this actually does

Drives the real, unmodified production classes end to end:

- **(a)** Seeds a real `Asset` row in real Postgres (`PostgresAssetRepository`),
  runs the real `EnrichmentPipeline`/`AssetContextEnricher` against a real
  `TimelineRecord` whose `host_name` matches, and checks **every original
  field individually** (`@timestamp`, `message`, `host_name`, `event_kind`,
  the whole `kronos` provenance block, `document_id`) is byte-for-byte
  unchanged — not just "some new keys appeared".
- **(b)** A record whose `host_name` has no matching real asset gets back
  the exact same object (`is` identity) — an honest "no enrichment", never
  a fabricated match.
- **(c)** Real cross-org isolation: the asset seeded for org A in step (a)
  never enriches an identical-hostname record scoped to a different real
  org B.
- **(d)** Updates the real asset's `criticality` in Postgres, re-runs
  enrichment against the **exact same original record object** from step
  (a), and confirms the derived data reflects the real update while the
  original record's own fields are still identical — proving the
  design decision in point 2 above actually works as intended.
- **(e)** Wires the same real pipeline into a real
  `ParsingOrchestrationService.execute_parse()` call — a real parser
  double yields one record, the real `TimelineIngestionService` indexes it
  into a real (`InMemoryOpenSearchClient`) ECS document — confirming the
  enrichment fields land at the expected nested `enrichment.asset.*` path
  in the actual indexed document shape, not just in the pipeline's own
  in-memory return value.

Run:
```
~/venv/bin/python3 poc/enrichment_pipeline/run_poc.py
```

## Result: `output.txt` — 19/19 real checks passed on the first run

No bugs found in the enrichment mechanism itself during this pass. One
real bug **was** found and fixed while writing this PoC's own supporting
unit test (`tests/unit/application/test_parsing_orchestration.py`): a
stray, unused `count += 1` line in the new `_apply_enrichment()` wrapper
generator in `src/application/parsing_orchestration.py` referenced a local
variable that was never initialized in that function (leftover from
drafting against the unrelated `_annotate_records` function, which does
track a count for `document_id` generation) — caught immediately by the
real end-to-end orchestration test failing with
`UnboundLocalError: cannot access local variable 'count'`, not a silent
issue. Removed; the function needs no counter at all.

## Explicitly flagged, not yet done

- **Only one enricher exists** (asset context) — the roadmap's own stated
  scope is architectural extensibility, not source coverage (mirrors this
  session's own repeated precedent: E2/E3/D4 each built exactly one real
  source too). Identity (Keycloak-backed) and vulnerability (external
  feed) enrichers are real, legitimate future work, not this item's gate.
- **No scheduled re-enrichment job** — `EnrichmentPipeline.enrich()`'s own
  pure/stateless design makes one trivial to build later (scenario (d)
  above proves the mechanism), but no such job exists yet; this item's
  job was proving the mechanism works when invoked, not automatic
  invocation (mirrors D3/D4/D5's own precedent for sealing/normalization
  scheduling).
- **No HTTP route for managing the asset inventory** — backend-only scope
  this pass, mirrors E3/E4/E5's own backend-only precedent.
