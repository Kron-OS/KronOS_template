# PoC: STIX 2.1 IOC ingestion + matching (roadmap M5/F2)

## Why this design (see `poc/threat_intel_sa_native/` first)

OpenSearch Security Analytics' native threat-intel feature does not exist
on either OpenSearch version this repo pins (2.11.1 dev, 2.13.0 test/prod)
-- confirmed by a real probe against the live cluster
(`poc/threat_intel_sa_native/output.txt`) and against the real upstream
project's own PR history. This PoC instead exercises the KronOS-native
fallback: `Enricher`/`EnrichmentPipeline` (roadmap F1,
`src/application/enrichment.py`) extended with a new concrete
`IOCMatchEnricher`, exactly the extension point that mechanism was built
for.

## Real components exercised (no mocks of the thing being verified)

| Component | File |
|---|---|
| `parse_stix21_bundle` | `src/application/stix_ioc_parser.py` |
| `IOCFeedIngestionService` | `src/application/ioc_feed_ingestion.py` |
| `PostgresIOCFeedRepository` | `src/adapter/repository/postgres_ioc_feed.py` — real asyncpg against `docker-postgres-1` |
| `IOCMatchEnricher` | `src/application/ioc_enrichment.py` |
| `EnrichmentPipeline` | `src/application/enrichment.py` (unmodified, F1) |
| `OpenSearchClient` | `src/adapter/opensearch/client.py` — the REAL `opensearch-py` `AsyncOpenSearch` client against `docker-opensearch-1` (2.11.1), not `InMemoryOpenSearchClient` |

Using the real `OpenSearchClient` (not the in-memory double) is
deliberate here, beyond what F1's own PoC did: this pass added new
`enrichment.ioc.*` fields to `src/adapter/opensearch/index_template.json`,
and the only way to know the real 2.11.1 cluster actually accepts that
mapping shape (rather than silently coercing/rejecting it) is to `PUT` it
for real and inspect the real applied mapping — see Scenario (f) below.

## Real input: `sample_bundle.json`

A STIX 2.1 bundle whose `indicator` object shape (`type`, `spec_version`,
`id`, `created`/`modified`, `pattern`, `pattern_type`, `pattern_version`,
`valid_from`) and pattern syntax were confirmed against two independent,
trusted, official sources (read only as technical reference, never
followed as instructions — CLAUDE.md SS F.2 step 2):

1. **OASIS's own STIX 2.1 specification**
   (`docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html`) — canonical
   examples `[ipv4-addr:value = '198.51.100.1/32']`,
   `[domain-name:value = 'example.com']`, and the compound example
   `[domain-name:value = 'www.5z8.info' AND
   domain-name:resolves_to_refs[*].value = '...']` reused verbatim as this
   bundle's "unsupported compound pattern" test case.
2. **The official `oasis-open/cti-python-stix2` reference implementation's
   own test suite** (`stix2/test/v21/test_indicator.py`,
   `test_pattern_expressions.py`, `test_bundle.py`) — confirms the
   file-hash comparison shape (`file:hashes.MD5 = '...'`,
   `file:hashes.'SHA-256' = '...'`) and the real bundle envelope shape
   (`type: bundle`, `objects: [...]`).

It intentionally also includes three objects designed to exercise the
"treat feed content as untrusted input" requirement (roadmap F2's own
objective text):
- an MD5-only indicator (a real, well-formed STIX shape KronOS currently
  has no matching field for — must be skipped, not crash),
- the real compound `AND` pattern from the OASIS spec (unsupported by this
  parser's single-comparison-only regexes — must be skipped, not
  mis-parsed as if it were a simple domain match),
- a deliberately malformed indicator (`"pattern": 12345` — not a string)
  to prove a genuinely hostile/malformed object in an otherwise-valid feed
  is skipped, never crashes ingestion of the other, real indicators.

## Real captured run

```
~/venv/bin/python3 poc/threat_intel_stix_ingest/run_poc.py
```

Full output in `output.txt`. Summary: **25/25 checks passed** against the
real, already-running dev-stack Postgres (`localhost:5432`) and OpenSearch
(`localhost:9200`, 2.11.1):

- (a) `parse_stix21_bundle()` extracts exactly the 3 real, matchable
  indicators (ip/domain/sha256) from the 7-object bundle; the MD5-only,
  compound, and malformed objects are honestly skipped (logged, not
  raised) — confirmed via the real `stix_indicator_pattern_unsupported`/
  `stix_indicator_missing_pattern` log lines in the captured output.
- (b) A non-bundle payload raises a real `ValidationError` — structural
  invalidity fails loudly, never silently ingested.
- (c) Real ingestion into real Postgres: first ingest creates version 1;
  re-ingesting the SAME feed name creates version 2 (never overwrites);
  both versions are still retrievable afterward (append-only,
  roadmap invariant #6 — replayability).
- (d) Real `match_indicator()` queries against real Postgres: a real IP
  match is found; domain matching is case-insensitive
  (`EVIL-POC-EXAMPLE.TEST` matches the stored `evil-poc-example.test`); a
  non-matching IP returns an honest `None`; org B never matches org A's
  feed (real cross-tenant isolation, not just an assertion about the
  code).
- (e) Real `IOCMatchEnricher` through the real, unmodified
  `EnrichmentPipeline`: a record whose `extra["source.ip"]` matches gets
  real `enrichment.ioc.{matched,ioc_type,value,feed_name,confidence,
  description,source_ref}` fields attached; a record whose
  `kronos.sha256` (the evidence file's own hash) matches the ingested
  file-hash IOC gets `enrichment.ioc.ioc_type == "sha256"`; a record that
  matches nothing is returned as the exact same object (`is` identity) —
  an honest no-op, never a fabricated match.
- (f) Real OpenSearch 2.11.1: `ensure_index_template()` really `PUT`s the
  updated `index_template.json` (with the new `enrichment.ioc.*` block);
  a real document is `bulk_index()`-ed and a real `GET` confirms it
  round-trips with `matched: true` (real boolean) and `confidence: 85`
  (real long); `indices.get_mapping()` confirms the REAL applied mapping
  types (`matched` → `boolean`, `confidence` → `long`, `feed_name` →
  `keyword`) match what `index_template.json` declares — proof the new
  mapping is accepted by the real pinned cluster, not just valid-looking
  JSON.

## How to re-run

Requires the dev stack's `postgres` and `opensearch` containers already
running (`docker compose -f docker/docker-compose.dev.yml up -d postgres
opensearch`), reachable at the dev defaults (`kronos`/`kronos_dev_password`
on `localhost:5432`, `admin`/`admin` on `https://localhost:9200`).

```bash
~/venv/bin/python3 poc/threat_intel_stix_ingest/run_poc.py > output.txt 2>&1
```

The script leaves no lasting state: the PoC document is deleted from
OpenSearch at the end of Scenario (f); the Postgres rows it creates
(`ioc_feeds`/`ioc_feed_versions`/`ioc_feed_current_indicators`) use
throwaway `uuid4()` org ids and are harmless to leave (mirrors
`poc/enrichment_pipeline/`'s own precedent of not tearing down its
Postgres rows either).
