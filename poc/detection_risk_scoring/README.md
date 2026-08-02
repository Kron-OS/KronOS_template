# PoC: Risk scoring + alert prioritization (roadmap M5/F4)

**Objective (roadmap):** "Deterministic, explainable scoring combining asset
criticality, identity privilege, IOC confidence, rule severity."

## Versions pinned (CLAUDE.md SS F.2 step 1)

- OpenSearch: `2.11.1` (`docker-opensearch-1`, already running on this host;
  confirmed via `docker ps` and `GET /_cluster/health`).
- `opensearch-py[async]>=2.6` (`pyproject.toml`) -- the real installed
  version in `~/venv` is `3.2.0` (`python3 -c "import opensearchpy;
  print(opensearchpy.__version__)"`), used to confirm the real
  `AsyncOpenSearch.mget()` signature via `inspect.signature` before writing
  `OpenSearchClient.get_documents_by_id`.
- `httpx` `0.28.1` (already a project dependency), used only in this PoC
  script to hit the SA rules-search endpoint directly for Scenario 0.

## Real docs/examples used (CLAUDE.md SS F.2 step 2)

- The **live cluster's own** `_plugins/_security_analytics/rules/_search
  ?pre_packaged=true` response -- not the Sigma spec's documentation, and
  not memory -- is the source of truth for the real severity vocabulary
  (see Scenario 0 below). Every one of this repo's own prior PoCs that
  touched SA (`poc/security_analytics_correlation/`,
  `poc/threat_intel_sa_native/`) established this same "read the live
  cluster, not the docs" precedent for anything SA-specific.
- `opensearch-py`'s own `AsyncOpenSearch.mget` signature, read directly via
  `inspect.signature(AsyncOpenSearch.mget)` against the pinned 3.2.0
  install: `(self, *, body: Any, index: Any = None, params: Any = None,
  headers: Any = None) -> Any`.

## What this PoC actually does (`run_poc.py`)

1. **Scenario 0 -- real Sigma severity vocabulary.** A real `POST
   .../rules/_search?pre_packaged=true` against the live 2.11.1 cluster,
   fetching all 2077 pre-packaged rules and tallying their real `level`
   field. Confirms the real corpus contains **exactly** `informational`
   (23), `low` (205), `medium` (720), `high` (972), `critical` (157) -- and
   that `src/domain/detection.py`'s `SIGMA_SEVERITY_LEVELS` constant
   matches this real set exactly (not a superset/subset guessed from
   memory).

2. **Scenario 1 -- real `get_documents_by_id` (`_mget`) round-trip.** Real
   `OpenSearchClient.ensure_index_template()` PUT, then real `bulk_index()`
   of 3 real documents into a throwaway `kronos-poc-risk-scoring-org-case-*`
   index: one carrying both `enrichment.ioc.confidence`/
   `enrichment.asset.criticality`, one carrying only
   `enrichment.asset.criticality`, one with no enrichment at all. A real
   `get_documents_by_id()` call for those 3 ids **plus** a 4th id that was
   never indexed confirms the real response shape (`docs[].found`) and
   that a missing id is honestly omitted from the result, never a
   fabricated placeholder. One real, non-obvious operational fact
   confirmed here: OpenSearch's default `refresh_interval` means a
   just-bulk-indexed document is not always immediately visible to a
   subsequent `mget` -- this PoC calls a real `indices.refresh()` between
   indexing and reading, and the production code path
   (`DetectionSyncService`) is not affected by this because a real SA
   finding's `related_doc_ids` always reference documents that were
   indexed and refreshed well before the finding itself was ever created.

3. **Scenario 2 -- end-to-end scoring through the real
   `DetectionSyncService`.** 4 synthetic-but-real-shaped SA finding hits
   (mirroring `tests/unit/application/test_detection_sync.py`'s own
   `_real_finding_hit`, itself confirmed against a live cluster in
   `poc/detection_finding_sync/`) are synced through the real,
   unmodified `DetectionSyncService`, wired to the REAL `OpenSearchClient`
   from Scenario 1 (not `InMemoryOpenSearchClient`):
   - same `high` rule severity + a matched document with real
     `ioc.confidence=85` + `asset.criticality='critical'` → **84.41**
   - same `high` rule severity + a matched document with only
     `asset.criticality='low'` (no IOC data) → **56.82**
   - same `high` rule severity + a matched document id that was never
     indexed → **75.0** (falls back honestly to rule-severity-only:
     `0.35*0.75 / 0.35 * 100`)
   - no recognized severity tag + no matched document at all → **None**
     (honestly un-scorable, never a fabricated `0.0`)

   The delta between 84.41 → 56.82 → 75.0 is the concrete, reproducible
   proof this item's brief asked for: *same rule severity + higher asset
   criticality (and higher IOC confidence) ⇒ higher score*, and the exact
   numbers are reproducible from `DetectionRiskScorer`'s own documented
   formula (see its module docstring), not asserted from thin air.

## Real captured output

See `output.txt` — the actual, unedited stdout of the last real run:
**17/17 checks passed** against the real, live OpenSearch 2.11.1 cluster
(not mocked, not `InMemoryOpenSearchClient`).

## Run

```
~/venv/bin/python3 poc/detection_risk_scoring/run_poc.py
```

Requires `docker-opensearch-1` (OpenSearch 2.11.1) already running on
`localhost:9200` with `admin:admin` — the same already-running dev-stack
container every other PoC in this repo that touches OpenSearch directly
(`poc/threat_intel_stix_ingest/`, `poc/security_analytics_correlation/`)
already assumes. The script creates and tears down its own throwaway
`kronos-poc-risk-scoring-org-case-*` index; it does not touch any other
index or container.
