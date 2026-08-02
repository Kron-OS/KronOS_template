# PoC: OpenSearch Anomaly Detection (AD/RCF), per-org, for triage prioritization (roadmap M6/G2)

**Objective (roadmap):** "Use the in-cluster Anomaly Detection plugin
per-org (scoped to `kronos-{org}-*`...). Hard constraint: RCF is an online
model that continuously updates its own state, so a score depends on
ingestion history, not just the scored document -- it is not reproducible
months later and must never be the evidentiary basis of a finding. Triage
prioritization and hunting leads only."

**Follows immediately after G1** (`poc/rarity_baseline_scoring/`), which
established the deterministic, fully-replayable baseline this item is
explicitly the non-reproducible *opposite* of.

## Versions pinned (CLAUDE.md SS F.2 step 1)

- OpenSearch: `2.11.1` (`docker-opensearch-1`, already running on this host).
- Anomaly Detection plugin: `opensearch-anomaly-detection 2.11.1.0` --
  confirmed installed via `GET _cat/plugins?v` (real output: `c494e4910d0b
  opensearch-anomaly-detection 2.11.1.0`), and confirmed alive/responsive
  via `GET _plugins/_anomaly_detection/stats` returning real HTTP 200,
  `detector_count: 0` (before this PoC ran). Both facts were already
  confirmed by the orchestrator before this PoC started (see task brief);
  not re-derived here.
- `httpx` (already a project dependency, `httpx>=0.27` in `pyproject.toml`)
  -- used directly, no `opensearch-py` wrapper, mirroring every other
  admin-credentialed adapter in this repo (`RarityBaselineClient`,
  `CorrelationClient`, `FindingsClient`, `SecurityAnalyticsDetectorProvisioner`).

## Real docs/examples used (CLAUDE.md SS F.2 step 2)

The general docs site (`opensearch.org/docs/2.11/...`) 301-redirects to
`docs.opensearch.org/2.11/...` and, via `WebFetch`, sometimes returned only
a redirect stub with no body -- explicitly noted here as a real, observed
gap in that tooling path, not silently worked around by guessing. Where
the docs site *did* return real content (via a second, more specific
`WebFetch`), it correctly explained the real-time-vs-historical-analysis
distinction, minimum cold-start data points ("more than 400 data points"),
default `shingle_size: 8`, and `category_field`'s "similar to `GROUP BY` in
SQL" semantics for high-cardinality/per-entity detection.

For anything the docs summary was fuzzy or silent about (the exact
historical-analysis REST shape, the real results-index name, real
idempotency behavior), this PoC went straight to the **plugin's own pinned
`2.11` branch source** on GitHub
(`github.com/opensearch-project/anomaly-detection`, ref `2.11`) rather than
trust an LLM's paraphrase of docs prose:

- `RestAnomalyDetectorJobAction.java` -- confirmed the REAL mechanism for
  historical analysis is **the same `_start` endpoint real-time jobs use**,
  disambiguated by a query param: `POST
  .../detectors/{detectorId}/_start?historical=true` with a JSON body
  `{"start_time": <epoch_ms>, "end_time": <epoch_ms>}` (`DetectionDateRange`,
  fields `start_time`/`end_time` confirmed from `DetectionDateRange.java`).
  There is no separate "historical analysis" endpoint as the docs summary's
  hedge implied -- it is a query-param variant of the ordinary job-start
  call.
- `AnomalyDetector.java` -- confirmed the real detector-body field names:
  `name`, `time_field`, `indices`, `feature_attributes` (each entry:
  `feature_name`, `feature_enabled`, `aggregation_query`), `category_field`
  (array), `detection_interval`, `window_delay`.
- `AnomalyResult.java` -- confirmed the real result-document field names:
  `detector_id`, `task_id`, `anomaly_grade`, `confidence`, `anomaly_score`,
  `feature_data`, `entity` (array of `{name, value}` -- this is where a
  `category_field` value like `host.name`/`host-anomalous` actually shows
  up per result), `data_start_time`/`data_end_time`, `expected_values` (the
  model's own predicted-normal value -- directly legible for a human
  triaging a lead, see Scenario 4 below).
- `CommonName.java` -- confirmed the real results-index name:
  `.opendistro-anomaly-results` (alias) backed by concrete
  `.opendistro-anomaly-results-history-<date>-<n>` indices.
- `RestSearchAnomalyResultAction.java` -- confirmed the real, DEDICATED
  plugin endpoint for reading results (see "Real bug/gap #2" below for why
  this one was load-bearing, not just a nice-to-have).

## Real, load-bearing findings (not assumed from memory)

**Finding 1 -- historical analysis genuinely bypasses real-time cold
start, confirmed live, not just per docs prose.** A real detector was
created against a real 600-document (2-entity × 300-minute) synthetic
corpus and a real historical-analysis job over the full range reached
`state: FINISHED` in ~3 seconds (`poll 0: state=CREATED task_progress=0.0`
→ `poll 1: state=FINISHED task_progress=1.0`), producing 598 real,
immediately-queryable anomaly results with a real `anomaly_grade: 1.0` for
the injected spike -- vs. the documented real-time cold start needing
"more than 400 data points" or "more than an hour" before the SAME
detector, run as a live job, would emit its first confident grade. This
concretely confirms historical analysis was the right choice for a
verification PoC that needs to finish in a reasonable time and still
produce real, inspectable output -- not an assumption.

**Finding 2 -- a genuinely surprising, security-plugin-driven gap: the raw
results INDEX is silently unreadable by direct search, even as `admin`,
even though it demonstrably contains real data.** `GET
_cat/indices/*anomaly*?v` and `GET
.opendistro-anomaly-results-history-2026.08.02-1/_stats/docs` both reported
a real, non-zero `docs.count` (4790, from cumulative PoC runs), but a plain
`POST .../.opendistro-anomaly-results-history-2026.08.02-1/_search` with
`match_all` returned real HTTP 200 with `hits.total.value: 0` -- not an
error, not a mapping issue, a SILENT empty result against an index proven
by `_stats` to physically contain thousands of documents. This is the
OpenSearch security plugin's system-index protection: `.opendistro-*`
indices are reserved for the owning plugin's own internal, privileged
requests; even the `admin` superuser's ordinary `_search` call against them
is transparently filtered to nothing. The plugin ships its own dedicated
read path specifically to route around this --
`POST /_plugins/_anomaly_detection/detectors/results/_search`
(`RestSearchAnomalyResultAction.java` -- its `prepareRequest` targets
`ALL_AD_RESULTS_INDEX_PATTERN` as a privileged internal plugin action, not
a bare user search) -- confirmed live to return the real 1196 total
results this PoC's runs had produced, findable by `task_id`. **Any KronOS
adapter reading AD results MUST use this dedicated endpoint, never a raw
query against the dot-index** -- getting this wrong would silently produce
"zero hunting leads found" for every org, forever, with no error anywhere,
exactly the class of bug CLAUDE.md SS F exists to catch before it ships.

**Finding 3 -- a made-up field name (`network.bytes_out`) silently fails
detector CREATE, and the real error message is honest about why.** The
first PoC attempt used a plausible-looking-but-nonexistent ECS field. Real
response: `HTTP 500`, `"Feature has an invalid query returning empty
aggregated data: avg_bytes_out"` -- AD's detector-CREATE call runs a real
validation query against the feature's own aggregation before accepting
the detector, and `kronos-*`'s own index template
(`src/adapter/opensearch/index_template.json`) is `"dynamic": "false"`
-- an unmapped field is stored in `_source` but not indexed/aggregatable at
all. Switched to `source.bytes` (a real, already-ECS-mapped `long` field)
and the same detector created cleanly. A genuinely useful, load-bearing
confirmation that **any KronOS caller of this plugin must pass a field
that is actually present in `index_template.json`'s explicit mapping**, the
same constraint `RarityBaselineScorer`'s own docstring already documents
for its own field parameter.

**Finding 4 -- detector-CREATE's own validation ALSO requires "recent"
data relative to wall-clock time, not just non-empty data anywhere.** A
first corpus dated `2026-07-01` (over a month before this session's real
system clock, `2026-08-02`) hit the same "empty aggregated data" error even
using a real, mapped field -- the validation query apparently checks a
window relative to `now()`, not the detector's own configured
`detection_interval`/whatever range historical analysis will eventually
use. Anchoring the synthetic corpus to end at `datetime.now(UTC)` (which
real streaming ingestion does naturally anyway) resolved this. Documented
here as a real, load-bearing PoC-authoring gotcha for whoever builds the
next module against this same plugin, not a KronOS design flaw.

**Finding 5 -- per-org detector idempotency: the OPPOSITE of what the task
brief's own precedent suggested checking for, confirmed for real, not
assumed either way.** `SecurityAnalyticsDetectorProvisioner`'s own
docstring documents that SA's detector-name field has NO server-side
uniqueness enforcement (KronOS's own check-then-create is a pure
KronOS-side convention there) and that SA's detector PUT-update path has a
real 2.11.1 500 defect forcing a create-only strategy.
`SecurityAnalyticsCorrelationRuleProvisioner`, in contrast, found PUT-update
works cleanly for correlation rules. Testing the AD plugin's OWN, distinct
implementation for real (never assumed to match either precedent):
- A second, real `POST .../detectors` with the exact same `name` was
  rejected with real `HTTP 500`,
  `"Cannot create anomaly detector with name [...] as it's already used by
  detector [<id>]"` -- **AD enforces detector-name uniqueness
  server-side**, unlike SA's detector API. This is a genuinely different,
  and in this specific respect simpler-to-build-on, real behavior: a
  KronOS provisioner still needs a check-then-create (or a
  try/except on this exact error shape) to stay idempotent and avoid a
  needless failed round-trip, but the plugin itself is a real backstop
  against ever creating two per-org AD detectors with the same name, which
  SA's own detector API does not provide.
- A real `PUT .../detectors/{existing_id}` update-in-place returned real
  `HTTP 200` with an incremented `_version` (`1` → `2`) -- **AD does NOT
  share SecurityAnalyticsDetectorProvisioner's documented 2.11.1
  detector-PUT-update 500 defect.** AD's update path behaves like
  `SecurityAnalyticsCorrelationRuleProvisioner`'s clean-update case, not
  like SA's own detector case -- confirming neither precedent could have
  been safely assumed to carry over without this real, independent test.

## Design decision: per-org scoping is INDEX PATTERN, `category_field` is
INTRA-org entity slicing -- never the tenant boundary itself

The roadmap text's own parenthetical ("scoped to `kronos-{org}-*`, which
also contains the behavioural-profile leak") plus this PoC's own findings
point to the same conclusion C2 (`SecurityAnalyticsDetectorProvisioner`)
already reached for Security Analytics detectors: **the tenant boundary is
the detector's own `indices: ["kronos-{org_alias}-*"]` field, computed by
KronOS from the authenticated `TenantContext`, exactly like every other
adapter in this codebase (roadmap invariant #3) -- never anything read out
of a detector's own `category_field`/`entity` values.** `category_field`
(here, `host.name`) is a real, useful, ORTHOGONAL mechanism for slicing
*within* one org's own already-scoped detector by a high-cardinality
dimension (host, user, source IP...) -- it lets ONE per-org detector
produce independently-scored, independently-attributed results per entity
(confirmed live: `host-anomalous` scored `anomaly_grade: 1.0` while
`host-normal` stayed at `0.0` from the SAME detector), rather than needing
a new detector per entity. This is exactly analogous to why C2 chose
per-org (not per-case) detectors: cases/entities are unbounded and
unknown in advance, while orgs are the natural coarse-grained unit AD
detectors (cluster-level, name-unique, real per-detector resource cost)
were designed for.

**The "behavioural-profile leak" the roadmap text flags is real and
independently confirmed here, at the cluster-observability layer, not the
per-result layer:** `GET _plugins/_anomaly_detection/stats` (already
probed by the orchestrator before this PoC) reports `detector_count`,
`model_count`, etc. as flat CLUSTER/NODE totals with no per-detector or
per-org breakdown at all -- an ops user with access to that one endpoint
can see that N models/detectors exist cluster-wide, but not whose. This
mirrors the A3 gate's own already-documented finding for Security
Analytics (`poc/security_analytics_tenant_isolation/`): AD's own
node-stats surface, like SA's, is NOT tenant-isolated, and must never be
exposed to a tenant-scoped session -- only KronOS's own per-org query path
(described below) may ever surface AD data to a tenant.

## Design decision: `BehavioralAnomalySignal` is query-time-only, never persisted

Mirrors `RarityBaselineScorer`'s own G1 precedent (`src/application/
rarity_scoring.py` module docstring) of shipping a standalone, read-only
analytics capability with **no repository, no DI wiring, no HTTP route
yet** -- but for a stronger, G2-specific reason than G1's "no consumer
exists yet": **a stored snapshot of a live, continuously-mutating RCF
score is not just premature, it is actively the wrong shape for this
signal, and storing one would recreate exactly the structural risk G3
exists to prevent.** Reasoning, mirroring how F4 reasoned through
frozen-at-sync (`Detection.risk_score`) vs. live-recompute:

- A `Detection` row is frozen at sync time *because* the underlying SA
  finding it mirrors is itself a discrete, non-repeating event (a rule
  fired once, on one document) -- freezing it is what makes it
  replayable: the finding, and KronOS's mirror of it, both stop changing.
- An AD/RCF result has no equivalent "this is now a fixed, past fact"
  moment. The score for the SAME historical data point can legitimately
  differ on a re-run because the RCF model's own state (which this
  plugin's `model_id`/checkpoint mechanism owns, not KronOS) keeps
  evolving as more data streams in. Storing a `BehavioralAnomalySignal`
  row would create a table that LOOKS like `Detection` (an id, a
  timestamp, a persisted "fact") but silently carries none of
  `Detection`'s actual replayability guarantee -- exactly the "same
  Pydantic model with an extra flag" anti-pattern the task brief warns
  against, just one layer removed (a *sibling* table with the same shape
  problem, instead of the same table).
  a future developer, or a future analyst, encountering a stored row has
  every reason to trust it the way they trust a stored `Detection` row;
  the correct trust level can only be reliably enforced by there being no
  stored row to encounter at all in the first place.
- G1 already established the "fresh analytics capability, no DI wiring,
  callers construct directly" shape is a legitimate, precedent-setting v1
  scope for this exact kind of read-only OpenSearch-backed capability in
  this codebase -- G2 fits the identical shape, for a stronger reason.

Concretely: `BehavioralAnomalyScorer.fetch_org_signals()` (`src/
application/anomaly_scoring.py`) takes a `TenantContext` and an already-run
detector's real results, straight from `AnomalyDetectionClient` (`src/
adapter/opensearch/anomaly_detection_client.py`), and maps them into
`BehavioralAnomalySignal` (`src/domain/anomaly.py`) value objects entirely
in memory, on every call -- there is no `AnomalyRepository`, no
Postgres table, no sync service. A future hunting UI/scheduled job queries
this the same way a future G1 consumer would query `RarityBaselineScorer`:
by calling it directly, at read time.

## Structural separation from `Detection` (binds G3)

`BehavioralAnomalySignal` (`src/domain/anomaly.py`) is a NEW, standalone
Pydantic model in its OWN module -- not a field added to `Detection`
(`src/domain/detection.py`), not a subtype of it, and not synced by
anything resembling `DetectionSyncService`. Concretely:

- It has its own `NOT_REPRODUCIBLE: ClassVar[Literal[True]]` class
  constant AND its own `not_reproducible: Literal[True]` required
  instance field (belt-and-braces: a class-level constant a static/import-
  time check can grep for without instantiating anything, PLUS an
  instance field so a runtime harness inspecting an actual object -- e.g.
  something serialized into an API response or a UI payload -- can
  mechanically assert the marker survived serialization, which a
  class-level-only constant would not guarantee). G3's future harness can
  check either mechanically; neither is a docstring a future developer
  could miss.
- There is no `DetectionRepository` method that accepts or returns a
  `BehavioralAnomalySignal`, and no triage-FSM (`DetectionTriageState`)
  applies to it -- it has no state machine at all, because it is not a
  verdict, it is a live, point-in-time observation surfaced for a human to
  go LOOK at (triage prioritization / hunting lead, per the roadmap's own
  words), not something KronOS itself asserts happened.
- `org_id`/`org_alias` are still always the CALLING `TenantContext`'s own
  values (roadmap invariant #3), for the same reason every other adapter
  in this codebase enforces that -- this one invariant is the one thing
  genuinely shared with `Detection`'s contract, and is shared because it
  is a tenant-isolation rule that applies universally, not because the two
  types are secretly the same thing.

## PoC files

- `run_poc.py` -- drives the real API end-to-end: indexes a real
  stable-then-spike, 2-entity synthetic corpus; creates a real
  `category_field`-scoped detector; runs and polls a real historical
  analysis task to completion; reads back real results via the plugin's
  own dedicated results-search endpoint; asserts the injected anomaly was
  actually found, correctly attributed, and correctly time-located; probes
  real idempotency behavior (duplicate-name create, PUT-update-in-place).
  Cleans up its own detector/indices in a `finally` block.
- `output.txt` -- the real, captured stdout of the last real run: **13/13
  checks passed** against the live OpenSearch 2.11.1 AD plugin.

## How to run

```
python3 poc/anomaly_detection_baseline/run_poc.py
```

Requires the dev OpenSearch stack already running (`docker-opensearch-1`,
`https://localhost:9200`, `admin:admin`) -- no other setup. Cleans up all
of its own PoC-created detectors/indices even on failure.
