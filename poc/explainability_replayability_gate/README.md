# G3 GATE: Explainability + replayability harness

**Roadmap item:** `docs/NEXTGEN_SOC_ROADMAP.md` M6/G3. Depends on G1, G2, C4
(all done). Closes Milestone M6.

## Verdict: **GATE RESOLVED — GO, real-verified.**

All three properties this GATE exists to prove hold, against real, live
infrastructure, 20/20 checks passed. See `output.txt` for the full captured
run (real timestamps, real stored values, real verdict objects).

## What "replayability" means here (get this right, it's subtle)

"Reproduces from pinned version + stored input" does **not** mean
"re-querying live OpenSearch state produces the same score" — the
underlying asset/IOC enrichment (F1/F2) and rule-pack content are both
legitimately mutable over time, and a court-facing verdict frozen at sync
time must stay reproducible independent of that later drift. It means:
given ONLY what was already frozen/stored at the moment a verdict was
computed, recomputing the deterministic formula from that stored input
alone reproduces the identical output — even if a live re-fetch of the
same underlying data would now (correctly) return something different.

## Real pinned versions (CLAUDE.md §F.2 step 1)

- OpenSearch `2.11.1` (`docker-opensearch-1`, confirmed via `docker ps`,
  matches `docker/docker-compose.dev.yml`'s `opensearchproject/opensearch:2.11.1`)
- Postgres `16-alpine` (`docker-postgres-1`, matches
  `docker/docker-compose.dev.yml`'s `postgres:16-alpine`)
- Pydantic v2 (`model_config = {"frozen": True}`, `model_dump(mode="json")`)

## Claim 1a: F4 risk-score replay (real OpenSearch round-trip)

**Refactor needed, confirmed by reading `src/application/risk_scoring.py`
before assuming otherwise:** `DetectionRiskScorer.score()` took raw inputs
(`rule_severity`, `ioc_confidence`, `asset_criticality`,
`identity_privilege`), not a pre-built `RiskFactor` tuple — the
weighted-average formula (`weighted_sum`/`weight_total` accumulation) was
computed inline while building each `RiskFactor`, with no standalone
function operating on the tuple alone. Extracted a new pure function,
`score_from_factors(factors: tuple[RiskFactor, ...]) -> float | None`, into
the same module. `DetectionRiskScorer.score()` now builds the `RiskFactor`
list exactly as before, then calls this same function to get the score —
one formula, one place, so the production code path and the replay path
can never silently drift from each other.

PoC steps (`run_poc.py::claim1a_f4_risk_score_replay`):

1. Index one real document into a real `kronos-poc-g3-replay-*` OpenSearch
   index with `enrichment.ioc.confidence=70` and
   `enrichment.asset.criticality="high"`.
2. Run a real SA finding (tags include `critical`) through the real,
   unmodified `DetectionSyncService.sync_org_findings()`, which calls the
   real `DetectionRiskScorer` — producing a real, frozen `Detection` with
   `risk_score=83.53` and its own `risk_factors` tuple.
3. **The replay:** call `score_from_factors(detection.risk_factors)` —
   nothing else, no `rule_severity`/`ioc_confidence`/`asset_criticality`
   arguments, no OpenSearch client at all. Result: `83.53`, byte-identical
   to the stored score.
4. **The negative-control that makes this claim meaningful:** `PUT` a real
   update to the same underlying document, changing
   `enrichment.asset.criticality` from `"high"` to `"low"` — confirmed via
   a real `get_documents_by_id` re-fetch that the live document did
   legitimately change. Replaying from the **stored** `risk_factors` again
   still returns `83.53` — proving the replay is over the frozen input, not
   a live query that would (correctly, but wrongly for this claim) now
   return a different, drifted score.

## Claim 1b: C3 cost-gate replay (real Postgres round-trip)

`RuleCostGate.evaluate(sigma_yaml: str) -> CostGateVerdict` was already a
pure function of its own string input — no refactor needed here, confirmed
by reading `src/application/cost_gate.py` in full before assuming so.

PoC steps (`run_poc.py::claim1b_c3_cost_gate_replay`):

1. Through the real, unmodified `RulePackService.add_custom_rule()` against
   a real Postgres 16 instance, create one reasonable rule (cost-gate
   `ACCEPTED`) and one `|contains` rule (cost-gate `REJECTED`, real
   leading-wildcard finding).
2. **The replay:** construct a **brand new** `RuleCostGate()` instance (no
   shared state with the original) and call `.evaluate()` again on each
   rule's own **stored** `sigma_yaml` alone. Both replayed `CostGateVerdict`
   objects (`decision` + full `findings` tuple, including the exact
   `reason` string) are equal to the originally stored verdicts.

## Claim 2: G2 structural exclusion (real source-file + real serialization check)

Confirmed (matches the orchestrator's own prior grep, independently
re-verified here): none of the six real Detection-related files —
`src/domain/detection.py`, `src/application/detection_sync.py`,
`src/application/detection_triage.py`, `src/adapter/repository/detection.py`,
`src/adapter/repository/postgres_detection.py`,
`src/external/routes/detections.py` — contain the substring `anomaly`
(case-insensitive) anywhere.

Also confirmed on a real, constructed `BehavioralAnomalySignal` instance
(not just inspected in source):

- `BehavioralAnomalySignal.NOT_REPRODUCIBLE` (class-level `ClassVar[Literal[True]]`)
  is `True`, introspectable with no instantiation.
- A real instance's `not_reproducible` field is `True`.
- `model_dump(mode="json")` — the exact call an API response serializer
  would make — retains `not_reproducible: True`, and (correctly) does NOT
  include `NOT_REPRODUCIBLE` (a `ClassVar`, not instance data, so pydantic
  rightly excludes it from the dump).
- Attempting to construct an instance with `not_reproducible=False`
  **raises `pydantic.ValidationError`** — the `Literal[True]` type
  genuinely rejects a caller that tries to forge the marker, not just a
  docstring warning.

This is now enforced permanently as an automated regression, not just a
one-time PoC finding: `tests/unit/test_g3_explainability_replayability_gate.py`
runs the same three properties (minus the live-infrastructure round-trips,
covered instead by pure in-memory Pydantic-factory fixtures per CLAUDE.md
§B.5) on every future CI run — it will fail the moment a future change
imports anything from the anomaly module into Detection-land, or drops
either non-reproducibility marker.

## How to run

```
docker ps  # confirm docker-opensearch-1 and docker-postgres-1 are up
source ~/venv/bin/activate
python poc/explainability_replayability_gate/run_poc.py
```

## Binding conditions for future work touching Detection or the anomaly module

1. **Never import anything from `src/domain/anomaly.py`,
   `src/application/anomaly_scoring.py`, or either anomaly adapter
   (`src/adapter/opensearch/anomaly_detector_provisioner.py`,
   `src/adapter/opensearch/anomaly_detection_client.py`) into any
   Detection-related file** (the six listed above). If a future feature
   genuinely needs to correlate a `BehavioralAnomalySignal` with a
   `Detection` for display purposes, it must do so at a layer ABOVE both
   (e.g. a route/DTO that reads both independently), never by constructing
   a `Detection` from anomaly data or adding an anomaly field onto
   `Detection` itself. `tests/unit/test_g3_explainability_replayability_gate.py`
   will fail immediately if this is violated.
2. **Any new "verdict" field added to `Detection` in future (beyond
   `risk_score`) must be replayable from data already frozen on that same
   `Detection` row** — i.e. it must follow the `risk_factors`/
   `score_from_factors` pattern (a pure function of already-stored fields),
   never a value that requires a live re-query to reconstruct.
3. **`BehavioralAnomalySignal` must never gain a repository, a triage FSM,
   or an HTTP route that returns it as if it were a `Detection`** — if a
   future item wants to persist anomaly observations, that is new,
   deliberate scope requiring its own explicit non-reproducibility
   handling design, not a silent reuse of `Detection`'s storage path.
