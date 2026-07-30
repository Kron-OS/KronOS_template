# B3 · Per-source ISM tiering + legal hold

Verifies `src/adapter/opensearch/ism_manager.py` (`OpenSearchIsmLifecycleManager`)
and `src/application/ism_tiering.py` (`DefaultIsmTierResolver`) against the
real, live dev-stack OpenSearch 2.11.1 ISM plugin, plus the real end-to-end
wiring into `TimelineIngestionService` and `EvidenceIntakeService.set_legal_hold()`.

## Versions pinned

OpenSearch 2.11.1, ISM (Index State Management) plugin bundled in the same
image as A1-C2's verified work. `httpx` as pinned in `pyproject.toml`.

## Run

```
source ~/venv/bin/activate
python poc/ism_tiering_legal_hold/run_poc.py
```

## Result: 15 passed, 0 failed (see `output.txt` for the full real run)

## The real, previously-undiscovered bug this PoC found

Before writing any tiering/legal-hold logic, this PoC first checked whether
the *existing*, already-deployed `kronos-rollover` ISM policy was actually
doing anything on the live cluster. It was not.

**Every one of the ~18 real, pre-existing KronOS case indices on this dev
stack had its ISM managed-index job stuck at `enabled: false,
enabled_time: null`.** `_plugins/_ism/explain` reports a `policy_id`
attached and looks correct; the real managed-index document in
`.opendistro-ism-config` (queried directly) tells the true story: management
was never actually ticking. No rollover, no delete-at-365-days, nothing —
despite `ensure_ism_policy()` reporting success at every ingest and B1/B2's
own earlier work treating "a policy is attached" as equivalent to "the
lifecycle is running."

Direct, controlled experiments against the live cluster (not assumed):
- An index created via an explicit `PUT /<index>` attaches with
  `enabled: true` within seconds.
- An index created via `_bulk`'s implicit auto-create-on-first-write (the
  path every real KronOS index actually goes through) *also* attaches
  `enabled: true` within seconds, when tested fresh.
- Yet every real, older production index is stuck `enabled: false`.

Conclusion: attachment itself works; something (very likely a
container/OpenSearch process restart mid-cycle, since this dev stack has
been rebuilt/restarted dozens of times across this multi-week session)
leaves a managed-index doc stuck disabled, and **the periodic ISM
coordinator sweep does not revisit an index that already has a (disabled)
managed-index doc** — there is no automatic self-healing. Only an explicit
`POST _plugins/_ism/add/{index}` resolves it.

## A second real bug found while building the fix

The obvious fix — call `_plugins/_ism/add/{index}` — has its own real,
undocumented failure mode, confirmed directly (`poc/ism_tiering_legal_hold/run_poc.py`
Part 1b): calling `add` on an index that **already has a recorded policy_id**
(even a disabled one — exactly the stuck state above) returns **HTTP 200**
with `{"failures": true, "failed_indices": [{"reason": "This index already
has a policy, use the update policy API to update index policies"}]}`.

A naive `resp.raise_for_status()` treats this as success — the exact
"confident-sounding, unverified code" failure mode CLAUDE.md §F exists to
catch, and the same class of bug as the historical `bulk_index` silent
partial-failure (roadmap A4). `ensure_managed()` was fixed to always do
`remove` then `add` (confirmed to work unconditionally, regardless of prior
state) and to check the response **body**, not just the HTTP status, raising
a real `StorageError` if `failures` is ever still true after that.

**All 17 real, stuck production indices on this dev stack were remediated
with the fixed `ensure_managed()`** as part of this work (not left broken)
— confirmed via a direct real-cluster query before/after: 17 disabled → 0
disabled.

## What Part 1/1b prove (self-healing)

- A deliberately-disabled test index is fixed by `ensure_managed()`
  (`enabled: false` → `enabled: true`, real `enabled_time` set).
- `is_managed_and_enabled()` correctly agrees with the real managed-index
  doc's own state.
- The "already has a policy" bug is reproduced directly via a raw,
  un-fixed `add` call, then shown to be worked around by the real
  `ensure_managed()` implementation (remove-then-add).

## What Part 2 proves (per-source tiering)

- `DefaultIsmTierResolver` correctly maps `source_id=None` (case-scoped) and
  unlisted sources to the standard `kronos-rollover` tier, and known
  high-volume sources (`network`, `firewall`, `flow`, `dns`) to the new
  `kronos-stream-aggressive` tier (5 GB/7-day rollover, 90-day delete —
  aggressive because continuous telemetry accumulates far faster than case
  evidence and doesn't carry the same evidentiary weight).
- Real ISM template priority ordering (confirmed via the official OpenSearch
  docs and directly against the live cluster): **higher priority number
  wins** when multiple `ism_template`s match the same index. The aggressive
  tier's `priority: 200` correctly overrides the general `kronos-*`
  pattern's `priority: 100` for a real index matching
  `kronos-*-stream-network-*`; a case-shaped index (no stream-source
  segment) still gets the standard tier.
- **Scope note, stated honestly:** the aggressive stream tier is only
  reachable in `src/` today via a direct `ism_manager`/`ism_tier_resolver`
  call — `TimelineIngestionService` (the only real ingestion path that
  exists yet) is case-scoped only (`build_index_name`, no `source_id`), so
  it always resolves to the standard tier. Stream ingestion itself (roadmap
  D1, `StreamIngestAdapter`) hasn't been built yet; wiring the aggressive
  tier into a real stream-ingest call site is that item's job, not B3's —
  B3 delivers the tiering *mechanism* and proves it against the real
  cluster, ready for D1 to consume.

## What Part 3 proves (legal hold)

- `Evidence.legal_hold` already existed (evidence-level, MinIO Object Lock
  — `S3EvidenceStorage.set_legal_hold`) before this session; it blocks
  deletion of the raw evidence object but never touched the OpenSearch side.
  `EvidenceIntakeService.set_legal_hold()` now also calls
  `IsmLifecycleManager.place_legal_hold()`/`release_legal_hold()` on the
  evidence's case's real OpenSearch indices (resolved via
  `kronos-{org}-case-{case_id}-*`), case-grade (not per-evidence-item):
  release only actually resumes lifecycle management once **no other**
  evidence in the same case is still held (checked via a real
  `EvidenceRepository.stream_by_case()` scan, not assumed).
- `place_legal_hold()` (`_plugins/_ism/remove`) makes a real index's
  managed-index doc disappear entirely — ISM cannot run *any* transition,
  including delete, against it. `release_legal_hold()`
  (`ensure_managed()`, remove-then-add) brings it back with
  `enabled: true`.
- Best-effort, matching every other OpenSearch-side provisioner in this
  codebase (`DashboardsIndexPatternProvisioner`, `SecurityAnalyticsDetectorProvisioner`):
  a transient OpenSearch outage during a legal-hold call must never fail
  the call that already succeeded against MinIO and Postgres — logged via
  `ism_legal_hold_sync_failed`, not raised.
