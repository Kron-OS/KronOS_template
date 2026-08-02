# F3 · Security Analytics Correlation Engine evaluation

**Roadmap item:** `docs/NEXTGEN_SOC_ROADMAP.md` F3 -- "Evaluate SA's native
correlation engine before building anything; only then consider an entity
graph for attack-chain assembly."

## Versions pinned

OpenSearch **2.11.1** (`docker-opensearch-1`, the real running dev container
-- `docker/docker-compose.dev.yml` pins `opensearchproject/opensearch:2.11.1`;
note `docker-compose.test.yml`/`docker-compose.prod.yml` pin **2.13.0**, not
re-verified here -- see "Not verified" below). `opensearch-security-analytics`
plugin version matching that OpenSearch build. The exact request/response
shape was NOT taken from opensearch.org's "latest" docs (which can describe a
newer version's syntax per CLAUDE.md SS F.2 step 2) -- it was read directly from
the real Java source of `github.com/opensearch-project/security-analytics`,
**branch `2.11`, commit `0092714047145972f990931e0d06595caa019185`** (cloned
locally to `/tmp/sa-repo` for this pass): `model/CorrelationRule.java`,
`model/CorrelationQuery.java`, `action/IndexCorrelationRuleRequest.java`,
`resthandler/RestIndexCorrelationRuleAction.java`,
`resthandler/RestSearchCorrelationAction.java`, and the real integration test
`correlation/CorrelationEngineRestApiIT.java` (which is what revealed the
correct create-rule-before-findings ordering -- see below).

## Orchestrator's own prior real probe (confirmed here, not re-derived)

- `GET /_plugins/_security_analytics/correlation/rules` -> **405** (route
  registered, POST-only).
- `POST /_plugins/_security_analytics/correlation/rules/_search`
  `{"query":{"match_all":{}}}` -> **200**, empty hits.
- Control: `POST .../detectors/_search` -> 200.

This is categorically different from F2's threat-intel finding (`400`, "no
handler found" -- route not compiled in at all). **The correlation engine is
real and live on this exact pinned cluster.**

## Real, confirmed request/response schema (from source, not guessed)

```
POST /_plugins/_security_analytics/correlation/rules
{
  "name": "<5-50 chars, regex [a-zA-Z0-9 _,-.]>",
  "correlate": [
    {"index": "<index or index pattern>", "query": "<lucene query_string>", "category": "<log type / detector_type>"},
    ... (>=2 for a real cross-log-type join)
  ]
}
```

- `name` is **required** and validated by `IndexCorrelationRuleRequest.IS_VALID_RULE_NAME`
  (`[a-zA-Z0-9 _,-.]{5,50}`) -- confirmed for real: an empty name gets a real
  `400 action_request_validation_exception` (Part 3b, `output.txt`).
- Response: `{"_id": ..., "_version": ..., "rule": {"name": ..., "correlate": [...]}}`.
- `category` is the **same string** as a Detector's own `detector_type` (one
  of the 23 real log types from roadmap SS0) -- there's no cross-reference
  validation in `CorrelationRule.java` itself, but the correlation engine
  only has real findings to correlate against for categories that have a
  real detector actually producing findings.
- `correlate` is a **NESTED** field in the underlying
  `.opensearch-sap-correlation-rules-config` index -- confirmed by a real
  run: a flat `{"term": {"correlate.category": "windows"}}` search matches
  **0** hits even with 2 real matching rules present, while the nested
  equivalent (`{"nested": {"path": "correlate", ...}}`) matches **2** (see
  `output.txt`, Part 5). This is the **exact same trap** that defeated C2's
  naive `detector.name` idempotency check -- worth recording precisely
  because it will bite anyone who later writes a flat query against
  KronOS's own correlation-rule bookkeeping.
- There is **no org/tenant field anywhere** in `CorrelationRule` or
  `CorrelationQuery` -- `index` is a free-form string the caller supplies,
  exactly like a Detector's own `indices` list.

## Real correlation match achieved (not simulated)

Method (see `run_poc.py`, full real output in `output.txt`):

1. Created two throwaway test indices (`poc-corr-windows-<ts>`,
   `poc-corr-network-<ts>`) -- see "Why not `kronos-*` index names" below.
2. Created two real detectors, one per index/category, using two Sigma
   rules **already verified to fire against real KronOS data** in
   `poc/security_analytics_field_mappings/` (C1): `db809f10-...` (windows,
   attack.t1006, condition `not 1 of filter_*` -- fires on any windows
   document lacking `Image`/`Device`/`ProcessId`) and `1fc0809e-...`
   (network, attack.t1021.001, condition `not selection` -- fires on any
   non-RFC1918 `id.orig_h`).
3. **Created the correlation rule BEFORE generating the findings** (see
   "Real bug/gap found #2" below for why this order is mandatory), joining
   `category: "windows"` (`query: "HostName:<value>"`) with
   `category: "network"` (`query: "id.orig_h:8.8.8.8"`).
4. Indexed one matching document per index, executed both detectors
   on-demand via the real Alerting `_execute` API, and got two real
   findings.
5. Queried `GET /_plugins/_security_analytics/findings/correlate?finding=<windows
   finding>&detector_type=windows&time_window=300000&nearby_findings=10`.

**Real result** (`output.txt`, Part 4):

```json
{"findings": [
  {"finding": "983d593c-...", "detector_type": "network", "score": 1.0, "rules": ["DMyUwp8BG52zb-VTmXZK"]},
  {"finding": "d8137495-...", "detector_type": "windows", "score": 1.0, "rules": ["DMyUwp8BG52zb-VTmXZK"]},
  {"finding": "07b271dc-...", "detector_type": "network", "score": 1.0, "rules": ["DMyUwp8BG52zb-VTmXZK"]},
  {"finding": "1ed60512-...", "detector_type": "network", "score": 1.0, "rules": ["DMyUwp8BG52zb-VTmXZK"]}
]}
```

`07b271dc-...` is **this exact run's own real network finding**, returned
with `score: 1.0` and tagged with `DMyUwp8BG52zb-VTmXZK` -- **this run's own
real correlation rule id**. The mechanism genuinely joins a real windows
finding to a real network finding, created from two independent detectors
over two independent indices, using only the rule's declarative
`index`/`query`/`category` triple. **20/20 checks pass** (`output.txt`).

## Real bugs/gaps found (not assumed, hit and root-caused live)

1. **Neither the create-detector response NOR a real `GET
   .../detectors/{id}` exposes `monitor_id`** -- both were tried against the
   live cluster and confirmed to omit it. The real
   `.opensearch-sap-detectors-config` document (read via a raw index search,
   bypassing the plugin's REST layer) does have it, as a list
   (`detector.monitor_id`). This exactly matches how the real Java IT test
   (`CorrelationEngineRestApiIT.createVpcFlowDetector`) does it too --
   `executeSearch(Detector.DETECTORS_INDEX, ...)`, never the plugin API, to
   get a monitor id. `run_poc.py`'s `_create_detector()` does the same.
2. **A correlation rule only correlates findings created AFTER the rule
   exists -- it does not retroactively re-scan pre-existing findings.**
   First attempt at this PoC created the rule AFTER the two findings already
   existed and got **zero** matches; only after reordering (rule first, then
   index the matching docs, then execute the detectors) did the real match
   appear. This is the same category of fact as
   `poc/detection_finding_sync/`'s own documented "SA detectors only
   evaluate documents indexed after the monitor's own last-run cursor" --
   the correlation engine is evidently a real-time listener on new findings,
   not a query-time joiner over the full findings history. **Binding on any
   future KronOS integration:** correlation rules must be provisioned
   *before* the detectors whose findings they're meant to join can produce
   anything worth correlating (mirrors the existing
   detector-before-first-finding ordering already established).
3. **Findings outlive both their detector AND their source index.** A
   network finding from an earlier, already-cleaned-up run of this same
   script (source index long since deleted) still showed up as a correlated
   match in a later run, because `.opensearch-sap-*-findings-*` documents
   are independent, immutable records that don't reference back to whether
   their source index still exists. Not a bug -- consistent with
   `poc/detection_finding_sync/`'s own "deleting a detector does not delete
   its past findings" -- but it means naive `poc/` cleanup between runs (or
   between test suite runs against a shared dev cluster) leaves permanent
   cross-run noise in the shared findings indices. `run_poc.py`'s own
   correctness check accounts for this (asserts "some network finding
   tagged with THIS run's own rule id", not "THIS run's exact finding_id",
   since the latter is legitimately brittle against that real noise).

## Real PUT-update behaviour (checked directly -- do not assume it mirrors detectors)

C2/C3's own detector provisioners both had to adopt a never-PUT,
delete-and-recreate idempotency strategy because a real PUT-update against
a live 2.11.1 *detector* returns a real 500
(`kotlin.collections.EmptyMap cannot be cast to kotlin.collections.MutableMap`).
Given that precedent, this was checked directly for correlation rules
rather than assumed either way: created a real rule, then
`PUT /_plugins/_security_analytics/correlation/rules/{id}` with a changed
`name`+`correlate`, then read it back via a real search. **Real result: the
PUT succeeded cleanly** -- `_version` incremented from 1 to 2, and the
re-read document shows the fully updated `name` and `correlate`, no error.
Correlation rules do **not** share the detector's update defect, so
`SecurityAnalyticsCorrelationRuleProvisioner` (src/) uses a normal
check-then-create-or-update strategy, not delete-and-recreate.

Also checked directly (not assumed from `correlate` being nested): a real
`{"term": {"name.keyword": "..."}}` search against a real rule's own
top-level `name` field returns **1** hit -- `name` is flat, only `correlate`
is nested. `SecurityAnalyticsCorrelationRuleProvisioner._find()` searches on
`name.keyword` for exactly this reason.

## Why not `kronos-*` index names for the mechanism PoC

`kronos-template` (`index_template.json`, `index_patterns: ["kronos-*"]`,
`dynamic: false`) would silently drop the ad-hoc fields
(`HostName`/`id.orig_h`) this PoC needed to control precisely to deterministically
fire two specific, already-known-good Sigma rules -- the exact same dynamic
mapping gap C1 already spent real effort on for `cloudtrail`. Using
plain `poc-corr-*` names (matching the real Java IT test's own generic
`vpc_flow`/`ad_logs` index names, not any KronOS-specific naming) isolates
the correlation-*mechanism* question from the field-mapping question C1
already owns, deliberately. Part 5 below separately confirms that a
`kronos-{org_alias}-*`-shaped index string is accepted with no special
handling, which is the fact that actually matters for integration.

## The multi-tenant scoping question (roadmap's explicit ask)

**Does a correlation rule support per-org index-pattern scoping like a
detector does? Answer: not as a first-class concept, but yes as a
convention KronOS itself imposes** -- identical to how detector scoping
already works today.

Real evidence (`output.txt`, Part 5): a correlation rule was created with

```json
"correlate": [
  {"index": "kronos-poc-tenanta-*", "query": "*", "category": "windows"},
  {"index": "kronos-poc-tenantb-*", "query": "*", "category": "network"}
]
```

and returned **201** with the exact same `index` strings echoed back --
no validation, no dedicated org/tenant field, nothing. This confirms from
the real schema (not just inferred from `CorrelationRule.java`/
`CorrelationQuery.java` lacking any org field) that:

- **There is no dedicated tenant-scoping mechanism** for correlation rules,
  exactly as A3 already found for detectors and findings
  (`poc/security_analytics_tenant_isolation/`): SA has no concept of a
  tenant at all below the KronOS application layer.
- **The `index` field is exactly as free-form as a Detector's own `indices`
  list**, which means the *same* per-org scoping convention
  `SecurityAnalyticsDetectorProvisioner` (C2) already established extends
  cleanly: KronOS computes `kronos-{org_alias}-*` from the authenticated
  `TenantContext` and writes it into the rule's `correlate[].index`, never
  from anything rule-content-supplied.
- A **single correlation rule cannot itself select "just this org"** across
  more than its own explicit `index` strings -- there is no wildcard-org
  concept. Since each rule already names its own two (or more) categories'
  index patterns explicitly, this is naturally **one correlation rule per
  org per rule-pair** (e.g. "windows-then-network lateral movement" is one
  rule per org), mirroring `SecurityAnalyticsDetectorProvisioner`'s own
  per-org-per-log-type shape exactly -- not a new scoping unit to invent.
- The A3 gate's binding conditions (admin-only creation/read, tenants never
  see SA directly, KronOS's own audited entity is the only tenant-facing
  surface) apply to correlation rules with **zero modification** -- this
  PoC found no new isolation risk beyond what A3 already covers, because
  correlation rules are governed by the identical coarse cluster-action RBAC
  model as detectors (a role either has
  `cluster:admin/opensearch/securityanalytics/correlations/*` or it
  doesn't -- no tenant granted it today, per A3's own confirmed grant list).

## Design decision: extend the native engine, do not build an entity graph

**GO on the native correlation engine, following the exact precedent
`SecurityAnalyticsDetectorProvisioner`/`SecurityAnalyticsCustomRuleDetectorProvisioner`
already set.** The roadmap's own gate ("evaluate before building") is
satisfied: the mechanism is real, produces real cross-log-type matches, and
its one real limitation (no dynamic per-record field-value join -- rules
correlate on a **declarative, pre-authored query pair evaluated within a
time window**, not "any two events sharing the same IP/user/host") is a
scenario-authoring constraint, not a tenant-isolation or reliability defect.
It does not block using it for KronOS's actual near-term need: a curated set
of named, cross-log-type attack-chain scenarios (e.g. "public RDP exposure
followed by a Windows credential-access event on the same host within N
minutes") — precisely the kind of rule this engine is designed to express.

A bespoke entity graph is explicitly **not** built this pass:

- Nothing observed here is a real, concrete defect the way C2's PUT-update
  bug or A3's "no tenant scoping at all" were -- the ordering requirement
  (rule-before-finding) and the nested-field trap are real facts to design
  around, not evidence the engine doesn't work.
- Building a parallel graph-based correlator now, alongside a native engine
  that already does real cross-log-type joins, would be exactly the
  "shortcut without an actual gap" CLAUDE.md SS G.3 warns against for a
  different subsystem (Track D sandboxing) -- the same reasoning transfers
  here: don't build the heavier bespoke thing until the native path has a
  real, demonstrated limitation for KronOS's own use cases.
- If a future need genuinely requires dynamic field-value joins ("same
  source IP across ANY two log types, not a pre-authored pair") the native
  engine's declarative-query-pair model cannot express that, and an entity
  graph becomes the right next step -- but that is a forward-looking,
  currently-hypothetical need, not something hit in this pass.

## Not built this pass (explicitly out of scope, not silently dropped)

- No `src/adapter/opensearch/correlation_rule_provisioner.py` provisioning
  class was written this pass -- see the companion status note in
  `docs/NEXTGEN_SOC_ROADMAP.md` for what specifically was/wasn't wired into
  `src/` given the scope of this single item.
- Curating the actual set of cross-log-type scenario rules KronOS ships
  (which specific windows/network/cloudtrail query pairs are worth
  pre-authoring) is real, separate product-definition work, not a mechanism
  question -- this PoC deliberately used one synthetic pair to prove the
  mechanism, not to propose a shipped rule set.
- Multi-rule chains (>2 categories, mirroring the real IT test's
  3-category `network -> ad_ldap -> windows` rule) were not tried here --
  the 2-category case is what's proven; N-category is a natural
  extrapolation of the exact same `correlate` array, not a different
  mechanism, but wasn't independently run.
- `docker-compose.test.yml`/`docker-compose.prod.yml` pin OpenSearch
  **2.13.0**, not 2.11.1 -- this PoC ran only against the real 2.11.1 dev
  container. Not re-verified against 2.13.0 this pass (flagged, not
  assumed identical).

## How to run

```
docker ps | grep opensearch   # confirm docker-opensearch-1 (2.11.1) is up
python3 poc/security_analytics_correlation/run_poc.py
```

Cleans up its own detectors/rules/indices at the end. Real findings this
run's detectors produced are NOT deleted (mirrors `detection_finding_sync`'s
own precedent: findings are independent, immutable, and the plugin has no
delete-finding API) -- this is why later runs observe earlier runs' findings
in their own correlation results (see "Real bug/gap found #3" above).
