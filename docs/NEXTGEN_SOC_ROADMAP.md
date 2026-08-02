# KronOS → Next-Gen SOC/CERT Incident-Response Platform: Roadmap

**Status:** active plan. Supersedes nothing in `CLAUDE.md` — every rule there
(§A architecture, §B standards, §E pipeline autonomy, §F verification-first,
§G module system) applies unchanged to every item below.

**Design authority for this roadmap:** the deep-research report supplied by the
project owner (2026-07-28), reconciled against verified repo/cluster reality in
the analysis that produced this document. Where the report and reality
disagreed, reality won and the reasoning is recorded inline.

---

## 0. Verified starting facts (do not re-derive; re-verify only if suspect)

Established by direct inspection of the running dev stack on 2026-07-28:

| Fact | Evidence |
|---|---|
| OpenSearch **2.11.1**, distribution `opensearch` | `GET /` |
| `opensearch-security-analytics` **installed, API live** | `_cat/plugins`, `detectors/_search` → 200 |
| **OpenSearch's detection rule language IS Sigma** | a shipped rule dumped verbatim — `title/id/logsource/detection/condition/level/tags` |
| **2,077 prepackaged Sigma rules already in-cluster** | `rules/_search?pre_packaged=true` → `hits.total.value` |
| **23 log types** supported | `ad_ldap, apache_access, azure, cloudtrail, dns, github, gworkspace, linux, m365, network, okta, others_{application,apt,cloud,compliance,macos,proxy,web}, s3, test_windows, vpcflow, waf, windows` |
| `opensearch-anomaly-detection` installed (RCF) | `_cat/plugins`; `detectors/_search` 404 is `index_not_found_exception` = no detectors yet, **not** missing capability |
| `opensearch-ml` (ML Commons) live | `_ml/stats` → 200 |
| `opensearch-alerting`, `opensearch-sql` (PPL/SQL), `opensearch-knn`, `opensearch-index-management` installed | `_cat/plugins` |
| **No Sigma / YARA / ML / Kafka code anywhere in `src/`** | grep |
| Index template maps **24 fields**, `dynamic` **unset → defaults to true**, **no `dynamic_templates`** | `index_template.json` |
| `ECSNormalizer.to_document()` merges `record.extra` with dotted-key expansion | `timeline_normalization.py:49-51` |
| `KronosProvenance` **mandates** `evidence_id`/`case_id`/`sha256`/`record_index` | `src/domain/timeline.py` |
| Index naming is **case-scoped**: `kronos-{org}-case-{case_id}-{yyyymm}` | `timeline_normalization.py:12` |
| ISM policy is **one flat policy** for all `kronos-*` (rollover 30d/30GB, delete 365d) | `ism_policy.json` |
| SIEM side-configs exist but were **never wired or exercised** | `docker/{falco,wazuh,fluent-bit}/`, own compose files, absent from main stack |
| Real ~521 MB KAPE target-extract ZIP available in MinIO quarantine (`kronos-evidence-kronos-dev-quarantine`, key `kronos-dev/4cf0dd96-8c06-4eee-ad75-aaa335fe50e4/6c02c9ad-13b8-46ac-b9fd-cb87fc7741ea/2026-07-28T202644_zipfile.zip`). State `ERROR`, `error_reason=infected:Win.Malware.LNKAgent-10043840-0` — a real, **correct** ClamAV detection (KAPE triage collections legitimately contain malicious artifacts), terminal/non-retryable by design, not a bug. Use for E1/E3/C5 real-sample work — pull directly via boto3, don't re-upload through the API | Postgres `evidence` table, confirmed 2026-07-29 |

**Two decisions already taken from this, do not relitigate:**

1. **Do not build a Sigma compiler.** Security Analytics compiles Sigma
   server-side and ships 2,077 rules. Building `pySigma` plumbing was scoped
   and then explicitly dropped.
2. **Do not build a bespoke ML feature store / model registry for v1.** RCF
   (Anomaly Detection) and ML Commons ship in-cluster.

---

## 1. Cross-cutting invariants — every agent, every item

Non-negotiable. An implementation violating any of these is rejected regardless
of whether it "works".

1. **OOP / composition-first (§A.1, §A.4).** This platform will be extended
   continuously. Every new capability is an **ABC + concrete implementations
   behind it**, registered via DI — never an `if/elif` chain, never a module of
   free functions, never configuration-as-extensibility. Max ~200 lines/class;
   delegate. Adding the *next* detection backend / stream transport / enrichment
   source / playbook action must require **zero edits to existing classes**.
2. **Layering (§A.3).** `src/domain/` and `src/application/` import **zero**
   framework/driver code. New domain entities are pure Pydantic.
3. **Tenant isolation is computed, never supplied (§G.3).** `org_id` is always
   derived from the authenticated `TenantContext` (or a verified client
   certificate) — **never** from module output, rule output, detector output,
   collector payload, or model output. This is the single most important
   security invariant in the system.
4. **Audit every mutation (§A.2).** State changes go through
   `AuditLogService.audit_context(...)`; the per-row hash chain is not optional.
5. **Derived opinions must never mutate primary evidence.** Detections,
   correlations, risk scores and ML verdicts are *derived, recomputable
   artifacts about immutable facts*. They get their own entities and their own
   provenance. They must never write to `Evidence`, the evidence audit chain, or
   an indexed timeline record.
6. **Replayability for anything court-facing.** Any verdict a examiner may have
   to defend must reproduce from (pinned rule/model version + stored input).
   Version identifiers are stored with the verdict, not looked up later.
7. **Verification-first (§F).** No item is "done" without a real run against the
   real dependency at the pinned version, with **captured output committed**.
   *Plausible code with no captured real run is an automatic fail.*
8. **Fail loudly, never silently.** Swallowed partial failures are treated as
   defects of the same severity as data loss (this repo has already shipped two:
   the ClamAV `NoOpScanner` downgrade and `bulk_index` error swallowing).

---

## 2. The layered proof discipline

Extends `CLAUDE.md` §F.3. **Every item declares its layer, and a layer cannot
be skipped.** An L3 chain PoC is not permitted to be the first real run of a
component that has no L1.

```
poc/
├── <component>/                    L1  component alone vs. its real dependency
├── <component_a>_<component_b>/    L2  two components genuinely linked
├── chain_<flow>/                   L3  3+ components, one user-visible flow
└── global_<scenario>/              L4  whole platform, realistic scenario
```

- **L1 — component.** Does this thing work at all, against the real service, at
  the pinned version? Captured output mandatory.
- **L2 — link.** Do these two components actually interoperate — schemas,
  auth, error semantics, tenant scoping? Most real bugs in this repo have been
  found here.
- **L3 — logical chain.** Does a complete flow hold end-to-end with real data
  (e.g. *collector → stream → seal → index → detect → triage*)?
- **L4 — global.** Realistic adversary scenario across the whole platform,
  including multi-tenant isolation under load.

Existing precedents to follow: `poc/opensearch/` (L1), `poc/plaso_opensearch/`
(L2), `poc/full_pipeline/` (L3), `poc/full_ingestion_test/` (L4).

---

## 3. Milestones

Gates are **blocking**: a NO-GO changes downstream design and must be reported
before dependent work starts.

| Milestone | Theme | Gate |
|---|---|---|
| **M0** | Schema foundation + isolation gate | **A3 GO/NO-GO** |
| **M1** | Provenance & stream schema | — |
| **M2** | Detection engine (rules) | **C1 coverage ≥ threshold** |
| **M3** | Continuous ingestion | **D3 custody preserved** |
| **M4** | Artifact detection (YARA, memory) | — |
| **M5** | Enrichment & correlation | — |
| **M6** | Analytics (rarity, then RCF) | **G3 replayability** |
| **M7** | Response / SOAR | **H2 no-unapproved-destructive-action** |
| **M8** | Validation, ops, parity, global E2E | **I4 L4 green** |

---

## M0 — Schema foundation + isolation gate

### A1 · Index template hardening + ECS field expansion — L1
**Objective.** Make the timeline schema safe for rule-based detection. Today
`dynamic` is unset (→ `true`) with no `dynamic_templates`, and `extra` is merged
in dotted form, so parser-specific fields land as `text`+`.keyword`. A Sigma
rule's `term` query on the un-suffixed name then **matches nothing, silently** —
the same defect class already documented at `timeline_ingest.py:71-75`, except
the silent failure is now a **missed detection**.
**Must include** at minimum, mapped explicitly: `process.command_line`,
`process.parent.*`, `source.ip`, `destination.ip`, `destination.port`,
`dns.question.name`, `file.hash.{md5,sha1,sha256}`, `registry.{path,key,value}`,
`event.code`, `event.action`, `winlog.*` as needed, plus `data_type` (Plaso
taxonomy) as `keyword`. `kronos.org_alias` is currently **written but unmapped**
— fix.
**Depends on:** nothing. **Blocks:** everything in M2.
**STATUS (2026-07-29): implemented and REAL-VERIFIED.** `dynamic: false`
chosen (not `strict` — would reject writes on any unlisted field). See
`poc/ecs_schema_hardening/` — 12/12 real checks against the live cluster:
bug reproduced (zero-hit term query on a real, existing doc), fix confirmed,
and the `dynamic:false` trade-off confirmed (unmapped field accepted +
stored, just unindexed). Existing indices keep their old mapping until
reindexed — documented, not addressed in this pass (needs a real
reindex/rollover plan, not something to do unattended).

### A2 · ECS field-mapping registry + CI validation — L1
**Objective.** One authoritative, testable mapping from each parser's output to
canonical ECS field names, so community rules are portable across all six
parsers. Must be an extensible registry object (new parser = registration, not
an edit to existing code). **CI must fail** if the registry names a field the
index template does not map — that mismatch is the A1 silent-failure bug.
**STATUS (2026-07-29): framework implemented and real-verified; coverage
partial.** `src/application/ecs_field_registry.py` — `FieldMapping` ABC +
`ECSFieldMappingRegistry` + `validate_against_index_template()` (the CI
check). 6/6 real pytest passes including a regression guard that the
validator actually catches a deliberately-unmapped field. Only `evtx-rs`
mapped so far (the real gap: `winlog.event_data.*` raw names never become
`process.command_line` etc.) — verified by reading `evtx.py`. Checked
`SuricataEveParser` too: it already writes ECS-shaped keys directly into
`extra` (`source.ip`, `destination.port`), so it needs **no** mapping —
don't add one. `CloudTrailParser`/`NginxParser`/`PlasoParser`/
`ChromeHistoryParser` **not yet individually inspected** — next agent must
read their real `extra[]` writes before assuming either way, same as was
done for evtx/suricata here. Deliberately skipped mapping
`winlog.event_data.Hashes` → `file.hash.sha256`: Sysmon's raw value is a
composite string (`MD5=...,SHA256=...`), a plain rename would misrepresent
it — needs real parsing logic first.
**Depends on:** A1 (same surface — same agent).

### A3 · GATE · Security Analytics multi-tenant isolation — L2
**Objective.** Determine whether Security Analytics can be used at all without
breaking tenant isolation. Detectors are cluster-level objects and findings land
in `.opensearch-sap-*` **system** indices; the existing isolation model is DLS
templated on `kronos.org_id` over `kronos-*`, which does **not** obviously
extend to plugin system indices.
**Answer definitively:** can org A's analyst read org B's findings/alerts/
detectors? Under what role config, if any, is that prevented?
**NO-GO consequence:** findings must be treated as privileged internal state,
surfaced to tenants exclusively through KronOS's own audited `Detection` entity
(C4) with backend-enforced filtering, and the Dashboards-native Security
Analytics UI cannot be exposed to tenants at all.
**Depends on:** nothing (poc-only). **Blocks:** C1, C2, C4, C6.
**STATUS (2026-07-29): GATE RESOLVED — GO WITH CONDITIONS, real-verified.**
See `poc/security_analytics_tenant_isolation/` (9/9 real checks, real
Dashboards-SSO login as a real tenant analyst). Finding: SA/Alerting have
**no per-tenant scoping at all** — pure cluster-action RBAC, no DLS
equivalent. Isolation today is by absence of grant (confirmed: no KronOS
tenant role has any SA/alerting permission; direct raw-index reads of
`.opensearch-sap-*` are also denied by `kronos-generic-tenant`'s
`index_permissions`, which cover only `kronos-*`). Binding conditions for
C1/C2/C4/C6: (1) never map SA/alerting roles to any tenant-facing role —
if ever granted, that user sees every org's data, cluster-wide, with no
recovery; (2) detectors/rules/findings are managed exclusively by a KronOS
backend service using admin credentials, same trust tier as
`ensure_index_template`; (3) all tenant-facing access goes through
KronOS's own `Detection` entity (C4) with application-layer `org_id`
filtering — not a NO-GO fallback, the only correct design, confirmed; (4)
the native SA Dashboards UI must never be exposed to tenants.

### A4 · Known debt: `bulk_index` silent partial-failure — L1
**Objective.** `OpenSearchClient.bulk_index` counts per-document errors from the
bulk response and returns a reduced success count **without raising**. A partial
failure is invisible: `execute_parse` takes the success path, no error state, no
retry, no audit flag — timeline records silently vanish from a case. Fix so
partial failures are surfaced, attributable, and either retried or recorded.
**Depends on:** nothing. **Blocks:** trustworthy coverage measurement (C5).

---

## M1 — Provenance & stream schema

### B1 · Provenance split (`EvidenceProvenance | StreamProvenance`) — L1
**Objective.** Continuous telemetry has no `evidence_id`, no source-file
`sha256`, and no owning case, yet `KronosProvenance` mandates all three.
Introduce a discriminated union so the asymmetry is type-checked rather than
papered over with sentinel UUIDs (which would silently corrupt custody).
`StreamProvenance` carries `source_id`, `batch_id`, `event_offset`, and an
**optional** `case_id` (attachable during triage).
**Depends on:** A1.

### B2 · Stream index family + DLS/ISM extension — L2
**Objective.** Second index family `kronos-{org}-stream-{source}-{yyyymm}`.
`kronos.org_id` must stay `keyword` and DLS must cover the new family — verify,
don't assume. **Depends on:** B1, A3.

### B3 · Per-source ISM tiering + legal hold — L2
**Objective.** Replace the single flat `kronos-*` policy with per-log-type
hot/warm/cold tiering and per-source retention, plus automated legal-hold
extension that blocks deletion. **Depends on:** B2.

**STATUS (2026-07-30): DONE.** `src/adapter/opensearch/ism_manager.py`
(`IsmLifecycleManager` ABC + `OpenSearchIsmLifecycleManager`) and
`src/application/ism_tiering.py` (`IsmTierResolver` + `DefaultIsmTierResolver`),
wired into `TimelineIngestionService` (self-healing attachment after every
flush) and `EvidenceIntakeService.set_legal_hold()` (mirrors
`Evidence.legal_hold` onto the case's real OpenSearch indices). Real
verification (`poc/ism_tiering_legal_hold/`, 15/15 checks passed) against
the live OpenSearch 2.11.1 cluster found a serious, previously-undiscovered
bug before writing any new logic: **every real, pre-existing KronOS case
index on this dev stack had its ISM managed-index job stuck at
`enabled: false, enabled_time: null`** — the already-deployed
`kronos-rollover` policy had never actually been ticking for any of them,
despite `_plugins/_ism/explain` reporting a policy_id attached. Root cause:
attachment itself works (confirmed for both explicit-`PUT` and `_bulk`-auto-create
paths, fresh); something (very likely a container/OpenSearch restart
mid-cycle, of which this session has had many) leaves a managed-index doc
stuck disabled, and the periodic ISM coordinator sweep never revisits an
index that already has a (disabled) managed-index doc — no automatic
self-healing exists. A second real bug was found while building the fix:
`POST _plugins/_ism/add/{index}` on an index that already has a recorded
policy_id (even a disabled one) returns **HTTP 200** with
`{"failures": true, ...}` in the body — the same silent-failure shape as
the historical `bulk_index` bug (A4). `ensure_managed()` now does
`remove`-then-`add` unconditionally and checks the response body, not just
the status. **All 17 real, stuck production indices on this dev stack were
remediated** (17 disabled → 0 disabled, confirmed via direct query).
Per-source tiering: a new `kronos-stream-aggressive` policy (5 GB/7-day
rollover, 90-day delete) for high-volume telemetry sources
(network/firewall/flow/dns), confirmed via real ISM template priority
ordering (`priority: 200` beats the general pattern's `100`) — reachable
today only via direct `ism_manager` calls, since `TimelineIngestionService`
is case-scoped only; wiring it into a real stream-ingest call site is D1's
job, not B3's. Legal hold: `Evidence.legal_hold` already existed
(MinIO Object Lock, pre-dating this session); B3 extends it to also
`place_legal_hold()`/`release_legal_hold()` the evidence's case's real
OpenSearch indices, case-grade (release only resumes once no other
evidence in the case is still held, checked via a real
`stream_by_case()` scan). See `poc/ism_tiering_legal_hold/README.md` for
the full account. Unit tests: `tests/unit/adapter/test_ism_manager.py`,
`tests/unit/application/test_ism_tiering.py`, plus new coverage in
`test_timeline_ingest.py` and `test_evidence_legal_hold_retention_tsa.py`.

---

## M2 — Detection engine (rules)

### C1 · Security Analytics field mappings per log type — L2
**Objective.** Map KronOS indices onto SA log types (`windows`, `linux`,
`cloudtrail`, `network`, `apache_access`) via
`_plugins/_security_analytics/mappings`, then **measure** how many of the 2,077
rules actually fire against real parsed evidence. **Gate:** report real
fired-rule counts per log type; a mapping that fires ~0 rules is a failure, not
a milestone. **Depends on:** A1, A2, A3.
**STATUS (2026-07-30): GATE PASSED — mechanism confirmed real, coverage
measured honestly, one open gap flagged.** See
`poc/security_analytics_field_mappings/`. Real detectors created (admin-
only, per A3) over real case indices for `windows`/`cloudtrail`/`network`;
real prepackaged rules fired against real ingested samples: **windows
3/1580 rules fired** (205+8+8 findings, real ATT&CK tags
t1006/t1212/t1110.003), **network 1/38 fired** (11 findings, t1021.001),
**cloudtrail 0/32 fired** (open gap — alias mappings accepted (200) but an
unmapped-field count never visibly dropped; not yet root-caused whether
that's a real mapping problem or just that this one benign sample doesn't
trigger any of the 32 rules' specific conditions). Low absolute percentages
are expected against single benign (non-adversarial) samples, not a gate
failure — C5's ATT&CK-coverage chain should re-run this same setup against
adversarial fixtures. Added a `winlog.event_data.*` dynamic_templates
override to the A1 index template (that namespace is genuinely
per-EventID-variable, can't be exhaustively pre-mapped) — scoped, not a
regression of A1's `dynamic:false` default elsewhere. Does not block
C2/C4/C6.

### C2 · Per-org detector provisioning service — L2
**Objective.** Detectors are cluster-level; provisioning must be per-org and
automatic, scoped to that org's index patterns — following the established
pattern of `ensure_generic_tenant_role` / `DashboardsIndexPatternProvisioner`.
Idempotent; new org needs zero manual steps. **Depends on:** C1.

**STATUS (2026-07-30): DONE.** `SecurityAnalyticsDetectorProvisioner`
(`src/adapter/opensearch/detector_provisioner.py`), wired through
`create_case()` best-effort, non-blocking, admin-credentials-only (A3).
Real verification (`poc/detector_provisioning/`, 16/16 checks passed)
against the live 2.11.1 cluster caught and fixed three real bugs invisible
from the code or the mocked unit tests: (1) missing `verify=False` on the
internal `httpx.AsyncClient` — the internal `OPENSEARCH_URL` is
`https://opensearch:9200` even docker-internally, so every real call was
failing `CERTIFICATE_VERIFY_FAILED`; (2) `extra={"name": ...}` in two log
calls, which raises `KeyError` in `Logger.makeRecord` (`name` is a reserved
`LogRecord` attribute) once INFO-level structured logging is enabled per
CLAUDE.md §B.4 — would have crashed every real provisioning call in
production; (3) the idempotency check queried a flat `name.keyword` field
that doesn't exist — `.opensearch-sap-detectors-config`'s real mapping has
`name` nested under a `detector` object, so the query silently matched
zero documents always, defeating idempotency (every call created a
duplicate). Also directly reproduced the real OpenSearch 2.11.1 PUT-update
defect (`kotlin.collections.EmptyMap cannot be cast to
kotlin.collections.MutableMap`) that justifies check-then-create-only
instead of create-or-update. One real, *unresolved but non-blocking* data
gap found and documented (not papered over): the live dev org `kronos-dev`
has ~40 legacy pre-A1 case indices with inconsistent field mappings
(`cloud.service.name` typed `keyword` post-A1 vs. dynamically-inferred
`text`+keyword pre-A1), which trips OpenSearch SA's real cross-index
alias-consistency check with a 500 when provisioning that specific org's
detectors — confirmed to be a data-quality artifact of this dev org's own
PoC history, not a provisioner defect (Part 1 proves the mechanism works
end-to-end against a clean org); the binding safety property (a real SA
failure must never block case creation) was confirmed to hold under this
exact real failure. See `poc/detector_provisioning/README.md` for the full
account. Unit tests: `tests/unit/adapter/test_detector_provisioner.py`
(6 tests, mocked httpx).

### C3 · Rule-pack lifecycle: versioning, signing, custom CRUD, cost gate — L1+L2
**Objective.** Rules are untrusted input. Two real risks: a rule compiling to a
catastrophically expensive query (leading-wildcard × regex over a year) is a
trivial DoS; and any raw-DSL passthrough path would bypass DLS entirely. Deliver
versioned rule packs, Cosign verification for third-party packs (reuse
`reviews/Extensibility_Architecture_Proposal.md` §4 unchanged), custom-rule CRUD,
and a pre-execution cost gate. **Depends on:** C1.

**STATUS (2026-07-31): DONE.** `src/domain/rule_pack.py` (`RulePack`,
`RulePackVersion` append-only versioning, `CustomRule`, `CostGateVerdict`),
`src/application/rule_pack_service.py` (versioned CRUD + Cosign gate,
zero OpenSearch knowledge), `src/application/rule_pack_publisher.py`
(the one place a pack's content reaches the real cluster), `RuleCostGate`
(pluggable heuristics: leading-wildcard `|contains`/`|endswith`, unanchored
`|re`), `SecurityAnalyticsCustomRuleClient` +
`SecurityAnalyticsCustomRuleDetectorProvisioner` (a deliberate sibling to
C2's detector class, not an extension — custom-rule content changes on
every CRUD op, so it uses delete-and-recreate idempotency instead of C2's
check-then-create-only, both confirmed necessary by the same real
OpenSearch 2.11.1 PUT-update defect C2 found), and
`CosignPackSignatureVerifier` (real Cosign v3.1.2, first use in this repo).
Real verification (`poc/rule_pack_lifecycle/`, 22/22 checks passed)
against the live cluster, real Postgres, and a real installed Cosign
binary found: (1) a real Sigma rule's `logsource` is product/service
(zeek-style), not a bare category field, and omitting
`description`/`author`/`references`/`falsepositives` reproduces a real 500
`NullPointerException`; (2) OpenSearch's own custom-rule API accepts a
genuinely expensive `|contains` rule with zero validation — confirmed by
actually pushing one, the concrete justification for why this gate must
run client-side; (3) Cosign v3.1.2's `sign-blob --bundle` produces a
self-contained JSON bundle with an embedded Rekor proof, not the bare
`.sig` older docs describe; a real signature-verified pack is accepted, a
tampered one is rejected wholesale (no version created at all, fails
closed before any bookkeeping); (4) a custom rule's OpenSearch-assigned
`_id` is independent of the Sigma YAML's own declared `id:`. Unit tests:
`test_cost_gate.py`, `test_rule_pack_service.py`,
`test_rule_pack_publisher.py`, `test_custom_rule_client.py`,
`test_custom_rule_detector_provisioner.py`, `test_cosign_verifier.py`
(40 tests). See `poc/rule_pack_lifecycle/README.md` for the full account.

### C4 · `Detection` entity + triage FSM + audited finding sync — L2
**Objective.** SA findings are mutable plugin state outside the Postgres hash
chain. Mirror them into an immutable, audited `Detection` entity with its own
triage FSM (`NEW → INVESTIGATING → TRUE_POSITIVE | FALSE_POSITIVE`), storing the
**exact rule version** that fired for replayability. `org_id` from
`TenantContext`, never from the finding. **Depends on:** C2, A3.

**STATUS (2026-07-30): DONE.** `src/domain/detection.py` (`Detection`,
`DetectionTriageState` FSM mirroring `EvidenceState`'s idiom),
`src/application/detection_sync.py` (`DetectionSyncService`, strictly
read-only against OpenSearch), `src/application/detection_triage.py`
(`DetectionTriageService`, every transition audited via
`AuditLogService.audit_context()`), `src/adapter/opensearch/findings_client.py`
(`SecurityAnalyticsFindingsClient`, admin-only per A3), and
`src/adapter/repository/postgres_detection.py`. Real verification
(`poc/detection_finding_sync/`, 20/20 checks passed) against the live
OpenSearch 2.11.1 cluster + real Postgres found two real, non-obvious
facts before writing the sync code: (1) real SA findings live in
**per-log-type** indices (`.opensearch-sap-{log_type}-findings-*`), not
`.opensearch-sap-findings-*` — an earlier session check against the wrong
pattern had incorrectly concluded C1's findings were "gone"; (2) SA
detectors only evaluate documents indexed **after** the monitor's own
last-run cursor, not pre-existing ones — a real operational fact, not a
KronOS bug. A real finding's `queries` field is a list (one finding can
match multiple rules), so `Detection.rule_matches` is a tuple, matching
the real data shape. Idempotency (re-sync creates zero duplicate rows),
the audited triage FSM (real hash-chain-linked `DETECTION_TRIAGE_TRANSITIONED`
events, `AuditLogService.verify_chain()` confirmed intact), and illegal-transition
rejection (with its own real `DETECTION_TRIAGE_TRANSITION_FAILED` audit
event, no reopen loophole on a terminal state) were all proven against
real Postgres, not asserted from code reading. See
`poc/detection_finding_sync/README.md` for the full account. Unit tests:
`tests/unit/domain/test_detection.py`, `test_detection_sync.py`,
`test_detection_triage.py` (40 tests). DI wiring
(`get_detection_sync_service`/`get_detection_triage_service`) exists but no
route or automatic trigger yet — that is C6's scope, not C4's.

### C5 · Rule coverage measurement + ATT&CK mapping — L3
**Objective.** `chain_detect_from_evidence/`: real upload → parse → index →
detect → `Detection` row. Report real coverage by ATT&CK technique.
**Depends on:** C4, A4.

**STATUS (2026-07-31): DONE, with a real, important architectural finding —
not a clean pass.** `poc/chain_detect_from_evidence/` real-chained upload →
Celery-driven parse → OpenSearch indexing → admin-only detector creation →
`DetectionSyncService` → Postgres, using genuinely fresh evidence (not a
reused already-indexed sample): 19/20 mechanics checks passed. The 20th
(a real SA finding firing within the run) failed for a real, conclusively
root-caused reason, **not a bug in any C1-C4 component**: OpenSearch
Security Analytics monitors filter candidate documents by whether their
own `@timestamp` falls within a recent execution window since the
monitor's last run — not by write/arrival order. Confirmed directly: the
same real evidence with its genuine historical timestamp (2015-era, from
the real EVTX file) produced zero findings across 8+ minutes and many
1-minute schedule cycles; re-indexing one document with **only**
`@timestamp` changed to "now" produced a real finding on the very next
cycle. **Real forensic evidence is, by definition, always historically
timestamped** — this means SA's detector/monitor model, oriented around
continuously-arriving present-time telemetry (the future D-milestone
stream path), is structurally the wrong fit for evaluating KronOS's
**evidence** ingestion path as currently configured. C4's own PoC had
already quietly worked around this exact issue (re-indexing samples with a
fresh timestamp to get a demonstrable finding) without generalizing the
implication — this item makes it explicit rather than leaving it buried.
**Open follow-up, not yet scoped as its own roadmap item:** either a
scheduled/backfill query mode for SA monitors against a fixed absolute
time range instead of "since last run," or a KronOS-native retrospective
rule-evaluation path independent of SA's monitor-schedule model. Real
measured ATT&CK coverage for this run's own fresh evidence: honestly zero
(nothing new fired to sync) — a correct, not a failed, measurement given
the root cause above. See `poc/chain_detect_from_evidence/README.md` for
the full account. No `src/` changes were needed or made for this item.

### C6 · Detection API + triage UI — L3
**Objective.** Backend-filtered detection list/detail/triage endpoints and UI.
If A3 was NO-GO, this is the *only* tenant-facing surface for findings.
**Depends on:** C4.

**STATUS (2026-07-31): DONE.** `src/external/routes/detections.py`
(`GET /api/detections` org-scoped+filterable, `GET /api/detections/{id}`
404-not-403 on cross-org, `POST /api/detections/{id}/triage` delegating
entirely to C4's already-audited `DetectionTriageService`, 409 not 500 on
an illegal FSM transition) plus a React frontend (`DetectionsPage`,
`DetectionDetailPage`, `TriageStatePill`, FSM-aware triage buttons),
matching the existing `CasesPage`/`CaseDetailPage` idiom. This is the
tenant-facing surface the A3 gate's binding condition requires — SA/
Alerting's own APIs are never proxied here, only the audited `Detection`
entity. Role split: read routes open to all four roles, triage restricted
to org_admin/case_lead/analyst (mirrors the §1 permission matrix's
"Upload evidence" row). Real verification: `poc/detection_api_triage_ui/`
(25/25 checks) against the real running backend with real Keycloak JWTs
from real logins across two real orgs — real org-scoped list/filter over
C4's 10 real Detection rows, cross-org isolation (404 not 403, verified
list/detail/triage all three), a real persisted `NEW→INVESTIGATING`
transition, illegal-transition and terminal-reopen rejection (409), and
read-only-role-cannot-triage (403). Real browser check via headless
Chromium: logged in as case-lead, saw all 10 real rows with correct
triage pills and real ATT&CK tags, filtered by state, opened a detail
page, clicked "Start Investigating," confirmed via direct `psql` that the
persisted row and a real audit row both reflect the transition — not just
a UI-state claim. Backend suite 767→781 passed, no regressions; frontend
`npm run test` 43 passed, `tsc -b`/lint clean. Known, reported (not
fixed) gap: no automatic trigger for `DetectionSyncService` exists yet
(no route or beat task calls it) — populating real `Detection` rows in
normal operation, beyond what earlier PoCs manually synced, remains open
follow-up work, not this item's scope.

---

## M3 — Continuous ingestion

### D1 · `StreamIngestAdapter` ABC + Redis Streams implementation — L1
**Objective.** Durable, replayable, at-least-once telemetry transport behind an
ABC. Redis Streams first: already deployed, consumer groups, no new
infrastructure or secrets. Kafka/Redpanda must be swappable with zero changes
above the adapter, and adopted only on measured need. Per-org stream keys so a
consumer for org A structurally cannot read org B, and one noisy tenant cannot
starve another. **Depends on:** B1.

**STATUS (2026-07-31): DONE.** `src/adapter/queue/stream_ingest.py`
(`StreamIngestAdapter` ABC + `RedisStreamIngestAdapter` + `InMemoryStreamIngestAdapter`
test double), keyed `kronos:stream:{org_id}:{source_id}` (org first —
isolation is structural, not app-layer-filtered). Real verification
(`poc/stream_ingest_redis/`, 22/22 checks) against the real, live
dev-stack Redis (confirmed 7.4.9, `redis` client 8.0.1 — the `>=5.0` pin
has drifted, flagged): two orgs with the *identical* source_id never
share a key; at-least-once delivery via real consumer groups
(`XREADGROUP`/`XPENDING`/`XAUTOCLAIM` — an unacked read genuinely stays
pending, a fresh consumer reclaims it after an idle threshold, ownership
demonstrably transfers); durability is server-side (a brand-new
connection + consumer name, after the original connection fully closed,
picks up exactly the backlog produced while "no consumer was running");
cross-org isolation confirmed via a real `NOGROUP` error (not just an
empty result) when one org's group is used against another org's key; a
real 20,000-event burst on one org's key does not delay an independent
consumer on another org's key (no shared bottleneck); `MAXLEN ~50`
approximate trimming confirmed to actually reduce 200 writes to 100
retained. Replay scope stated honestly: from the consumer group's own
start cursor, not arbitrary-timestamp seek (Redis Streams has no native
timestamp index) — a deliberate, bounded design choice. Wired into DI via
a new `stream_redis_db` setting (default 3), a dedicated DB number on the
same shared Redis instance so stream traffic never contends with the
Celery broker/backend (DB 1/2) or step-up tickets (DB 0). This is
strictly L1 (the adapter itself, not wired into D2's collector API or
D4's normalization pipeline yet — both consume it going forward). Also
finally gives B3's `kronos-stream-aggressive` ISM tier (built ahead of any
real producer) something to eventually be exercised by, once D4 lands.
Unit tests: `tests/unit/adapter/test_stream_ingest.py` (13 tests, mocked
redis client + a same-ABC-contract check on the in-memory double).

### D2 · Collector ingest API + mTLS identity — L2
**Objective.** Collector-facing ingest authenticated by **step-ca-issued client
certificates**, not long-lived bearer tokens (500 endpoints × static secret is
credential sprawl). `org_id`/`source_id` derived from the verified peer
certificate; a collector that lies in its payload must not be able to write into
another tenant. Backpressure and dedup-by-event-hash required.
**Depends on:** D1.

**STATUS (2026-07-31): DONE.** `CollectorIdentity` (org_id/source_id,
`src/domain/collector.py`), `X509SanCollectorIdentityExtractor`
(`src/external/middleware/collector_mtls.py`, parses a
`urn:kronos:collector:org:<uuid>:source:<id>` URI SAN from the
already-TLS-verified peer cert), `MTLSIdentityH11Protocol`
(`src/external/mtls_protocol.py`, recovers the verified peer cert via
asyncio's `ssl_object` since uvicorn 0.51.0 has no ASGI TLS extension —
confirmed by grepping its real installed source), `CollectorIngestService`
(backpressure + SHA-256 content-hash dedup, then produce via D1's
`StreamIngestAdapter` — extended with a new `approximate_length()` method),
`RedisEventDedupChecker` (atomic `SET NX EX`), a minimal standalone
`collector_app`/`run_dual_listener.py` (mTLS termination happens in this
uvicorn process itself, not nginx, for this deployment's most
security-sensitive new trust boundary). Real verification
(`poc/collector_ingest_mtls/`, 17/17 checks) against the live step-ca:
two real, distinct client certs issued for two different real orgs via
the real `admin` JWK provisioner (the only one actually configured — the
bootstrap script's `kronos-sa`/ACME additions are silently absent on the
live container); each real cert's request derives the matching real
org_id, never from the payload; a payload embedding a fake org_id is
structurally inert — confirmed via direct Redis inspection, not just a
200 response; no client cert, and an untrusted (non-step-ca-signed) cert,
are both rejected at the TLS handshake; real dedup and real (deliberately
tiny, for the test) backpressure both fire and are independently
confirmed via direct Redis reads.

**Real finding**, load-bearing for any future client of this API:
httpx 0.28.1's convenience `cert=(crt, key)` + `verify=<ca path>` tuple
form silently fails this exact TLS 1.3 + EC P-256 mutual-auth handshake
with `UNEXPECTED_EOF_WHILE_READING` on every attempt — isolated by
confirming the identical server/certs work correctly via `curl`, raw
`openssl s_client`, AND an explicit `ssl.SSLContext` passed to httpx as
`verify=`. Not a bug in this repo's own mTLS code (independently proven
correct first) — a real httpx-side quirk for this parameter combination,
worked around in the PoC and worth knowing for D6's later L3 chain.

**Scope note**: `run_dual_listener.py` is real and runs correctly as a
standalone process; it is not yet added to `docker/docker-compose.dev.yml`
— real deployment wiring is flagged as follow-up work, not attempted here
(matches this session's established pattern, e.g. B3's aggressive tier,
C2's kronos-dev legacy-index gap). See `poc/collector_ingest_mtls/README.md`
for the full account. Unit tests: `test_collector_mtls.py`,
`test_collector_ingest.py`, `test_event_dedup.py`,
`test_routes_collector_ingest.py` (24 tests).

### D3 · GATE · Batch sealing (Merkle + TSA + WORM) — L2
**Objective.** Reconcile continuous ingestion with chain of custody without
per-event hashing/scanning/timestamping. Seal stream segments (time- or
size-bounded) into immutable batches: one WORM object, one TSA token, one audit
event, **plus a Merkle root over per-event hashes** so any single event stays
independently provable. Reuse the construction `AuditLogService.anchor_day()`
and `src/domain/merkle.py` already prove.
**Gate:** demonstrate an inclusion proof for one arbitrary event from a sealed
batch. **Sealing failure must never ack the stream, and a `MAXLEN` trim of
unsealed events must page, not warn** — that is silent evidence loss.
**Depends on:** D1.

**STATUS (2026-08-01): DONE — GATE PASSED.** `src/domain/sealed_batch.py`
(frozen `SealedBatch`, validates `leaf_hashes`/`message_ids`/`event_count`
alignment), `src/application/batch_sealing.py` (`BatchSealingService` —
consumes via D1's `reclaim_stale(min_idle_ms=0)` + `consume()`, hashes each
payload as a Merkle leaf, writes one WORM manifest, calls a **mandatory**
TSA (unlike `anchor_day()`'s best-effort TSA — a batch missing its TSA token
is not "sealed", full stop), persists one `SealedBatch` row, logs one
`BATCH_SEALED` audit event, and only then acks — any failure before ack
raises `BatchSealFailedError` and leaves the source messages genuinely
unacked for D1's own at-least-once redelivery), `src/application/
sealing_trigger_policy.py` (`Size`/`Time`/`CompositeTriggerPolicy`, mirrors
`RuleCostGate`'s composition idiom), `src/adapter/repository/sealed_batch.py`
+ `postgres_sealed_batch.py`, `src/adapter/storage/sealed_batch_storage.py`
(`S3SealedBatchStorage` — one Object-Lock COMPLIANCE bucket per org, mirrors
`S3EvidenceStorage`). New `AuditEventType.BATCH_SEALED` /
`BATCH_SEAL_FAILED` / `BATCH_SEAL_WATERMARK_GAP_DETECTED`, new
`BatchSealFailedError` / `EvidenceLossDetectedError` exceptions. D1's
`StreamIngestAdapter` ABC gained `earliest_message_id()` (`XRANGE ... COUNT
1`), the concrete primitive the watermark-gap check needs. Unit suite:
850 passed (independently re-verified, up from the 818 baseline).

PoC: `poc/batch_sealing/` — 28/28 checks passed against the real
already-running dev stack (`docker-postgres-1` 16.14, `docker-redis-1`
7.4.9, `docker-minio-1`) plus a real openssl-`ts`-backed RFC 3161 TSA
(reusing `poc/rfc3161`'s own real-TSA substitute, since the dev-compose
`tsa` stub returns an empty body and can't produce a decodable token). The
literal gate condition was demonstrated by re-fetching a sealed batch fresh
from real Postgres (a separate round trip from the in-process object),
reconstructing an inclusion proof for an **arbitrary** event (index 2 of 5)
via `src/domain/merkle.py`, and verifying it true — plus two negative cases
(tampered leaf, tampered proof) both verifying false. Both binding
failure-mode requirements were also demonstrated against real
infrastructure, not just unit-mocked: (1) a real MinIO auth failure
(`ClientError`, wrong credentials) left the source events genuinely pending
per real `XPENDING`, raised `BatchSealFailedError`, wrote no `SealedBatch`
row, and a subsequent real recovery attempt sealed exactly those two
message ids via `reclaim_stale`, no loss or duplication; (2) a real `XTRIM
MAXLEN 1` past an already-sealed watermark raised `EvidenceLossDetectedError`
with a real `BATCH_SEAL_WATERMARK_GAP_DETECTED` audit row persisted, not a
swallowed warning.

Real gap found and fixed during this verification pass (not by the dead
subagent that built the feature): `PostgresSealedBatchRepository.
create_tables()` was never wired into `src/external/startup.py` —
`sealed_batches` would not have existed in any real deployment, so the
first production save would have failed with "relation does not exist."
Added alongside the other repositories' own `create_tables()` calls in
`wire_dependencies_async()`.

**Explicitly flagged, not yet done:** (1) nothing schedules
`BatchSealingService.seal_pending()` in production yet — no Celery beat
task, no `configure_batch_sealing_service()` call anywhere in `startup.py`
(mirrors D2's own precedent of the collector listener not yet being in
`docker-compose.dev.yml`) — natural fit for D5/D6, both of which already
depend on D3; (2) single-sealer-per-(org, source) assumption documented in
`BatchSealingService`'s own docstring — real multi-sealer concurrency would
need per-message ownership leases, not attempted; (3) a stream that goes
fully empty after a prior successful seal is treated as "nothing to check"
rather than an automatic gap (D1's adapter can't distinguish "never had
more data" from "everything including unsealed data was trimmed" once
empty) — a persistent last-produced-id watermark independent of the stream
itself would close this, flagged as follow-up.

### D4 · Continuous normalization pipeline (stream → ECS) — L2
**Objective.** Reuse the A2 registry to normalize continuous sources into the
*same* ECS schema as Plaso-parsed forensic events — one timeline, one query
surface. Extensible per-source: new source = new registered normalizer.
**Depends on:** D1, A2, B2.

**STATUS (2026-08-01): DONE.** Real input is a **sealed batch** (D3), never
the raw pre-seal stream: `StreamProvenance.batch_id` is a required field, so
a `TimelineRecord` tagged with stream provenance can't exist until that
event's batch is actually sealed. `src/application/stream_normalization.py`
(`StreamNormalizationService`) fetches an already-sealed batch's WORM
manifest, decodes each event, runs it through the `source_id`-registered
`StreamSourceNormalizer` (`src/application/stream_source_registry.py`,
mirrors `ECSFieldMappingRegistry`'s registration idiom), and bulk-indexes
via a new `TimelineIngestionService.ingest_stream_records()` sibling method
that reuses the exact same bulk_index/ISM/partial-failure-checking `_flush`
as the file-ingest path (A4's bug fix included, not reimplemented).
`TimelineRecord.kronos` widened to the `Provenance =
EvidenceProvenance | StreamProvenance` discriminated union (moved to
`src/domain/timeline.py`; `ProvenanceBase` extracted to a new dependency-free
leaf module `src/domain/provenance.py` to avoid a genuine circular import
between `timeline.py` and `stream.py`). One real concrete normalizer,
`ZeekConnLogNormalizer` (Zeek's default JSON `conn.log` format) — field
mapping independently re-verified against Zeek's own source
(`raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/conn/main.zeek`'s
`Conn::Info` record) both by the implementer and again by this orchestrator
before trusting it; correctly converts `duration` from Zeek's seconds
(`interval`, JSON-serialized as a float) to ECS's nanoseconds (`event.duration`,
`long`) — a real unit conversion, not a bare rename.

PoC: `poc/stream_normalization/` — 15/15 checks passed against the real
already-running dev stack (real Redis → real `BatchSealingService` (D3) →
real Postgres/MinIO/openssl-ts TSA → real `StreamNormalizationService` →
real `OpenSearchClient` → **an independent real `POST <index>/_search`**,
a separate HTTP round trip from the service's own return value, confirming
correct ECS fields (`@timestamp`, `source.ip`, `network.transport`,
`network.protocol`, correctly-unit-converted `event.duration`) and correct
`kronos.*` `StreamProvenance` fields (`source_id`, `batch_id` matching the
real sealed batch, `event_offset` 0..3, `case_id` correctly absent).

This item was dispatched to a subagent that died on a spend-limit
interruption after building the `src/` implementation and its own 45(ish)
unit tests, but **before** running the mandatory verification checklist
(mypy/black/ruff) or building the real PoC — the orchestrator (this
session) picked up from real on-disk state per the roadmap's own §6
pause/resume protocol, found the `src/` design sound on read-through, and
completed verification directly:
- **mypy found 18 real new errors** the dead subagent never checked for
  (confirmed via a true `git stash -u` baseline of 29 pre-existing errors
  vs. 47 with D4 applied). Fixed for real: `isinstance()` type-narrowing
  assertions in `timeline_ingest.py`'s `_fallback_id`/`_fallback_stream_id`
  and `archive.py`'s `_stamp_source_path` (each accesses one specific
  provenance subtype's fields on what is now a union type — a genuine
  runtime guard, not just a mypy appeasement), a `dict[str, Any]`
  annotation fix, and adding `stream_normalization.py` to the
  already-established `pyproject.toml` mypy override for pydantic
  `populate_by_name` construction (same symptom already documented there
  for `src.external.parsers.*`). Back to exactly the 29-error baseline
  after fixing, zero new errors.
- `black` reformatted one file; `ruff` had zero new issues.
- Independently re-ran the full unit suite (never trusting the subagent's
  self-report): **868 passed** (850 baseline + 18 new — `stream_source_registry.py`
  and `stream_normalization.py` unit tests, which the dead subagent hadn't
  reached yet, written and verified by the orchestrator).

**Explicitly flagged, not yet done:** (1) only one source normalizer exists
(Zeek conn.log) — the roadmap's own stated gate is architectural
extensibility, not source coverage, so this is not a gap; (2)
`StreamSourceNormalizer.source_id` keys on an exact string match, not a
per-host-collector prefix (D2's own multi-collector example) — flagged as
follow-up in the normalizer ABC's own docstring, not needed for this one
source; (3) nothing schedules `normalize_batch()` automatically yet — no
beat task, no trigger-on-seal wiring, mirroring D3's own explicit
scheduling follow-up — natural fit for D5/D6.

### D5 · Backpressure, DLQ, observability — L1
**Objective.** Lag/queue-depth/trim metrics, dead-letter for unparseable events,
alerting on sealer fall-behind. **Depends on:** D1.

**STATUS (2026-08-01): DONE.** Three independent mechanisms, each proven
against the real dev stack, none wired to automatic scheduling (same
precedent as D2's collector listener, D3's `seal_pending()`, D4's
`normalize_batch()` — this item proves each mechanism works when invoked,
per CLAUDE.md's own D5 scope note; no Prometheus/Grafana/`/metrics`
endpoint was added, per this item's own explicit out-of-scope list).

1. **Consumer-group lag/health.** `StreamIngestAdapter` ABC
   (`src/adapter/queue/stream_ingest.py`) gained
   `consumer_group_health(org_id, source_id, group) -> ConsumerGroupHealth`
   (a new frozen dataclass: `pending_count`/`min_pending_id`/
   `max_pending_id`/`consumer_pending_counts` from Redis Streams' real
   `XPENDING <key> <group>` summary form, `lag` from `XINFO GROUPS`'s own
   `lag` field, Redis 7+ — the two numbers answer different questions:
   "consumers reading but not acking" vs. "nothing reading this stream at
   all"). Implemented for real in `RedisStreamIngestAdapter` (verified
   against the real, live `docker-redis-1` 7.4.9 both via unit tests
   mocking the redis client per CLAUDE.md §B.5 and via the real PoC below)
   and honestly in `InMemoryStreamIngestAdapter` (documented limitation:
   this double has no real pending-entries-list, so `pending_count` is
   always 0 — matches `ack()`/`reclaim_stale()`'s own already-documented
   gaps in that class; `lag` IS real there, computed from the same cursor
   `consume()` already tracks). `lag=None` (not `0`) distinguishes "group
   never existed" from "group exists with zero backlog."
2. **Dead-letter for unparseable stream events — the concrete bug this
   item was scoped around.** Before this pass,
   `StreamNormalizationService.normalize_batch()`
   (`src/application/stream_normalization.py`) let a single event's
   `ParsingError` (e.g. one genuinely corrupt Zeek line) abort the whole
   `_records()` generator feeding `TimelineIngestionService.
   ingest_stream_records()` — real, observable data-loss risk for every
   other already-yielded, perfectly-good event in the same batch.
   `normalize_batch` now catches `ParsingError` per event, routes that
   event's raw payload/`batch_id`/`event_offset`/org/source/real error to a
   new `DeadLetterSink` ABC (`src/adapter/repository/dead_letter.py`,
   `InMemoryDeadLetterSink` + `PostgresDeadLetterSink` — mirrors the
   `SealedBatchRepository` ABC+impl pattern exactly; a new
   `dead_letter_events` Postgres table, chosen over a new storage backend
   since every other durable pipeline artifact is already Postgres-backed),
   logs it (`logger.warning`, no payload content — SS B.4), writes a new
   `AuditEventType.STREAM_EVENT_DEAD_LETTERED` event, and continues with
   the rest of the batch. Returns a new `StreamNormalizationResult`
   (`indexed_count`/`dead_lettered_count`) instead of a bare `int` so a
   caller can never conflate "all good" with "some silently vanished" — a
   real, intentional constructor/return-type break from D4, with both
   existing call sites (unit tests) updated, not papered over.
3. **Sealer fall-behind alerting.** `BatchSealingService.seal_pending()`
   gained an optional `stall_alert_after_seconds` threshold — distinct from
   `SealingTriggerPolicy`'s own trigger threshold (must be set well above
   it: a healthy, regularly-invoked sealer would already have sealed a
   segment long before reaching this threshold, so crossing it is real
   evidence the seal cycle itself isn't running/keeping up, a liveness
   problem, not evidence loss). Reuses `_check_watermark_gap`'s exact
   idiom (`logger.critical` + a dedicated `AuditEventType.
   SEALER_FALL_BEHIND_DETECTED` + a dedicated `SealerFallBehindDetectedError`
   exception class exists in `src/exceptions.py`) but — after actually
   reasoning about it, not copy-pasting — deliberately does **not** raise
   from the automatic path: unlike the watermark gap (data already,
   irreversibly trimmed by the time it's detected), the stale pending
   segment is still fully present and this very `seal_pending()` call is
   about to attempt sealing it; raising would abort the one call that
   could resolve the staleness. So it pages (log + audit event) and lets
   sealing proceed — proven for real in the PoC below: the alert fires
   AND the stale batch gets sealed in the same call.

**Real PoC:** `poc/stream_backpressure_dlq/` — 24/24 checks passed against
the real already-running dev stack (`docker-redis-1` 7.4.9,
`docker-postgres-1`, `docker-minio-1`, `docker-opensearch-1`, plus the same
real openssl-`ts`-backed TSA substitute D3/D4 used). (a) A real batch of 5
Zeek-conn-log-shaped events with one deliberately malformed at offset 2 was
sealed (sealing hashes raw bytes — it has no opinion on payload content, so
this is purely a normalization-time bug) and normalized: an independent
real Postgres `SELECT` confirmed exactly one `dead_letter_events` row at
the correct offset with the exact original malformed bytes and a real
`ParsingError` error_type, and an independent real OpenSearch `_search`
(filtered on this run's own `kronos.batch_id` — a real `keyword` ECS
field — not `match_all`, see the PoC's own README for why) confirmed
exactly the 4 good events landed. (b) 5 real events produced, 3 consumed
without acking via a real consumer group; `consumer_group_health()`'s
answer (`pending_count=3`, `lag=2`) was cross-checked against **raw**
`XPENDING`/`XINFO GROUPS` calls made independently in the PoC script
itself, not trusted from the adapter's own parsing alone — both agreed;
acking+draining brought both real numbers to zero; a never-created group
correctly reported `lag=None`. (c) One real event `XADD`'d with an
explicitly 1-hour-old message id (Redis Streams allows an arbitrary
starting id on a fresh stream, so no real sleeping was needed) triggered a
real `SEALER_FALL_BEHIND_DETECTED` audit row (`oldest_pending_age_seconds
>= 3599`, independently confirmed via Postgres `SELECT`) in the same
`seal_pending()` call that also wrote a real `BATCH_SEALED` row —
confirming the alert is additive, not blocking.

**Real findings during PoC verification, fixed, not hidden** (see the
PoC's own README for the full account): a first real run passed 24/24; a
second real run (checking idempotency) failed 2 checks because the PoC's
own fixed `org_alias`/fixed Zeek timestamps produce the same OpenSearch
index name every run, so a `match_all` query double-counted a prior run's
leftover documents — fixed by scoping the query to the run's own
`kronos.batch_id` (a real bug in the PoC's assertion, not in `src/`); a
third run then hit a real `OSError: Address already in use` on the PoC's
own local TSA responder port (`socketserver.ThreadingTCPServer`'s
`allow_reuse_address` defaults to `False`) — fixed with
`allow_reuse_address = True`. Re-ran clean afterward, confirmed idempotent
across repeated runs.

**Verification checklist:** unit suite independently re-run at **878
passed** (868 D4 baseline + 10 new: 5 for `consumer_group_health`, 3 for
sealer fall-behind alerting, 2 for the dead-letter fix). `mypy src/
--ignore-missing-imports`: a true `git stash -u` baseline (including
untracked files, per this session's own established discipline) confirmed
exactly **29 pre-existing errors**; with this item's changes applied, back
to exactly 29 — zero new, after fixing two real new symptoms first
(`postgres_dead_letter.py`'s `_from_row` typed its row parameter as
`dict[str, object]`, the same pattern `postgres_sealed_batch.py` already
carries as one of the 29 pre-existing errors — retyped as `dict[str, Any]`
instead of copying the same bug into a new file; `ConsumerGroupHealth`'s
`consumer_pending_counts` dict comprehension needed a real non-`None`
decode helper for consumer names, a genuine Redis Streams invariant, not
just a type-checker appeasement). `ruff check src/`: a true stashed
baseline was 27; back to exactly 27 after fixing one real new
import-order issue (`postgres_dead_letter` import misplaced alphabetically
in `startup.py`) — zero new. `black --check src/`: the pre-existing
16-file baseline unchanged; the 3 files this item's own new/changed code
touched (`dead_letter.py`, `postgres_dead_letter.py`, `batch_sealing.py`)
were reformatted clean.

**Explicitly flagged, not yet done:** (1) `DeadLetterSink`/
`PostgresDeadLetterSink` are not wired into `configure_dependencies()` —
mirrors `SealedBatchRepository`'s own precedent (its Postgres table is
created at startup via `create_tables()`, but nothing calls
`configure_batch_sealing_service()` in `startup.py` either yet); a
`get_dead_letter_sink()`/`configure_dead_letter_sink()` pair exists in
`src/external/dependencies.py` as the hook point, and
`PostgresDeadLetterSink.create_tables()` runs at real startup so the table
exists whenever a future caller needs it — deliberately not repeating D3's
own since-fixed gap of a missing `create_tables()` call. (2) No admin route
or beat task calls `consumer_group_health()`/lists dead-lettered events for
an operator yet — proving the mechanism, not wiring its consumption, is
this item's own explicit scope (see CLAUDE.md's D5 out-of-scope list). (3)
`stall_alert_after_seconds` has no default operational value chosen for
production — an operator must pick one deliberately above whatever
`SealingTriggerPolicy` threshold is configured for the same (org, source);
no attempt was made to derive one automatically from the trigger policy
object, since the ABC doesn't expose its own threshold for introspection
today. (4) `SealerFallBehindDetectedError` is defined but never raised
anywhere in this codebase yet (deliberately, see reasoning above) — it
exists purely as a hook point for a future caller (e.g. an admin
liveness/health-check route) that wants a hard-failure signal instead of
the default page-and-continue behavior.

### D6 · L3 chain: collector → stream → seal → index → detect
**Depends on:** D2, D3, D4, C4.

**STATUS (2026-08-01): DONE.** Verification-only item, same shape as C5
(`poc/chain_detect_from_evidence/`) but for the continuous-telemetry path:
chains D1–D5/C1/C2/C4's already-separately-verified real components
together with no new `src/` code needed. `poc/l3_chain_collector_to_detect/`
— 35/35 checks against the real dev stack: a real mTLS POST (D2) → real
Redis stream (D1) → real `BatchSealingService.seal_pending()` (D3, real
WORM/TSA/Postgres) → real `StreamNormalizationService.normalize_batch()`
(D4, real OpenSearch) → a real per-org Security Analytics detector (C1/C2)
that actually **fires** on the resulting document → real
`DetectionSyncService.sync_org_findings()` (C4) writing a real `Detection`
row → an **honest provenance-linkage check** following that `Detection`'s
`matched_document_ids` back to the real OpenSearch document and confirming
its `kronos.batch_id`/`source_id`/`event_offset` match the real sealed
batch — proving the chain is genuinely connected end to end, not five
independently-working pieces.

Correctly avoided C5's own documented pitfall (SA monitors evaluate
documents by whether `@timestamp` falls within a recent execution window,
not arrival order): every synthetic event used real wall-clock `time.time()`
timestamps, confirmed in the run itself, not the fixed 2025-01-01 constant
D4/D5's own narrower PoCs use. Additionally hedged against a second
plausible mechanism (a monitor baselining a per-shard cursor at creation
time) by running two rounds — benign events before the detector exists,
then the real trigger event strictly after — satisfying either candidate
mechanism rather than guessing at one. Targeted C1's own already-verified
real firing prepackaged rule (`network`/"Publicly Accessible RDP Service",
`attack.t1021.001`) rather than fabricating a new one.

No `src/` changes were needed (confirmed via `git status` before
committing) — every hop worked correctly on the first real run, including
the honest linkage check, using `Detection.matched_document_ids` (already
existed from C4) with no new provenance field required.

**Explicitly flagged, not yet done:** same nothing-schedules-this-
automatically follow-up already flagged by D3/D4/D5 (no beat task for
`seal_pending()`/`normalize_batch()`/`sync_org_findings()` yet — this PoC
drives each stage manually); this PoC targeted one specific known-good rule
and does not attempt to measure broader continuous-telemetry rule coverage
(a C1-style measurement exercise, not this item's job).

---

## M4 — Artifact detection

### E1 · Container unwrapping gap (tar-in-image) — L1
**Objective.** Real, reproduced gap from the `forensic2.E01` analysis: the image
was a **tar archive containing `image.dd` + `memory.dmp`**, so dfVFS found no
partition table and Plaso extracted zero events. No recursive unwrapping exists
for tar-inside-disk-image. Follow the `ZipArchiveParser` recursion pattern; do
not invent a parallel mechanism. **Blocks:** E3, E5 for real-world images.

**STATUS (2026-08-01): DONE.** `TarArchiveParser`
(`src/external/parsers/tar_archive.py`) mirrors `ZipArchiveParser` exactly,
registered first alongside it in `get_parser_registry()`: bounded
`read(cap+1)` per member (never trusts `TarInfo.size`, which GNU sparse
members can lie about the same way `ZipInfo.file_size` can), skips
non-regular members (symlinks/hardlinks/devices are the documented
`tarfile` traversal-CVE class — never resolved, just skipped), rejects
absolute/`..` member paths, and never calls `extractall()`. Depth and the
files/bytes budget now live in a new shared module,
`src/external/parsers/_container_common.py`, imported by **both**
`archive.py` and `tar_archive.py` — a real fix, not just factoring: two
independent per-type budgets would have let a zip-in-tar-in-zip nesting
tree reset either counter just by alternating container type, verified
closed by two new cross-type tests in `test_tar_archive.py`
(`test_depth_is_shared_across_tar_and_zip_nesting`,
`test_byte_budget_is_shared_across_tar_and_zip_nesting`).

Real, verified tar magic: POSIX ustar's mandated 5-byte `"ustar"` prefix at
header offset 257 — confirmed identical across GNU tar 1.35's own CLI
output and Python 3.14's own `tarfile` module (`GNU_MAGIC`/`POSIX_MAGIC`),
added to `validation.py`'s `_MAGIC_TABLE`. Pre-POSIX (V7) tar has no magic
at a fixed offset and is out of scope — real DFIR tooling (GNU tar, BSD
tar, Python `tarfile`, UAC) defaults to ustar-compatible headers.

**The raw-disk-image sub-gap (point 3 of this item's brief) was real and
has been fixed.** Before this pass, `PlasoParser` only recognised EWF
(E01) magic — a bare `image.dd`/`.img`/`.raw` (no partition table, no EWF
wrapper) had no path to Plaso at all, so unwrapping the tar alone would
not have fixed the actual incident: the tar would explode fine, then
`image.dd` would hit "no parser found" and vanish, reproducing the same
zero-events failure one layer deeper. Verified for real (not assumed)
against the exact pinned `plaso==20260512` in the already-running
`docker-celery-worker-plaso-1` container: built real ext4 (`mke2fs -d`,
no root needed), NTFS (`mkntfs` + loop-mount), and FAT16 (`mkfs.vfat` +
`mtools`) raw images on this host and ran real `log2timeline`/`psort`
against each with **zero extra flags** — dfVFS's own source-analyzer
already auto-detects all three filesystem superblocks directly ("Source
type: storage media image", same as EWF), producing real `fs:stat` events
with the filesystem's own dfVFS prefix (`EXT:`/`NTFS:`/`FAT:`, all three
already present in `firecracker.py`'s `_DFVFS_TYPE_PREFIXES` from earlier
EWF work — `_plaso_source_path()` needed zero changes). Fixed by adding the
three real, verified magic signatures (ext2/3/4 offset 1080, NTFS offset
3, FAT16/32 offsets 54/82) to both `PlasoParser.supports()` and
`validation.py`'s `_MAGIC_TABLE`.

A container member with a recognised type but no parser yet
(`memory.dmp` — Volatility is E5, not built here) logs
`tar_member_no_parser` and is skipped, mirroring `ZipArchiveParser`'s own
pre-existing `zip_member_no_parser` precedent exactly, per this item's own
instruction not to invent new behaviour for an already-solved case.

Real end-to-end PoC (`poc/tar_container_unwrapping/`, per CLAUDE.md §F):
built a real synthetic reproduction of the actual incident shape — a tar
named `forensic2.E01` (the exact misleading extension from the real
incident, proving detection is magic-byte- not extension-driven)
containing a real 4 MiB ext4 image (`mke2fs -d`, 3 real files at 3 real
distinct timestamps) plus a placeholder `memory.dmp` — fed through the
**real** evidence-intake pipeline (real PKCE login, real case, real
presigned MinIO upload, real `finalize_upload`) against the real,
already-running dev stack. Result: 20 real OpenSearch documents, all 3
real files recovered with their exact real timestamps (previously: zero),
`memory.dmp` produced zero records without any error marker or evidence
state regression, all `container_sha256` correct. Full transcript in
`poc/tar_container_unwrapping/output.txt`/`README.md`.

Verification: `~/venv/bin/python3 -m pytest tests/unit/ -q --no-cov` → 906
passed (baseline 878 + 28 new tests: `test_tar_archive.py` ×16,
`test_validation.py` ×6, `test_plaso_parser.py` ×6). mypy: 29 errors,
unchanged from the pre-existing baseline (confirmed via `git stash -u`),
none in touched files. ruff: 27 (baseline), fixed one new import-order
finding introduced by `_container_common.py` before landing. black: clean
on all touched files.

**Not covered (honest scope boundary), flagged for whoever picks up E3/E5
next:** `.tar.gz` (UAC's actual output format) is out of scope — gzip
bytes at offset 0 hide the ustar header, so this parser's magic check
correctly does not claim it; a future module would need to peel the gzip
layer first, itself just another link in the same recursive chain. Real
memory-dump parsing is E5, unchanged. GPT/MBR-partitioned raw images
(distinct from this PoC's single-filesystem-directly-on-the-file shape)
resolve via dfVFS's `TSK:` partition-table path instead — not separately
re-verified here.

### E2 · YARA-X sandboxed runner — L1
**Objective.** YARA-X (Rust) over libyara/`yara-python` — the latter compiles
untrusted rule text **in-process** and libyara has a CVE history; inside an API
worker that is one memory-safety bug from RCE. Subprocess, container-sandboxed
via `FirecrackerLauncher` per §G.3. Never shell out from inside a parser class.

**STATUS (2026-08-01): DONE (runner only — E3/E4 remain, by design).**
Real research first, per §F: `pip index versions yara-x` confirmed the real,
official VirusTotal/yara-x Python binding is on PyPI, latest **1.19.0**,
shipping a `cp38-abi3` manylinux wheel that installs and imports cleanly on
this host's Python 3.14.4 with **zero extra runtime dependencies** (`pip
show yara-x` → empty `Requires:`) — confirmed by a real `pip install
yara-x==1.19.0` into both a throwaway venv and the project's real dev venv.
Pinned `yara-x==1.19.0` in `pyproject.toml`.

A real `yr` standalone CLI binary also genuinely exists (GitHub releases),
but was **not** used: its documented `--output-format ndjson|json` surface
(`virustotal.github.io/yara-x/docs/cli/commands/`) only exposes rule
identifiers/namespace/tags, never per-match byte offsets — verified by
reading the real docs, not assumed. E3's own requirement ("matched-string
offsets so an examiner can independently verify") is unmet by that path.
The Python binding's `Match` object, by contrast, exposes real
`offset`/`length`/`xor_key` directly — confirmed for real: a rule matching
`"foobar"` in a synthetic blob returned matches at byte offsets 4 and 14,
both independently checkable by counting bytes (`poc/yarax_sandboxed_runner/
output.txt`, Scenario 1). That is the deciding factor: only the binding
path can honestly satisfy E3's stated requirement, so it was used —
**inside a subprocess worker**, never imported into the caller's process.

Built `YaraXSandboxRunner` (`src/external/sandbox/yara_x_runner.py`) as a
**separate class from `FirecrackerLauncher`**, not a subclass or a shared
base — same subprocess/JSON-io/timeout *architecture*
(`docker/yara/kronos-yarax-worker.py` mirrors `kronos-plaso-worker.py`'s
exact shape: real rule-source/target-bytes files on disk, CLI-arg paths, one
JSON object on stdout, everything else on stderr), but genuinely different
output shape (`YaraScanResult`/`YaraRuleMatch`/`YaraStringMatch` dataclasses
carrying rule identifier/namespace/tags + real matched-string byte
offsets, vs. `FirecrackerLauncher`'s `TimelineRecord` stream) and
`FirecrackerLauncher`'s own constructor is genuinely Plaso-specific
(`parser_name`/`parser_version` defaults, dfVFS `display_name` prefix
parsing) with no YARA-X analogue — mirrors this same branch's own E1
precedent (`TarArchiveParser`/`ZipArchiveParser`: two classes, one
pattern) rather than forcing a shared base for its own sake.

Two independent timeouts, same reasoning as the Plaso worker's
`_L2T_TIMEOUT`/`_PSORT_TIMEOUT` vs. the Celery task's own `time_limit`: the
worker itself calls `yara_x.Scanner.set_timeout()` (verified for real: a
pathological nested-quantifier rule against a large blob cleanly raised
`yara_x.TimeoutError` at the configured 1s, not a hang), and
`YaraXSandboxRunner` layers its own outer `subprocess.run(timeout=...)`
above that as a second kill-switch if the in-worker one somehow doesn't
fire — both paths covered by real tests, not just described.

**Honest risk-model statement (not oversold):** YARA-X's Rust
implementation removes the memory-corruption/CVE class of bug
libyara/`yara-python` carries — the reason this item exists — and running
it in a subprocess buys real *subprocess* isolation (a crashed/misbehaving
worker is not a compromised API/Celery process). It does **not** buy
Firecracker-microVM/gVisor isolation: this still runs as a plain host
subprocess inside the existing Chainguard/Wolfi container, the exact same
honest level of isolation `FirecrackerLauncher`'s own docstring already
states for Plaso today. No new claim beyond what's real.

**No new Dockerfile variant, no new Celery queue** — checked, not assumed.
Unlike Plaso, `yara-x`'s wheel is a single 9.3 MB self-contained extension
with no extra dependencies; the base `docker/Dockerfile`'s existing `pip
install .` step already picks it up from `pyproject.toml`. Nothing calls
`YaraXSandboxRunner` outside its own tests/PoC yet (E3 is the real future
caller), so wiring a dedicated queue now would be speculative — flagged for
whoever picks up E3 to decide once real workload/latency is known.

Verification: `~/venv/bin/python3 -m pytest tests/unit/ -q --no-cov` →
**920 passed** (baseline 906 + 14 new: `test_yara_x_runner.py`, 3 of which
drive the real worker script against the real, pinned `yara_x==1.19.0`,
100% coverage on both new files — confirmed via a full `--cov` run,
`src/exceptions.py` 20/20 and `src/external/sandbox/yara_x_runner.py` 92/92
— no coverage-omit entry needed, unlike `firecracker.py`). mypy: 29 errors,
unchanged from the pre-existing baseline (confirmed identical error list),
none in touched files. ruff: 27 (baseline), unchanged. black: clean on all
touched files. Real end-to-end PoC
(`poc/yarax_sandboxed_runner/`, per §F): 4 real scenarios (positive match
with correct offsets, honest negative match, clean compile-error surfacing,
tagged rule with two real overlapping-pattern occurrences) — full
transcript in `output.txt`.

**Explicitly not built here (E3/E4's job, flagged for whoever picks those
up next):** no wiring into the parser recursion path or
`ZipArchiveParser`/`TarArchiveParser`/`PlasoParser`'s already-surfaced
`source_path`/`container_sha256` (E3); no `StructuredArtifact(kind=
"yara.match")` emission, though `YaraRuleMatch`/`YaraStringMatch` already
carry every field E3 needs (rule identifier, tags, matched-string
offset+length) to build that `content` dict without this class changing;
no ruleset signing/versioning/lifecycle (E4); no Celery queue decision
(see above). `YaraXSandboxRunner.run()` currently accepts rule source text
directly (not a pre-compiled/cached `Rules` object) — fine for E2's scope
(one runner, one scan), but E3's real caller will likely want to compile
once per ruleset and scan many files, which this class does not yet
support (recompiling per call is correct but not optimized) — noted, not
solved, since nothing calls this repeatedly yet.

### E3 · YARA scanning in the recursion path → `StructuredArtifact` — L2
**Objective.** Scan **forensic artifacts**, not just the top-level blob. Hook
where `ZipArchiveParser` / `PlasoParser` already surface extracted files with
`source_path` + `container_sha256`. A match must be reportable as *"rule X at
`/Windows/Temp/x.exe` inside evidence.zip (container `4e3cf3…`)"* — that is an
admissible statement; *"matched somewhere in a 250 MB blob"* is not. Emit
`StructuredArtifact(kind="yara.match")` with matched-string offsets so an
examiner can independently verify. **Depends on:** E1, E2.

**STATUS (2026-08-01): DONE.** `ZipArchiveParser`/`TarArchiveParser` both
override `extract_artifacts()` (the existing, previously-unoverridden
`ForensicParser` hook, §G.1): shared container-walk logic was refactored
out of `parse()`'s own `_walk_zip`/`_walk_tar` into a common
`_iter_members()` so the same container-bomb defenses (path-traversal
rejection, bounded reads, shared `ExtractionBudget`) back both passes —
never two copies that could drift. Each member's raw bytes are scanned via
E2's `YaraXSandboxRunner` against rule text from a new, deliberately
minimal `YaraRuleProvider` ABC (`src/application/yara_rules.py`) +
`DirectoryYaraRuleProvider` (reads `*.yar` files from a directory) — E4
(ruleset signing/lifecycle) is explicitly not built here; both collaborators
default to `None`/honestly-disabled, matching the `RFC3161TimestampService`
pattern already used elsewhere. A rule-*compilation* error aborts the rest
of that evidence file's scan (fails identically for every member); a
*scan* error skips just the one member — mirrors the
`zip_member_no_parser`/`tar_member_no_parser` "one bad thing doesn't sink
the container" precedent. A container member that is itself a nested
container is both scanned as raw bytes *and* recursed into (via the
registry's own registered parser instances — this only works end to end
when every container parser registered in the DI container shares the same
`yara_runner`/`yara_rule_provider`, confirmed for real in the PoC below
after first reproducing the bug when it wasn't true).

This item was dispatched to a subagent that died on a session-wide spend
limit while mid-edit on `reset_dependencies()` — real, substantial `src/`
progress existed (the full `extract_artifacts()` implementation on both
parsers, the rule-provider abstraction, partial DI wiring) but no tests, no
PoC, and one incomplete edit. The orchestrator (this session) verified
per §6.2, found the design sound, and finished directly:
- Completed the interrupted `reset_dependencies()` edit (the two new
  globals were being set in `configure_dependencies()` but never reset
  between tests — a real test-isolation gap).
- Found and fixed a real, minor provenance gap: `_build_yara_artifact` in
  both parsers omitted `org_alias` (every other real `EvidenceProvenance`
  construction site in this codebase, e.g. `plaso.py`, sets it from
  `evidence.metadata.org_alias`) — fixed in both.
- Wrote the unit tests the subagent hadn't reached (12 in
  `test_tar_archive.py`, 3 lighter mirror tests in `test_archive.py`, 5 in
  a new `test_yara_rules.py`).
- Built the real PoC (`poc/yara_recursion_scanning/`) and, on the first
  run, found a real bug **in the PoC itself** (not `src/`): registering a
  `TarArchiveParser` without the yara collaborators into the registry,
  then calling `extract_artifacts()` on a separately-constructed,
  correctly-configured `ZipArchiveParser` *not* in the registry — when it
  recursed into a nested tar member, `_recurse_into_nested_container`
  resolved the registry's own unconfigured instance, so the inner member
  was silently never scanned. Fixed by registering both parsers with the
  same collaborators (the real `get_parser_registry()` wiring already does
  this correctly) — 12/12 checks passed once corrected.
- The PoC's real cost measurement (scenario (c)) also corrected a
  too-optimistic docstring claim: the *complete* `YaraXSandboxRunner.run()`
  round trip (real worker launch + `yara_x` import + rule/target file I/O)
  measured ~58ms per member on this host, not the ~16ms an earlier,
  narrower in-process-only measurement implied. The conclusion is
  unchanged (even a 500-member container adds only ~29s, still well inside
  a HEAVY Celery task's budget) but the docstring now states the real,
  complete number, not the optimistic one.
- Independently re-ran the full checklist: **935 passed** (920 D5/E1/E2
  baseline + 15 new), `mypy` **29** (baseline, zero new),
  `ruff` **27** (one new I001 import-order finding introduced then fixed,
  back to baseline), `black` clean on all touched files.

**Explicitly flagged, not yet done:**
- **Plaso-internal per-file scanning is out of scope and confirmed real**:
  Plaso's own pipeline doesn't expose raw per-file bytes for scanning (it
  only streams `TimelineRecord`-shaped events *about* files, not their
  content) — this item only scans container members `ZipArchiveParser`/
  `TarArchiveParser` themselves unpack, not files Plaso extracts from
  inside a disk image during its own dfVFS-based parsing. A real, larger,
  separate integration effort if ever needed.
- **Nothing wires a real ruleset into production DI** — `configure_dependencies()`
  accepts `yara_runner`/`yara_rule_provider` but `startup.py` never passes
  anything non-`None` (E4 doesn't exist yet to provide a real signed
  ruleset) — this is correct, not a gap, per the "honestly disabled" idiom.
- `YaraXSandboxRunner.run()` recompiles the combined rule source on every
  call (per-member, not per-rule, per `YaraRuleProvider`'s own docstring) —
  fine at measured real cost, flagged as a checked-not-guessed follow-up if
  a much larger real container ever makes this measurement stale.

### E4 · Ruleset lifecycle (signed, versioned) — L1
**Objective.** Same trust model as C3, applied to YARA rulesets.

**STATUS (2026-08-01): DONE.** `src/domain/yara_rule_pack.py`
(`YaraRulePack`, `YaraRulePackVersion` append-only versioning, `YaraRule` --
mirrors C3's `RulePack`/`RulePackVersion`/`CustomRule` shape exactly,
reusing `RulePackSourceTier` UNCHANGED per CLAUDE.md §G.3),
`src/application/yara_rule_pack_service.py` (`YaraRulePackService`:
versioned CRUD + `publish_version`, zero cost-gate knowledge -- see below),
`src/adapter/repository/yara_rule_pack.py` +
`src/adapter/repository/postgres_yara_rule_pack.py`
(`YaraRulePackRepository`/`PostgresYaraRulePackRepository`, mirroring
`postgres_rule_pack.py`'s append-only-versions-plus-mutable-pointer-table
pattern), and `SignedYaraRulePackProvider` + `yara_scan_org_var`
(`src/application/yara_rules.py`) -- the concrete `YaraRuleProvider`
implementation E3's own docstring anticipated, wired into
`ParsingOrchestrationService.execute_parse` with **zero changes** to
`ZipArchiveParser`/`TarArchiveParser` themselves. Real verification
(`poc/yara_rulepack_lifecycle/`, 22/22 checks passed) against real
Postgres and a real installed Cosign v3.1.2 binary, plus a real end-to-end
run through the actual `ZipArchiveParser.extract_artifacts()` +
`YaraXSandboxRunner` subprocess, found:

1. **No new signature verifier was needed.** `CosignPackSignatureVerifier`
   (C3) is genuinely generic over content bytes -- reused completely
   unchanged to sign/verify YARA rule-pack content, confirmed by an actual
   `cosign sign-blob`/`verify-blob` round trip over real YARA-X rule text
   (not just Sigma YAML).
2. **No cost/DoS gate was built, as a considered decision, not an
   oversight.** C3's `RuleCostGate` exists because a bad Sigma rule
   compiles to an expensive query against a *shared, multi-tenant
   OpenSearch cluster*. YARA-X scanning has no equivalent shared-resource
   amplification path: `YaraXSandboxRunner` (E2) already wall-clock-bounds
   every scan two ways (in-worker `Scanner.set_timeout()` + its own outer
   subprocess timeout) -- a real, already-verified mitigation for the
   analogous risk, contained per-scan/per-member in one sandboxed
   subprocess, never cluster-wide. Building a parallel gate would
   duplicate that existing mitigation for a risk shape that doesn't
   apply. See `src/domain/yara_rule_pack.py`'s module docstring for the
   full reasoning.
3. **`get_rule_source()`'s zero-argument contract (frozen, per E3) meant
   org scoping needed a `ContextVar`, not a new method parameter.** A
   signed/versioned pack is inherently org-scoped, but changing
   `YaraRuleProvider.get_rule_source()`'s signature would have required
   touching `ZipArchiveParser`/`TarArchiveParser`'s call sites -- explicitly
   out of scope. `yara_scan_org_var` is bound by
   `ParsingOrchestrationService.execute_parse` (the one call site for
   every `ForensicParser.extract_artifacts()`, not just the two container
   parsers) immediately around that call and reset afterward, mirroring
   the existing `depth_var`/`budget_var` idiom
   (`src/external/parsers/_container_common.py`). Verified for real (a
   different org's bound context sees nothing; no bound context at all
   yields an honest `None`) and by a dedicated unit test proving the bind/
   reset happens in the real orchestration path, not just inside the PoC.
4. **No HTTP route was added**, matching C3's own real scope exactly (a
   repo search confirmed C3 itself never got one either -- only DI-level
   FastAPI dependency functions). `get_yara_rule_pack_service`/
   `get_yara_rule_pack_repository` exist in
   `src/external/dependencies.py`, ready for a future route.
5. **A real, previously-undiscovered gap in E2/E3's own production
   activation was found and deliberately NOT worked around**: neither
   `docker/Dockerfile` nor `docker/Dockerfile.plaso-worker` `COPY`s
   `docker/yara/kronos-yarax-worker.py` into the built image (unlike
   `docker/plaso/kronos-plaso-worker.py`, which IS copied in) --
   `YaraXSandboxRunner`'s default worker path would not resolve inside a
   real deployed container today. `PostgresYaraRulePackRepository` +
   `create_tables()` persistence wiring WAS added to
   `wire_dependencies_async` (real, independently verified above), but
   `_yara_runner`/`_yara_rule_provider` were deliberately left unwired in
   production startup -- wiring scanning on by default, unverified against
   the real built container image, would itself violate CLAUDE.md §F.
   Flagged as the concrete follow-up for whoever completes E2/E3/E4's
   actual production activation (Dockerfile `COPY` fix + a real
   container-level PoC re-run).

Unit tests: `tests/unit/application/test_yara_rule_pack_service.py` (21
tests), `tests/unit/application/test_yara_rules.py`'s new
`TestSignedYaraRulePackProvider` (5 tests), and one new test in
`tests/unit/application/test_parsing_orchestration.py::TestExecuteParse`
proving the `yara_scan_org_var` bind/reset. See
`poc/yara_rulepack_lifecycle/README.md` for the full account.

### E5 · Memory-dump module (Volatility, §G) — L1+L2
**Objective.** A `ForensicParser` per §G wrapping real `volatility3` in its own
sandboxed runtime/queue, emitting `StructuredArtifact`s (`volatility.pstree`
etc.). Real target already in hand: the 512 MiB `memory.dmp` inside
`forensic2.E01`. Update `reviews/DFIR_Artifact_Landscape.md`.
**Depends on:** E1.

**STATUS (2026-08-02): DONE (pstree/psscan proven end-to-end; other plugins
and full HTTP pipeline are the documented follow-on).** `VolatilityModule`
(`src/external/parsers/volatility.py`) + `VolatilityLauncher`
(`src/external/sandbox/volatility_launcher.py`) + a real worker script
(`docker/volatility/kronos-volatility-worker.py`) mirror
`PlasoParser`/`FirecrackerLauncher`'s exact subprocess/JSON-io shape
(CLAUDE.md §G.3). Only `extract_artifacts()` is implemented — every plugin
wrapped so far (`windows.pstree`, `windows.psscan`) is fundamentally
non-timeline output; `parse()` is a documented no-op override (required
because `ForensicParser.parse()` is abstract, unlike `extract_artifacts()`).

Real, downloaded sample: the classic `cridex.vmem` (Windows XP,
Cridex/Feodo, 512 MiB uncompressed, sha256 documented in
`poc/volatility_memory_module/README.md`, never committed). Pinned
`volatility3==2.28.0` (re-confirmed current on PyPI before pinning).

**Real, reproduced finding (the open detection question this item was
scoped to resolve):** raw physical memory dumps have no verified magic
bytes — `cridex.vmem`'s own first 4 KiB carry no Microsoft crash-dump
(`PAGEDUMP`/`PAGEDU64`) or LiME magic, just raw kernel bytes with no header
at all. Extension-only detection
(`.vmem`/`.mem`/`.raw`/`.dmp`/`.lime`) is the honest answer, wired into both
`MagicByteValidator._MEMORY_DUMP_EXTENSIONS` and `VolatilityModule.supports()`.
`VolatilityModule` is registered **last** in `get_parser_registry()` (after
`PlasoParser`) so a real disk-image magic always wins the ambiguous
`.raw`/`.dmp` case first — verified for real that `cridex.vmem`'s own bytes
don't collide with any of `PlasoParser`'s fixed-offset magics.

**Real, reproduced finding (unplanned, discovered during verification):**
`windows.pstree`/`windows.pslist` (the kernel `PsActiveProcessHead`
linked-list walk) return a real, reproducible **zero-row** result against
`cridex.vmem` + `volatility3==2.28.0` — confirmed via `-vvv` (no exception,
just an empty walk), `--pid`/`--physical` variants, and `windows.info`
proving the kernel base/DTB/symbol table all resolve correctly. This is a
genuine tool/sample-era interaction (XP-era volatility3 support is known
shaky — see `poc/volatility_memory_module/README.md` for the GitHub-issue
search), not a bug in this repo's wrapping: proven by running the bare `vol`
CLI directly, zero KronOS code involved. `windows.psscan` (an independent
pool-tag scanner) recovers the real, full, well-documented 17-process census
from the same file. `kronos-volatility-worker.py` therefore always attempts
the configured primary plugin and automatically re-runs a configured
fallback plugin when the primary's own result is empty, reporting both;
`VolatilityModule` yields one `StructuredArtifact` per plugin that ran —
`kind="volatility.pstree"` (real, honestly empty for this sample) plus
`kind="volatility.psscan"` (real, 17 rows) when the fallback fires.

**Container/queue decision, made from real evidence, not assumed:**
`volatility3`'s base install is `pefile` + a ~1.4 MB wheel (verified via
`pip download`/wheel-metadata inspection) — light enough to add to
`docker/Dockerfile.plaso-worker`'s existing builder stage rather than
needing its own Dockerfile variant the way Plaso's much heavier dependency
set does. Built for real as `kronos-poc-volatility-worker:test`; verified
*inside* the built image (not assumed) that `vol --help` reports
`Volatility 3 Framework 2.28.0` and that
`/app/volatility-worker/kronos-volatility-worker.py` exists at the exact
path `VOLATILITY_WORKER_PATH` points to — explicitly checked to avoid
repeating roadmap E4's own left-over gap (that Dockerfile still never
`COPY`s `kronos-yarax-worker.py` in; still not fixed here, flagged again in
the Dockerfile's own comment). Also ran the real worker script *inside* the
built container against the real `cridex.vmem` (bind-mounted in) — same
pstree-empty/psscan-17-rows result as the host-venv run, proving the
container's own installed `vol` binary and copied worker script both work,
not just the Dockerfile syntax. No new Celery queue: `ParserType.HEAVY`
already shares `q.parse.plaso` across `ZipArchiveParser`/`TarArchiveParser`/
`PlasoParser` (a pre-existing, if confusingly-named, precedent) —
`VolatilityModule` reuses it rather than inventing a fourth heavy queue with
no other current member.

Unit tests: `tests/unit/test_volatility_launcher.py` (12 tests, mirrors
`test_yara_x_runner.py`'s fake-worker-script idiom; one real-sample test
gated on `KRONOS_CRIDEX_VMEM_PATH`, skip-not-fail when unset) and
`tests/unit/parsers/test_volatility.py` (20 tests: detection, kind-mapping,
artifact construction, the pstree->psscan fallback, graceful degradation on
`VolatilityScanError`, and the 8 MiB content-cap chunking path). Full real
run (bare CLI -> real sandboxed launcher -> real `VolatilityModule`) captured
in `poc/volatility_memory_module/output.txt`.

**Honest gaps, explicitly out of scope this pass (see PoC README's own
"Gaps" section):** the full HTTP upload → validate → parse → Postgres
pipeline was not driven end-to-end (stops at real, in-memory
`StructuredArtifact` construction); `.dmp`/`.lime` magic bytes were not
verified against real samples of those specific formats (only `.vmem` was
downloaded); timeline-shaped plugins (`timeliner`, `pslist` CreateTime,
`windows.netscan`) remain unwired; only `windows.pstree`/`windows.psscan`
were exercised (`malfind`/`filescan`/`dlllist`/etc. are natural follow-ons);
only a Windows XP sample was used (Linux/macOS memory samples are out of
scope per this item's own brief).

---

## M5 — Enrichment & correlation

### F1 · Enrichment pipeline (asset / identity / vulnerability context) — L2
**Objective.** Extensible enrichment applied at ingest (ABC + per-source
enrichers). Enrichment is **derived** — must not overwrite original event
fields; goes in a separate namespace so the raw record stays pristine.

**STATUS (2026-08-02): DONE.** `Enricher` ABC + `EnrichmentPipeline`
(`src/application/enrichment.py`) mirror this codebase's established
ABC+registry extensibility idiom (`FieldMapping`/`ECSFieldMappingRegistry`,
`StreamSourceNormalizer`/`StreamSourceNormalizerRegistry`). Two real design
decisions, both deliberate, not defaults:

1. **Derived data lives in `TimelineRecord.extra`, namespaced
   `"enrichment.<source_name>."`, not a new top-level domain field.**
   `extra` already exists precisely for this (every parser's own
   dotted-key convention) and `ECSNormalizer` already flattens it into the
   indexed document — a new field would touch the normalizer, the index
   template, and every construction site across six parsers for no real
   benefit over reusing the existing mechanism. `EnrichmentPipeline.enrich()`
   enforces the namespace contract itself: a key not prefixed with the
   calling enricher's own `source_name`, or one that would collide with an
   existing key, is logged and dropped, never silently applied.
2. **Enrichment runs once, at ingest, before a record becomes an
   immutable, indexed artifact** (wired into
   `ParsingOrchestrationService.execute_parse`, right after
   `_annotate_records`, before `TimelineIngestionService.ingest_records`)
   — not as a job that reaches back and edits already-indexed OpenSearch
   documents. This platform's own chain-of-custody principle (WORM
   evidence, the append-only audit log, immutable sealed batches) treats
   an indexed forensic record as never mutated after the fact; enrichment
   computed before indexing is no different in kind from any other
   derived field a parser or the ECS field-mapping registry (A2) already
   attaches. `EnrichmentPipeline.enrich()` is deliberately pure/stateless
   (record + org_id in, a new record out) specifically so a *future*
   scheduled re-enrichment pass can re-run it against original records
   without ever mutating them — proven for real (see PoC below), not
   built as a scheduled job this pass.

One real, concrete, working enricher: `AssetContextEnricher`
(`src/application/asset_enrichment.py`) + `Asset`/`AssetRepository`/
`PostgresAssetRepository` (`src/domain/asset.py`,
`src/adapter/repository/asset.py`, `postgres_asset.py`) — a real,
org-scoped, **mutable** asset inventory (deliberately *not* append-only
like this codebase's other Postgres-backed domain rows — an asset's
criticality/owner legitimately changes over time; it is not itself
forensic evidence). Looks up a `TimelineRecord.host_name` and attaches
`enrichment.asset.{asset_id,criticality,owner,environment}`.
Identity-via-Keycloak-admin-API and vulnerability-via-external-feed were
both explicitly out of scope for this pass (no existing Keycloak admin
REST client in this codebase to build on; an external feed is arguably
F2's own territory) — one real source proves the extensibility mechanism,
matching this session's own repeated precedent (E2/E3/D4 each shipped
exactly one real concrete instance too).

PoC: `poc/enrichment_pipeline/` — 19/19 checks against real Postgres:
(a) a real seeded asset enriches a matching record with every ORIGINAL
field individually verified byte-for-byte unchanged; (b) a non-matching
record gets back the exact same object, an honest no-op, never a
fabricated match; (c) real cross-org isolation; (d) updating the real
asset in Postgres and re-running enrichment against the *same* original
record object reflects the update while the original's own fields stay
identical — the concrete proof behind design decision 2 above; (e) the
same pipeline wired into a real `ParsingOrchestrationService` +
`TimelineIngestionService` call, confirming the enrichment fields land at
the correct nested `enrichment.asset.*` path in the actual indexed ECS
document.

This item's dispatched subagent died on a genuine session-wide spend
limit very early (still reading established patterns, before writing any
code) — real-state check found nothing written yet (clean git status, no
`poc/` dir), so the orchestrator implemented it directly rather than
losing time to a redispatch. One real bug was found and fixed while
writing the new orchestration-level unit test (not by the PoC, which
passed first try): a stray, uninitialized `count += 1` in the new
`_apply_enrichment()` wrapper generator (leftover from drafting against
the unrelated `_annotate_records` function) — caught immediately by the
real end-to-end test raising `UnboundLocalError`, not a silent issue.
Also fixed a real mypy finding in `PostgresAssetRepository.upsert()`
(chaining `.returning()` onto an `ON CONFLICT DO UPDATE` statement doesn't
type-check cleanly with this SQLAlchemy version) by switching to a
separate `SELECT` after the upsert, mirroring
`postgres_yara_rule_pack.py`'s own existing pattern for the identical
shape — verified for real that this correctly preserves the *original*
row's `asset_id` across an update (not the fresh one on the incoming
domain object), the honest, stable-identity behavior an asset-inventory
consumer needs.

Independently ran the full checklist: **1011 passed, 1 skipped** (988
baseline + 23 new), `mypy` at **29** (pre-existing baseline, zero new),
`ruff` at **26** (pre-existing baseline, zero new after the two fixes
above), `black` clean on every touched file.

**Explicitly flagged, not yet done:** only one enricher exists (asset
context) — identity and vulnerability enrichment are real, legitimate
future work, not this item's gate; no scheduled re-enrichment job exists
yet (the mechanism is proven re-runnable, not automatically triggered);
no HTTP route for managing the asset inventory (backend-only scope this
pass, mirrors E3/E4/E5's own precedent).

### F2 · Threat intelligence (STIX/TAXII, MISP, SA threat-intel) — L2
**Objective.** IOC ingestion and matching, using SA's own threat-intel feature
where it fits. Treat feed content as untrusted input.

**STATUS (2026-08-02): DONE (STIX 2.1, KronOS-native path).** First, real
finding, not a foregone conclusion: OpenSearch Security Analytics' native
threat-intel feature (source configs, IoC-feed monitors) does **not exist**
on either OpenSearch version this repo pins. Verified two ways:

1. A real `curl` against the live dev cluster
   (`docker-opensearch-1`, 2.11.1) for
   `_plugins/_security_analytics/threat_intel/sources` returned **HTTP
   400, "no handler found for uri"** -- OpenSearch's own signal that the
   REST action isn't registered at all, not a 404/empty result. A control
   call to a real, known-working SA endpoint on the SAME cluster
   (`detectors/_search`) returned a normal 200, ruling out "SA is just
   down".
2. Checked against the real `opensearch-project/security-analytics`
   GitHub history: threat-intel work was originally targeted at the 2.11
   line itself, then **reverted** before release (PR #717, "Revert Threat
   Intel Changes for 2.11", merged into the `2.11` branch 2023-11-08 --
   three weeks before 2.11.1 itself shipped). Real feature work (source
   CRUD, monitors, REST APIs) only resumes in the PR history starting
   May-June 2024; every backport found for later threat-intel fixes goes
   back only as far as 2.15. `docker-compose.test.yml`/
   `docker-compose.prod.yml`'s pinned 2.13.0 predates the feature too. See
   `poc/threat_intel_sa_native/` (README + real captured `output.txt`).

Design decision: build the KronOS-native fallback the roadmap's own
objective text anticipates ("where it fits") -- extend F1's `Enricher`/
`EnrichmentPipeline` (`src/application/enrichment.py`, unmodified) with a
second concrete enricher, `IOCMatchEnricher`
(`src/application/ioc_enrichment.py`). Mirrors `RulePack`/
`RulePackVersion`'s exact versioned-repository shape (append-only,
tenant-scoped): `IOCFeed`/`IOCFeedVersion`/`IOCIndicator`/`IOCMatch`
(`src/domain/ioc_feed.py`), `IOCFeedRepository` ABC + `InMemory*`
(`src/adapter/repository/ioc_feed.py`) + `PostgresIOCFeedRepository`
(`postgres_ioc_feed.py` -- adds one materialized, indexed
"current indicators" projection table alongside the append-only
`ioc_feed_versions` table specifically so a per-record match lookup at
ingest stays a cheap indexed query, not a JSON-blob scan). Ingestion is
`IOCFeedIngestionService.ingest_stix_bundle()`
(`src/application/ioc_feed_ingestion.py`), parsing via a hand-written,
regex-only extractor (`src/application/stix_ioc_parser.py`) -- never
`eval`/`exec` against feed content, real enforced caps on bundle size/
object count/pattern length, and unsupported/malformed indicator objects
are honestly skipped (logged) rather than failing the whole feed. Real
STIX 2.1 pattern shapes were confirmed against two official, trusted
sources (OASIS's own STIX 2.1 spec and the official
`oasis-open/cti-python-stix2` reference implementation's test suite), not
invented from memory. Matchable fields were surveyed from what today's six
parsers actually emit (`source.ip`/`destination.ip`, `url.domain`,
`kronos.sha256` -- the evidence file's own hash) rather than invented;
MISP/TAXII-poll ingestion are real, legitimate follow-ups, not built this
pass (same "one real source proves the mechanism" precedent as F1's own
asset-only enricher). `enrichment.ioc.*` fields added to
`src/adapter/opensearch/index_template.json`, mirroring F1's
`enrichment.asset.*`.

PoC: `poc/threat_intel_stix_ingest/` -- **25/25 checks passed** against the
real, already-running dev Postgres AND the real live OpenSearch 2.11.1
cluster (not `InMemoryOpenSearchClient` -- specifically to prove the NEW
`enrichment.ioc.*` mapping is actually accepted by the real pinned
cluster, via a real `ensure_index_template()` PUT +
`indices.get_mapping()` read-back). Covers: defensive parsing of a
7-object real-shaped STIX bundle (3 real matchable indicators + an
MD5-only indicator + a real compound-`AND` pattern from the OASIS spec +
a deliberately malformed non-string `pattern` field, all three honestly
skipped, never crashing the other 3); a structurally invalid bundle
raising `ValidationError`; real append-only versioning against real
Postgres (re-ingest creates version 2, version 1 never lost); real
`match_indicator()` queries (case-insensitive, cross-org isolated, honest
`None` on no match); the real `IOCMatchEnricher` through the real
`EnrichmentPipeline` (IP match, file-hash match via the evidence's own
`kronos.sha256`, most-specific-first priority when both would match, real
no-op on no match); and the real OpenSearch round-trip (bulk-indexed
document's `enrichment.ioc.matched`/`confidence` come back with the exact
real mapping types the updated `index_template.json` declares).

Added a real, true end-to-end unit test mirroring F1's own
(`test_ioc_match_enricher_applies_real_derived_fields_before_indexing` in
`tests/unit/application/test_parsing_orchestration.py`) through
`ParsingOrchestrationService` -> `EnrichmentPipeline` ->
`TimelineIngestionService` -> `InMemoryOpenSearchClient`, plus full unit
coverage for the parser (`test_stix_ioc_parser.py`), ingestion service
(`test_ioc_feed_ingestion.py`), enricher (`test_ioc_enrichment.py`), and
`InMemoryIOCFeedRepository` (`test_ioc_feed_repository.py`).

Wired into `src/external/dependencies.py` (new `_ioc_feed_repository`
global, `get_ioc_feed_repository()`, added to both
`configure_dependencies()` **and** `reset_dependencies()` -- this exact
omission from `reset_dependencies()` was a real mistake made once already
this session on E3 and had to be fixed there; checked for it explicitly
here) and `src/external/startup.py` (`PostgresIOCFeedRepository` +
`create_tables()`, `IOCMatchEnricher` added alongside
`AssetContextEnricher` in the real `EnrichmentPipeline`).

Independently ran the full checklist: **1063 passed, 1 skipped** (988 F1
baseline + ~75 new across this and other work landed since), coverage
**86.92%** (was 86.65%, no regression -- `pyproject.toml`'s
`--cov-fail-under=80` gate still passes with real margin), `mypy` at
**29** (identical pre-existing baseline, zero new -- checked line-by-line
that none of the 29 errors are in any file this pass touched), `ruff` and
`black` clean on every touched file.

**Explicitly flagged, not yet done:** only STIX 2.1 bundle ingestion is
wired -- MISP-JSON export and live TAXII 2.1 polling (a scheduled job with
its own URL/credentials/interval, meaningfully more work: discovery,
collections, auth) are real, legitimate follow-ups, not this item's gate.
No HTTP route for managing IOC feeds (backend-only scope this pass,
mirrors F1/E3/E4/E5's own precedent). `IOCMatchEnricher` reports only the
single MOST-SPECIFIC match per record when multiple fields would match
(file hash > IP > domain) -- surfacing every simultaneous match is
legitimate future scope, not a defect. Compound STIX patterns (`AND`/`OR`/
`FOLLOWEDBY`) and non-sha256 file hashes (MD5/SHA-1) are honestly
unsupported, not silently mismapped. Once OpenSearch is upgraded to 2.15+
in some future pass, revisiting SA's now-real native threat-intel feature
against this KronOS-native path is the natural next evaluation point --
not a foregone "replace it" conclusion.

### F3 · Correlation (SA correlation rules first, then entity graph) — L2/L3
**Objective.** Evaluate SA's native correlation engine **before** building
anything; only then consider an entity graph for attack-chain assembly.

**STATUS (2026-08-02): DONE — native engine evaluated real, GO, entity graph
NOT built.** Confirmed SA's correlation engine genuinely exists and is live
on the pinned OpenSearch 2.11.1 dev cluster (`POST .../correlation/rules`
route registered, distinct from F2's threat-intel finding where the route
didn't exist at all). Read the real Java source for the pinned `2.11` branch
(`opensearch-project/security-analytics` commit
`0092714047145972f990931e0d06595caa019185`) rather than trusting "latest"
docs, confirming the exact request/response schema
(`{"name": ..., "correlate": [{"index", "query", "category"}, ...]}`).

**Real PoC** (`poc/security_analytics_correlation/`, 20/20 checks passed):
created two real detectors over two real test indices using two Sigma rules
already proven to fire against real KronOS data in C1 (`db809f10-...`
windows/T1006, `1fc0809e-...` network/T1021.001), created a real correlation
rule joining `category: windows` with `category: network`, and got a real
cross-log-type match back from `GET .../findings/correlate`: a real network
finding returned with `score: 1.0`, tagged with this run's own real
correlation rule id. Two real, non-obvious operational facts found and
designed around: (1) the correlation engine only correlates findings created
**after** the rule exists — no retroactive re-scan of pre-existing findings
(rule must be provisioned first); (2) unlike detectors, a real PUT-update
against a correlation rule works cleanly (`_version` 1→2, no error) — no
delete-and-recreate workaround needed here.

**Multi-tenant scoping answer:** a correlation rule has **no dedicated
tenant field** (confirmed from `CorrelationRule.java`/`CorrelationQuery.java`
directly, and empirically — a rule with `kronos-poc-tenanta-*`/
`kronos-poc-tenantb-*` index strings was accepted with **201**, no
validation). `index` is exactly as free-form as a Detector's own `indices`
list, so C2's existing per-org convention extends cleanly: KronOS computes
`kronos-{org_alias}-*` for every category leg itself, never from rule
content. Also confirmed the real `GET .../correlations` list endpoint is
**cluster-wide with no org/tenant filter at all** (only start/end
timestamps) — a genuinely more permissive gap than detectors/findings
(which are at least scoped by `monitor_name`), so **all** tenant isolation
for correlation data is enforced application-side by
`CorrelationSyncService`, which discards any pair unless BOTH finding ids
already resolve to a Detection this exact org previously synced.

**Design decision: GO on the native engine, entity graph not built.** No
real defect was found (the two facts above are operational constraints to
design around, not the kind of concrete bug that forced C2/A3's own
workarounds) and the native engine already produces real cross-log-type
matches, so building a parallel bespoke correlator now would be exactly the
premature-shortcut pattern CLAUDE.md SS G.3 warns against. Revisit only if a
future need requires dynamic field-value joins ("same IP across any two log
types") the engine's declarative-query-pair model can't express.

**Built:** `src/domain/detection.py` (`DetectionCorrelation`, a new,
immutable sibling fact type — not a mutation of `Detection`, which stays
frozen-once-created); `src/adapter/repository/detection_correlation.py` +
`postgres_detection_correlation.py` (ABC/in-memory/Postgres, mirroring
`DetectionRepository` exactly); `src/adapter/opensearch/correlation_client.py`
(read-only `CorrelationClient`/`SecurityAnalyticsCorrelationClient`, mirrors
`FindingsClient`); `src/adapter/opensearch/correlation_rule_provisioner.py`
(`CorrelationRuleProvisioner`/`SecurityAnalyticsCorrelationRuleProvisioner`,
check-then-create-or-PUT-update, mirrors C2/C3's provisioner shape but with
the simpler update-in-place strategy the real PUT test justified);
`src/application/correlation_sync.py` (`CorrelationSyncService`, a new sync
path reusing `DetectionRepository`/`AuditLogService` rather than duplicating
their tenant-scoping/audit logic, exactly as this item's brief required);
two new `AuditEventType` entries (`DETECTION_CORRELATED`,
`DETECTION_CORRELATION_SYNC_FAILED`); DI wiring in
`src/external/dependencies.py` (checked `reset_dependencies()` explicitly
for the exact omission bug hit once already on E3/F2) and
`src/external/startup.py`.

**Not built this pass (explicitly flagged, not silently dropped):** no
curated set of production scenario rules (which category/query pairs are
worth shipping is real, separate product-definition work — this PoC used
one synthetic windows/network pair to prove the mechanism); no HTTP route
exposing correlation sync or the provisioner (backend-only scope, mirrors
F2/F1's own precedent — `get_correlation_sync_service()` is DI-wired and
ready for a future route/beat task, exactly like `get_detection_sync_service()`
already sits unrouted today); no >2-category rule chains tried (a natural
extrapolation of the same `correlate` array, not verified this pass);
`docker-compose.test.yml`/`docker-compose.prod.yml` pin OpenSearch 2.13.0,
not re-verified against the 2.11.1 dev cluster this PoC actually ran
against.

**Tests:** real unit coverage for the domain model, both repositories, both
new adapters (mocked httpx, mirroring `test_detector_provisioner.py`'s own
style), and a true end-to-end `CorrelationSyncService` suite exercising the
real `InMemoryDetectionRepository`/`InMemoryDetectionCorrelationRepository`/
`AuditLogService` together (only the OpenSearch client is faked) — including
the tenant-isolation gate itself (a pair is dropped when either finding
belongs to another org) and idempotency under the real API's own
unordered-pair reporting. Full suite: **1095 passed, 1 skipped** (was 1063
after F2, 32 new this pass), coverage **87.08%** (was 86.92%, no regression
— `--cov-fail-under=80` gate holds with margin), `mypy` **29** (identical
pre-existing baseline, zero new — verified line-by-line none of the 29 are
in any file this pass touched), `ruff`/`black` clean on every new/touched
file (verified via `git show HEAD:<file>` diffing against the one
pre-existing baseline line this pass's own edit happened to sit next to in
`tests/unit/domain/test_detection.py`).

### F4 · Risk scoring + alert prioritization — L2
**Objective.** Deterministic, explainable scoring combining asset criticality,
identity privilege, IOC confidence, rule severity.

**STATUS (2026-08-02): DONE. Milestone M5 complete.** Confirmed the real
Sigma severity vocabulary against the live 2.11.1 cluster's own 2077
pre-packaged rules (`GET .../rules/_search?pre_packaged=true`): exactly
`informational` (23), `low` (205), `medium` (720), `high` (972), `critical`
(157) -- `src/domain/detection.py`'s new `SIGMA_SEVERITY_LEVELS` matches
this real set exactly, not a guessed enum. A real finding's `tags` array
was already observed (F3's own captured PoC output) mixing a bare severity
token in with ATT&CK/category tags; `highest_rule_severity()` extracts it
with the same "filter one tag family" idiom `Detection.attack_tags` already
established.

IOC confidence (F2) and asset criticality (F1) live on the INDEXED
TIMELINE DOCUMENT, not on `Detection` -- there was no read path back to
them. Added `AbstractTimelineIndex.get_documents_by_id()` (real OpenSearch
`_mget`, verified against the live cluster in
`poc/detection_risk_scoring/`: confirmed the real `docs[].found` response
shape, and that a missing id is honestly omitted, never a fabricated
placeholder) plus the obvious `InMemoryOpenSearchClient` equivalent.
`DetectionSyncService._resolve_risk_inputs()` fetches a finding's own
`matched_document_ids` from its own `source_index` and combines multiple
matched documents by taking the MAX normalized value per factor ("a
finding is exactly as risky as its riskiest matched document").

**Design decision: score computed ONCE at sync time, frozen onto
`Detection`, never recomputed in place.** This mirrors `Detection`'s
existing "frozen snapshot of what was known when it was synced" contract
(`case_id`/`rule_matches` are captured the same way) -- a Detection stays
reproducible from the real inputs recorded alongside it
(`Detection.risk_factors`), even though the underlying asset inventory
(F1) is itself legitimately mutable and could drift afterward. A future
re-scoring pass is real, deliberate follow-up scope, not silently implied.
`DetectionRiskScorer` (`src/application/risk_scoring.py`) is a small, pure,
stateless class (mirrors `RuleCostGate`'s shape) with hardcoded weight
constants -- deliberately code, not `Settings` fields, since the formula
that produced a frozen score must be reproducible from the codebase at
that commit, not an ops-editable env var that could silently drift
per-deployment.

**Identity privilege is honestly always absent.** F1 never built an
identity-context enricher; this scorer accepts an `identity_privilege`
parameter for a future real signal but no caller in this codebase has one
yet. `RiskFactor(name="identity_privilege", normalized_value=None, ...)`
is always present in the breakdown with an explicit "why absent" detail
string -- never a fabricated neutral default, and never silently dropped
from the explanation. Every other absent input (unscoreable rule tag,
unresolved matched document, unrecognized tenant-free-text criticality
value) degrades the same honest way: omitted from both the weighted sum
and its own weight denominator, never defaulted to 0.

PoC: `poc/detection_risk_scoring/` -- **17/17 checks passed** against the
real, live OpenSearch 2.11.1 cluster (real Sigma vocabulary query, real
`_mget` round-trip including a real `indices.refresh()` timing fact, and a
real end-to-end sync through the unmodified `DetectionSyncService`
producing four real, reproducible scores: 84.41 for high-severity +
critical-asset + ioc-85, 56.82 for the same rule but only a low-criticality
asset match, 75.0 falling back honestly to rule-severity-only when the
matched document id never resolves, and `None` when no factor has any
usable value at all).

**Real gap found and fixed by the orchestrator during independent
verification (CLAUDE.md SS F, "plausible code without a captured real run
is an automatic fail"):** the dispatched subagent's own PoC used
`InMemoryDetectionRepository`, never exercising `PostgresDetectionRepository`
against the real live dev Postgres. `sa.MetaData.create_all(checkfirst=True)`
only creates missing TABLES, never adds columns to an existing one (the
same documented caveat `postgres_evidence.py` already carries for its own
additive legal-hold/WORM columns) -- so the real, already-existing
`detections` table on this host's dev Postgres was missing `risk_score`/
`risk_factors` entirely; any real `PostgresDetectionRepository.save()`
call after this landed would have failed loudly with a real "column does
not exist" error. Fixed two ways: (1) ran the real, one-time `ALTER TABLE
detections ADD COLUMN risk_score double precision; ALTER TABLE detections
ADD COLUMN risk_factors json NOT NULL DEFAULT '[]';` against the live
`docker-postgres-1` container and confirmed via `\d detections` that both
columns now exist; (2) added the same doc comment `postgres_evidence.py`
already uses for this exact caveat, so a future fresh deployment (where
`create_tables()` creates the table from scratch, including these columns)
and an existing one (needing this same manual `ALTER TABLE`) are both
documented. Then ran a real, independent script that saves and re-fetches
a `Detection` with real `risk_score=84.41`/`risk_factors` through
`PostgresDetectionRepository` against the now-patched live table --
confirmed the exact round-trip, not just an in-memory one.

Extended the existing Detection API DTO (`src/external/routes/detections.py`,
C6) with `riskScore`/`riskFactors` rather than a parallel endpoint.

Independently re-ran the full checklist: **1135 passed, 1 skipped**,
coverage **87.33%** (gate 80%, no regression), mypy **29** (identical
pre-existing baseline, zero new -- confirmed none in any file this pass
touched), ruff/black clean on every touched file (no lint gaps this time,
unlike the prior F3 cycle).

**This completes Milestone M5** (F1 enrichment, F2 threat intel, F3
correlation, F4 risk scoring). Milestone M6 (G1-G3, deterministic baseline
scoring / AD-RCF / explainability gate) is next.

---

## M6 — Analytics

### G1 · Deterministic rarity / frequency baseline scoring — L1
**Objective.** Classic DFIR least-frequency-of-occurrence via plain OpenSearch
aggregations (`terms`, `cardinality`, first-seen/last-seen on `@timestamp`). No
ML. Fully replayable. **Ship before any ML** — it delivers most of the value
attributed to UEBA and gives a labelled baseline to measure models against.

### G2 · AD/RCF per-org detectors for triage prioritization — L2
**Objective.** Use the in-cluster Anomaly Detection plugin per-org (scoped to
`kronos-{org}-*`, which also contains the behavioural-profile leak).
**Hard constraint:** RCF is an **online model that continuously updates its own
state**, so a score depends on ingestion history, not just the scored document —
it is **not reproducible months later and must never be the evidentiary basis of
a finding.** Triage prioritization and hunting leads only; must be labelled as
such in the API and UI. **Depends on:** G1.

### G3 · GATE · Explainability + replayability harness — L2
**Objective.** Prove that every court-facing verdict reproduces from pinned
version + stored input, and that non-reproducible signals (G2) are structurally
prevented from being presented as evidentiary. **Depends on:** G1, G2, C4.

---

## M7 — Response / SOAR

### H1 · Playbook engine — L1
**Objective.** OOP, pluggable: `PlaybookAction(ABC)` + registry, declarative
playbook definitions as data. Deterministic and fully audited — every step,
input, output and decision recorded. New action = registration, not an edit.

### H2 · GATE · Action adapters + approval gates — L2
**Objective.** Containment adapters (isolate host, block IP, revoke session)
behind an ABC. **Gate:** prove no destructive action can execute without either
an explicit policy authorization or human approval, and that every attempt is
audited whether or not it succeeded. Ties to existing step-up auth.
**Depends on:** H1, C4.

### H3 · Automated evidence collection on detection — L3
**Objective.** A detection triggers forensically-sound collection (memory, disk,
logs) that enters the *existing* evidence pipeline with full custody — the
strongest synthesis of the SOC and forensic halves of the platform.
**Depends on:** H2, E5.

### H4 · Case / ticket integration — L2

---

## M8 — Validation, ops, parity, global E2E

### I1 · Detection validation harness — L3
**Objective.** Atomic Red Team / Caldera-driven continuous validation that rules
still fire; regression-tested in CI.

### I2 · Metrics & KPIs — L2
MTTD, MTTR, FP rate, rule coverage, ingest lag, sealer lag, analyst workload.

### I3 · Prod / Helm parity debt — L2
**Known-open, already documented:** Helm has **no `CLAMD_HOST` wiring at all**;
`MAX_UPLOAD_BYTES`/`CLAMD_CONF_*` reconciliation was scoped to
`docker-compose.dev.yml` only; SA/AD/ISM provisioning must be added for prod and
Helm. Also: the pre-existing ~300 s `test_sse_routes.py` slow test.

### I4 · GATE · GLOBAL L4 end-to-end — L4
**Objective.** Realistic multi-tenant adversary scenario spanning continuous
ingest + evidence upload + detection + correlation + triage + response +
custody, with **explicit cross-tenant isolation assertions** under concurrent
load.

### I5 · Performance & scale validation — L4
Against §B.6 baselines and measured ingest rates.

---

## 4. Agent brief template

Every agent starts **cold**. Briefs must be self-contained. Per §F.4, the
orchestrator pins versions *before* dispatch — agents never guess a version.

```
ROLE: You own <ID> · <title> for KronOS.
Repo: /home/reca/Claude/Kronos/KronOS_template   Branch: <branch>

READ FIRST: CLAUDE.md §A (architecture), §B (standards), §F (verification-first),
§G if you touch parsers/modules. Then docs/NEXTGEN_SOC_ROADMAP.md §0 (verified
facts — trust these, don't re-derive), §1 (invariants), §2 (proof layers).

OBJECTIVE (what, and why it matters): <...>

YOU DESIGN THE SOLUTION. This brief states the goal, the invariants and the
proof bar — not the implementation. Assess the objective, research the real
current documentation for the pinned versions, choose the most robust and
secure approach, and justify the choice. If you conclude the objective is
wrong or a better path exists, say so with evidence instead of complying.

PINNED VERSIONS: <...>   (verified by orchestrator; re-verify if suspect)

HARD INVARIANTS: roadmap §1 items <n,n,n> apply. Specifically: <the 2-3 that
bite hardest here>.

EXTENSIBILITY BAR: this will be extended repeatedly. Deliver ABC + concrete
impl + DI registration. Adding the next <thing> must need ZERO edits to
existing classes. No if/elif dispatch. Max ~200 lines/class.

PROOF BAR: layer <L1|L2|L3|L4>, at poc/<dir>/. Real dependency, pinned
version, captured output committed (README.md + output.txt). Plausible code
with no captured real run is an AUTOMATIC FAIL. Paste the actual captured
output in your report — never a description of expected output.

DELIVERABLES: 1) poc/<dir>/ with README.md + runner + output.txt
2) src/ implementation (only after the PoC proves the approach)
3) tests (unit + integration per §B.5) 4) full unit suite green, no regressions

REPORT BACK: what you designed and why; the actual captured output; anything
you found broken that was NOT in scope (do not fix silently — report it);
what you did NOT verify and why.

DO NOT: commit or push. Do not touch containers you didn't create. Do not
modify files outside your scope — report conflicts instead.
```

If this is a **redispatch** of a previously-interrupted task (check the
task's `dispatch_log` metadata per §6), prepend a real, evidence-based
**PRIOR PROGRESS** section per §6.3 — never resend the original brief
verbatim as if nothing happened.

---

## 5. Execution policy

- **Sequence anything sharing a file surface**; parallelize only disjoint
  surfaces. PoC-only agents (`poc/**`) are always safe to parallelize against
  `src/`-touching agents.
- **Gates are blocking.** A3, C1, D3, G3, H2, I4 must be reported and accepted
  before dependents start.
- **Orchestrator holds the dev stack.** Agents must not `down -v` the shared
  stack; container restarts are coordinated.
- **Commit/push authorization (2026-07-29, explicit, standing for this
  effort only):** the project owner authorized auto-committing verified
  work on `feat/nextgen-soc-cert-platform` as the autonomous orchestration
  progresses, specifically because this run may span weeks unattended and
  leaving it all uncommitted risks real data loss. Scope: commit (and push
  to the already-tracked remote branch) only work that is actually real-PoC
  verified per §2/§F — never commit a subagent's unverified claim. Never
  force-push. Never touch `main` or any branch but this one. Never rewrite
  history (no `commit --amend` beyond the immediately-preceding commit in
  the same turn, no `rebase`). This authorization does **not** extend to
  any other branch or repo action (PR creation, merges, deletes) — those
  remain a human call. Subagents themselves still must not commit (per
  their brief template in §4) — only the orchestrator commits, after
  reviewing what a subagent actually did.
- **Model policy (orchestrator directive, supersedes plain §F.4 guidance):**
  the orchestrator runs as Sonnet 5 at high effort; subagents run **cheaper**
  — Sonnet 5 at low/medium effort for well-scoped single-pair work with known
  versions, Haiku at medium effort for small/mechanical tasks (test updates,
  boilerplate registrations, log/doc bookkeeping). Do not dispatch subagents
  at Opus or high effort even for gates (A3, D3, F3, G3) — those get Sonnet
  with a more careful, explicit brief instead, per the template in §4.
- **Known operational friction: the dev stack's step-ca leaf cert has a 24h
  TTL and does not auto-renew.** Any agent whose PoC needs real login via
  `kronos.local` (most L2/L3 work) will hit
  `CERTIFICATE_VERIFY_FAILED: certificate has expired` once a day. Fix:
  `docker compose -f docker/docker-compose.dev.yml up -d tls-init && docker
  restart docker-nginx-1`, then retry. Not a code bug — a real, recurring
  dev-environment fact worth each agent knowing up front rather than
  rediscovering.
- **Continuation mechanism (2026-07-29):** autonomous continuation between
  the project owner's own messages uses the harness's native `CronCreate`
  (recurring prompt fired directly into this same chat session — the
  project owner explicitly wants status visible here, not in a separate
  cron-invoked CLI session's log file). `CronCreate` jobs are session-only
  and auto-expire after 7 days — if this orchestration is still running
  when a job is nearing that limit, re-arm it with a fresh `CronCreate`
  call for another cycle rather than letting it lapse silently. A
  secondary, silent OS-crontab-based backstop also existed
  (`scripts/dev_autoresume/`) purely for the case the whole session process
  itself dies (not just a subagent hitting a spend limit) — it proved
  itself once this session (see its own README) — but its activity is not
  chat-visible by design/necessity. **Stopped (2026-07-29) via its own
  `stop.sh`** once `CronCreate` proved reliable across many consecutive
  wake-ups: running both concurrently caused the real git-index race
  documented just below, and `CronCreate` alone is sufficient while this
  session stays alive. Re-run `scripts/dev_autoresume/install.sh` only if
  `CronCreate` itself stops firing (session death) and the project owner
  needs unattended continuation restored.
- **Real concurrency hazard observed (2026-07-29), not hypothetical:** the
  crontab backstop's `claude -p -c` and the interactive/CronCreate-fired
  session both operate on the exact same git working directory (not
  separate worktrees). Both processes running at once briefly raced on the
  shared `.git/index`: one process's staged `git add` was silently undone
  by the other process's own `git add`/`status` calls, until the other
  process ran `git commit` (which resolved it -- the commit landed with
  correct content, nothing was actually lost, but the staging area was
  momentarily unpredictable for the losing side). **Rule going forward:**
  if another `claude -p`/backstop process is alive
  (`ps aux | grep 'claude -p'`) and has files staged/modified that you
  didn't touch, do NOT run your own `git add`/`git reset`/`git commit`
  until it finishes -- let it complete and commit its own work first. Pick
  up a **different, unblocked** item on a disjoint file surface instead of
  idly polling. If this becomes a recurring problem, the real fix is
  running the backstop in a separate `git worktree` rather than sharing the
  interactive session's working directory -- not yet done, flagged here.

---

## 6. Pause/resume protocol for spend-limit interruptions

**Problem this section fixes:** the `Agent` tool has no native pause/resume.
A dispatched subagent either completes or dies; there is no built-in "retry
this exact task when the limit resets." Observed repeatedly this session:
subagent dispatch fails immediately with a spend-limit error in bursts, then
recovers, with no advance warning either way. Without a formal protocol,
each recovery either loses the subagent's real partial progress (redoing
work, wasting budget) or silently duplicates it (e.g. creating a second
detector with a different name for work already done). Both already nearly
happened this session before being caught by manual inspection — this
section makes that inspection mandatory and structured instead of ad hoc.

**The model: pause = leave real, inspectable state behind; resume = read
that state before acting, never trust task status alone.**

### 6.1 The task metadata ledger (mandatory, every task)

Before dispatching or resuming work on task N, and again immediately after
any dispatch attempt (success, failure, or spend-limit death), update that
task's `metadata` via `TaskUpdate` with an appended entry under
`dispatch_log` (a list; append, don't overwrite):

```json
{
  "dispatch_log": [
    {"ts": "2026-07-30T05:12:00Z", "action": "dispatch", "model": "sonnet",
     "outcome": "spend_limit", "note": "died before any file/artifact created"},
    {"ts": "2026-07-30T07:14:00Z", "action": "verify_state", "outcome": "clean",
     "note": "git status clean, no poc dir, no live detectors named kronos-poc-*"},
    {"ts": "2026-07-30T07:14:30Z", "action": "dispatch", "model": "sonnet",
     "outcome": "success", "note": "committed as <hash>"}
  ]
}
```

This is durable (the Task store has persisted across this entire multi-day
session, including a context-compaction event) and gives the *next* actor —
whether that's you later, a fresh subagent, or a cold-started orchestrator
turn — a structured answer to "what already happened here" without
re-deriving it from scratch or trusting a stale `in_progress` label.

### 6.2 Mandatory real-state verification before ANY action on an in-flight task

Never act on a task's `status`/`owner` fields alone. Before dispatching,
resuming, or redispatching, **always** check real, ground-truth state first,
in this order, and record what you found in `dispatch_log` (per 6.1):

1. `git log --oneline -10 -- <the files this task would touch>` — was it
   already committed (possibly by a different process — this happened for
   real with B2, see §5's concurrency note)?
2. `git status --short` and `ls poc/<expected-dir>/` — is there real,
   uncommitted progress sitting in the working tree?
3. Where applicable, a live check against the real dependency (e.g. "does a
   detector/index/role with this exact name already exist?", the same way
   B2's PoC caught that A1's template fix existed in the file but had never
   actually reached the live cluster). **A file existing is not proof a
   *live system* reflects it — check both when the task involves external
   state.**

Only after this produces a real, evidenced picture should you decide: finish
it yourself, redispatch with a delta-aware brief (6.3), or start clean.

### 6.3 Delta-aware resume briefs (redispatch, not restart)

A redispatch is **never** the original static brief re-sent verbatim. Before
redispatching, prepend a **PRIOR PROGRESS** section built from 6.2's real
findings, e.g.:

```
PRIOR PROGRESS (verified by orchestrator 2026-07-30T07:14Z, do not redo):
- A prior attempt already created 3 real detectors
  (kronos-poc-windows-detector, -cloudtrail-detector, -network-detector)
  and captured real findings (see poc/security_analytics_field_mappings/
  if it exists, or the task's dispatch_log). Confirmed via
  `_plugins/_security_analytics/detectors/_search` that [these still exist
  / these were already cleaned up].
- Confirmed via `git log` that [nothing/partial work] has been committed.
YOUR JOB: pick up exactly from here — [specific remaining scope]. Do not
recreate resources that already exist; if unsure whether something exists,
check first (idempotent-by-construction is already required per §1.1, this
is the same principle applied to your own resumption).
```

If 6.2 found a clean slate (nothing real happened), say so explicitly
instead ("PRIOR ATTEMPT(S): N, all died before producing any artifact —
proceed as a fresh dispatch") so the agent doesn't waste time hunting for
progress that doesn't exist.

### 6.4 The pause/resume cadence itself

- **Pause is implicit and free**: a spend-limited dispatch fails fast (no
  meaningful budget burned per attempt). No special "pause" action is
  needed beyond recording the failure (6.1) and not retrying dispatch
  again *this same cycle* (existing §5/cron-prompt rule: one probe attempt
  per cycle, fall back to direct work on failure rather than burning
  multiple attempts in a row).
- **Resume is driven by `CronCreate`'s existing schedule** (§5) — no
  separate resume-specific timer is needed. Every firing already re-checks
  `TaskList`; per 6.2, it must now also re-verify ground truth for any
  `in_progress` task before deciding to redispatch, finish directly, or
  wait another cycle.
- **No duplication, structurally**: every dispatched brief already requires
  idempotent-by-construction operations (§1.1's extensibility bar plus each
  item's own idempotency requirements — e.g. C2's "creating a case twice
  must not create duplicate detectors"). 6.2/6.3 add a second layer on top
  (don't even attempt the redundant call if it's already known to be done),
  but idempotency at the operation level remains the hard backstop even if
  a resume brief's PRIOR PROGRESS section is incomplete or wrong.
- **No loss, structurally**: because 6.2 is mandatory before treating
  anything as "not done," real partial progress (uncommitted files, live
  cluster resources) is never silently abandoned — it either gets
  committed (if verified correct) or explicitly folded into the next
  brief's scope.
