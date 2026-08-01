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

### D6 · L3 chain: collector → stream → seal → index → detect
**Depends on:** D2, D3, D4, C4.

---

## M4 — Artifact detection

### E1 · Container unwrapping gap (tar-in-image) — L1
**Objective.** Real, reproduced gap from the `forensic2.E01` analysis: the image
was a **tar archive containing `image.dd` + `memory.dmp`**, so dfVFS found no
partition table and Plaso extracted zero events. No recursive unwrapping exists
for tar-inside-disk-image. Follow the `ZipArchiveParser` recursion pattern; do
not invent a parallel mechanism. **Blocks:** E3, E5 for real-world images.

### E2 · YARA-X sandboxed runner — L1
**Objective.** YARA-X (Rust) over libyara/`yara-python` — the latter compiles
untrusted rule text **in-process** and libyara has a CVE history; inside an API
worker that is one memory-safety bug from RCE. Subprocess, container-sandboxed
via `FirecrackerLauncher` per §G.3. Never shell out from inside a parser class.

### E3 · YARA scanning in the recursion path → `StructuredArtifact` — L2
**Objective.** Scan **forensic artifacts**, not just the top-level blob. Hook
where `ZipArchiveParser` / `PlasoParser` already surface extracted files with
`source_path` + `container_sha256`. A match must be reportable as *"rule X at
`/Windows/Temp/x.exe` inside evidence.zip (container `4e3cf3…`)"* — that is an
admissible statement; *"matched somewhere in a 250 MB blob"* is not. Emit
`StructuredArtifact(kind="yara.match")` with matched-string offsets so an
examiner can independently verify. **Depends on:** E1, E2.

### E4 · Ruleset lifecycle (signed, versioned) — L1
**Objective.** Same trust model as C3, applied to YARA rulesets.

### E5 · Memory-dump module (Volatility, §G) — L1+L2
**Objective.** A `ForensicParser` per §G wrapping real `volatility3` in its own
sandboxed runtime/queue, emitting `StructuredArtifact`s (`volatility.pstree`
etc.). Real target already in hand: the 512 MiB `memory.dmp` inside
`forensic2.E01`. Update `reviews/DFIR_Artifact_Landscape.md`.
**Depends on:** E1.

---

## M5 — Enrichment & correlation

### F1 · Enrichment pipeline (asset / identity / vulnerability context) — L2
**Objective.** Extensible enrichment applied at ingest (ABC + per-source
enrichers). Enrichment is **derived** — must not overwrite original event
fields; goes in a separate namespace so the raw record stays pristine.

### F2 · Threat intelligence (STIX/TAXII, MISP, SA threat-intel) — L2
**Objective.** IOC ingestion and matching, using SA's own threat-intel feature
where it fits. Treat feed content as untrusted input.

### F3 · Correlation (SA correlation rules first, then entity graph) — L2/L3
**Objective.** Evaluate SA's native correlation engine **before** building
anything; only then consider an entity graph for attack-chain assembly.

### F4 · Risk scoring + alert prioritization — L2
**Objective.** Deterministic, explainable scoring combining asset criticality,
identity privilege, IOC confidence, rule severity.

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
