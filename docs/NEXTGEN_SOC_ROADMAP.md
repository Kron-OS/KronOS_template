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

---

## M2 — Detection engine (rules)

### C1 · Security Analytics field mappings per log type — L2
**Objective.** Map KronOS indices onto SA log types (`windows`, `linux`,
`cloudtrail`, `network`, `apache_access`) via
`_plugins/_security_analytics/mappings`, then **measure** how many of the 2,077
rules actually fire against real parsed evidence. **Gate:** report real
fired-rule counts per log type; a mapping that fires ~0 rules is a failure, not
a milestone. **Depends on:** A1, A2, A3.

### C2 · Per-org detector provisioning service — L2
**Objective.** Detectors are cluster-level; provisioning must be per-org and
automatic, scoped to that org's index patterns — following the established
pattern of `ensure_generic_tenant_role` / `DashboardsIndexPatternProvisioner`.
Idempotent; new org needs zero manual steps. **Depends on:** C1.

### C3 · Rule-pack lifecycle: versioning, signing, custom CRUD, cost gate — L1+L2
**Objective.** Rules are untrusted input. Two real risks: a rule compiling to a
catastrophically expensive query (leading-wildcard × regex over a year) is a
trivial DoS; and any raw-DSL passthrough path would bypass DLS entirely. Deliver
versioned rule packs, Cosign verification for third-party packs (reuse
`reviews/Extensibility_Architecture_Proposal.md` §4 unchanged), custom-rule CRUD,
and a pre-execution cost gate. **Depends on:** C1.

### C4 · `Detection` entity + triage FSM + audited finding sync — L2
**Objective.** SA findings are mutable plugin state outside the Postgres hash
chain. Mirror them into an immutable, audited `Detection` entity with its own
triage FSM (`NEW → INVESTIGATING → TRUE_POSITIVE | FALSE_POSITIVE`), storing the
**exact rule version** that fired for replayability. `org_id` from
`TenantContext`, never from the finding. **Depends on:** C2, A3.

### C5 · Rule coverage measurement + ATT&CK mapping — L3
**Objective.** `chain_detect_from_evidence/`: real upload → parse → index →
detect → `Detection` row. Report real coverage by ATT&CK technique.
**Depends on:** C4, A4.

### C6 · Detection API + triage UI — L3
**Objective.** Backend-filtered detection list/detail/triage endpoints and UI.
If A3 was NO-GO, this is the *only* tenant-facing surface for findings.
**Depends on:** C4.

---

## M3 — Continuous ingestion

### D1 · `StreamIngestAdapter` ABC + Redis Streams implementation — L1
**Objective.** Durable, replayable, at-least-once telemetry transport behind an
ABC. Redis Streams first: already deployed, consumer groups, no new
infrastructure or secrets. Kafka/Redpanda must be swappable with zero changes
above the adapter, and adopted only on measured need. Per-org stream keys so a
consumer for org A structurally cannot read org B, and one noisy tenant cannot
starve another. **Depends on:** B1.

### D2 · Collector ingest API + mTLS identity — L2
**Objective.** Collector-facing ingest authenticated by **step-ca-issued client
certificates**, not long-lived bearer tokens (500 endpoints × static secret is
credential sprawl). `org_id`/`source_id` derived from the verified peer
certificate; a collector that lies in its payload must not be able to write into
another tenant. Backpressure and dedup-by-event-hash required.
**Depends on:** D1.

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

### D4 · Continuous normalization pipeline (stream → ECS) — L2
**Objective.** Reuse the A2 registry to normalize continuous sources into the
*same* ECS schema as Plaso-parsed forensic events — one timeline, one query
surface. Extensible per-source: new source = new registered normalizer.
**Depends on:** D1, A2, B2.

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
  secondary, silent OS-crontab-based backstop also exists
  (`scripts/dev_autoresume/`) purely for the case the whole session process
  itself dies (not just a subagent hitting a spend limit) — it already
  proved itself once this session (see its own README) — but its activity
  is not chat-visible by design/necessity, so `CronCreate` remains primary.
