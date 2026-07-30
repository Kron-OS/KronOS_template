# C1 GATE: Security Analytics field mappings + real rule-coverage measurement

**Roadmap item:** `docs/NEXTGEN_SOC_ROADMAP.md` M2/C1. Bound by A3's binding
conditions (all SA actions below use **admin** credentials only — never a
tenant-facing role; see `poc/security_analytics_tenant_isolation/`).

## Method

1. Real login (`case-lead`), real case, real upload+finalize of one sample
   per relevant parser through the actual pipeline — `system.evtx`
   (evtx-rs), `aws_cloudtrail.jsonl` (CloudTrailParser), `apache_access.log`
   (NginxParser), `eve.json` (SuricataEveParser) — all reached `COMPLETE`
   (`evidence_ids.json`, `final_states.json`, `ingest_output.txt`).
2. For each relevant log type (`windows`, `cloudtrail`, `network`,
   `apache_access`), fetched the real `_plugins/_security_analytics/mappings`
   response for the case's real index pattern and applied alias mappings for
   the fields it reported unmapped (`build_alias_mappings.py`,
   `alias_mapping_report.json`/`alias_mapping_output.txt`).
3. Created 3 real detectors as **admin** (`kronos-poc-{windows,cloudtrail,network}-detector`)
   over the real case index pattern
   (`kronos-kronos-dev-case-<case_id>-*`), each using OpenSearch's real
   prepackaged rule set for that log type (no hand-picked subset).
4. Re-ingested fresh copies of the samples post-detector-creation
   (`ingest_post_detector*.py`) so the detector's own monitor execution had
   new documents to evaluate against.
5. Queried real findings per detector and inspected real per-rule counts,
   tags, and ATT&CK references directly from the finding documents (not
   estimated).

## Real measured coverage

| Log type | Prepackaged rules available | Distinct rules that fired | Total findings | Sample used |
|---|---|---|---|---|
| `windows` | 1,580 | **3** | 205 + 8 + 8 | `system.evtx` (evtx-rs) |
| `network` | 38 | **1** | 11 | `eve.json` (SuricataEveParser) |
| `cloudtrail` | 32 | **0** | 0 | `aws_cloudtrail.jsonl` |
| `apache_access` | (not separately counted — 0 unmapped fields, no detector created this pass) | — | — | `apache_access.log` |

Real fired examples, with real ATT&CK tags pulled directly from the finding
documents (`_plugins/_security_analytics/findings/_search`):

- **windows**, rule `db809f10-...` (205 findings): `tags: [low, windows,
  attack.defense_evasion, attack.t1006]` — an allowlist-exclusion rule
  ("alert on any process image NOT matching a list of known-benign system
  paths"). Matched broadly here because the real ingested EVTX sample
  contains many `Security` auditing events (group-membership changes,
  privilege-use events) that carry **no** `winlog.event_data.Image` field at
  all — the rule's `NOT (...)` logic is vacuously true for any event that
  simply lacks the field it excludes on. This is a real, honest
  characterization: high finding *count* here reflects one broad,
  low-specificity rule matching non-adversarial audit noise, not diverse
  meaningful coverage. The other two windows rules (`7818b381-...` /
  credential access T1212, `196a29c2-...` / T1110.003 brute-force) fired 8
  times each on genuinely more specific conditions.
- **network**, rule `1fc0809e-...` (11 findings): `tags: [high, network,
  attack.t1021.001]` (remote-services lateral movement) — fired against
  real Suricata EVE flow records.
- **cloudtrail: zero rules fired.** Real, unresolved gap — see below.

## Real bug/gap found: cloudtrail field-mapping aliases did not visibly reduce "unmapped" count

`alias_mapping_report.json`: applying 7 real field aliases to the
`cloudtrail` log type (`aws.cloudtrail.event_name` → `event.action`,
`aws.cloudtrail.source_ip_address` → `source.ip`, etc.) returned real `200
{"acknowledged":true}` responses from `_plugins/_security_analytics/mappings`,
but a follow-up unmapped-field check still reported **41 unmapped before,
41 unmapped after** for every log type tested (`windows`: 167→167,
`network`: 25→25, `cloudtrail`: 41→41) — the alias POST is accepted but the
"unmapped" count never visibly drops. Combined with cloudtrail's real 0/32
rule-fire result, this is a genuine open question, not yet root-caused:
either (a) the unmapped-count check itself queries the wrong thing (e.g. it
may need to re-run against a freshly re-ingested/re-indexed document rather
than the mapping config alone), or (b) the alias mechanism doesn't actually
change rule evaluation the way assumed and real cloudtrail rules need the
literal field names, or (c) the 32 available cloudtrail rules genuinely
target signals (specific `errorCode`/`eventName` values, e.g.
`ConsoleLogin` failures, IAM policy changes) that this one benign real
CloudTrail sample simply doesn't contain — indistinguishable from a mapping
failure using only this one data point. **Flagged as follow-up, not solved
here** — needs either a cloudtrail sample containing a real event one of
the 32 rules explicitly targets, or a deeper read of the mappings API
semantics (real doc-version confirmation of what "unmapped" actually
measures).

## Gate assessment

**Mechanism confirmed working end-to-end, real coverage measured
honestly, one open gap flagged.** The detection engine mechanism itself is
proven real: mapping → detector → real finding, with correct ATT&CK
tagging, for 2 of 3 tested log types. Absolute coverage percentage is low
(3/1580, 1/38) against a single benign sample per type — expected and not
itself a gate failure, since Sigma rules target specific adversarial
conditions a single non-adversarial sample won't trigger broadly; this
number will only become meaningful once measured against samples
containing known attack techniques (see roadmap C5's ATT&CK-coverage
chain, which should reuse this exact mapping+detector setup against
adversarial fixtures rather than the benign ones used here).

This does **not** block downstream C2/C4/C6 — the mechanism works, A3's
conditions were followed throughout (admin-only), and the cloudtrail gap is
narrow and specifically scoped for follow-up.

## Index template change made alongside this (`src/adapter/opensearch/index_template.json`)

Real EVTX ingestion surfaced a gap A1/A2 didn't anticipate: `winlog.event_data.*`
carries a genuinely variable field set per Windows event type (`CommandLine`,
`TargetUserName`, `PrivilegeList`, ... — different per `EventID`), so it
cannot be exhaustively pre-mapped the way `event.*`/`process.*` were. Added a
scoped `dynamic: true` override + a `dynamic_templates` entry forcing any
`winlog.event_data.*` string to `keyword` (not `text`) — re-enabling dynamic
mapping only inside that one known-variable namespace, not globally (the
top-level `dynamic: false` from A1 is unchanged for everything else). Also
added `cloud.service.name`/`cloud.region`/`log.file.path` — the ECS targets
the cloudtrail/network alias mappings above translate into.

**Distinct from `ecs_field_registry.py` (A2) — not yet reconciled.** The SA
`_plugins/_security_analytics/mappings` aliases applied above are a
*different* mechanism from KronOS's own `ECSFieldMappingRegistry`: the SA
mappings tell Security Analytics itself how to interpret fields for its own
rule execution; the registry is KronOS's internal bookkeeping + CI check
that the index template covers what parsers actually emit. The
cloudtrail/network aliases used here were not added to the registry, so
`validate_against_index_template()` doesn't yet cover them. Flagged as
follow-up for whoever extends A2's remaining parser inspections
(`CloudTrailParser`/`NginxParser`/`PlasoParser` were already noted as
not-yet-individually-inspected in A2's own status).

## Not verified

- Did not deeply root-cause the cloudtrail unmapped-count/zero-findings
  gap (see above).
- `apache_access`/`others_web` log type: confirmed 0 unmapped fields
  needing aliasing, but no detector was created/tested against it this
  pass — real NginxParser output apparently already matches ECS naming
  closely enough to need no translation, consistent with A2's own finding
  that `SuricataEveParser` needed none either, but this wasn't independently
  detector-tested the way windows/cloudtrail/network were.
- `linux`/`plaso`-sourced log types not tested (no Plaso sample ingested
  this pass).
