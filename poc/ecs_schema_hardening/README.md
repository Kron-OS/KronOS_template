# A1/A2: index template hardening + ECS field-mapping registry

**Roadmap item:** `docs/NEXTGEN_SOC_ROADMAP.md` M0/A1 + M0/A2.

## The bug, reproduced for real

`src/adapter/opensearch/index_template.json` originally set no `dynamic`
policy (defaulting to `true`) and mapped only 24 fields. OpenSearch's
default dynamic mapping maps an unmapped string field to `text` (analyzed)
+ a `.keyword` sub-field. Security Analytics compiles Sigma rules to `term`
queries expecting exact-match `keyword` semantics against the bare field
name — against a dynamically-mapped `text` field, that query **silently
returns zero hits**, with no error anywhere.

`run_poc.py` reproduces this against the real, live OpenSearch 2.11.1
cluster (not simulated): indexed a real document with
`process.command_line`, confirmed OpenSearch actually mapped it as `text`,
then ran the exact Sigma-shaped `term` query and captured **zero hits
despite the document demonstrably existing** (`output.txt`, checks 1-5).

## The fix

- **`dynamic: false`**, not `strict`. Chosen over `strict` because parser
  `extra` fields vary per format/parser — `strict` would **reject the whole
  write** the instant any record carried an unlisted field, breaking
  ingestion outright. `false` means an unmapped field is safe-but-unsearchable
  (stored in `_source`, not indexed) rather than either a write failure or
  the original silently-wrong dynamic-text mapping. Verified for real (check
  10-12): a document with a genuinely unexpected field is still **accepted**
  (201), the field is **not** searchable via `term`, but the raw value is
  still present in `_source` — nothing is silently dropped.
- **Expanded mapped fields**: `process.command_line`, `process.parent.*`,
  `source.ip/port`, `destination.ip/port`, `dns.question.name`,
  `file.hash.{md5,sha1,sha256}`, `registry.{path,key,value}`,
  `event.code/action`, `data_type`, and the previously-unmapped
  `kronos.org_alias`.
- **Second pass, found while doing the A2 per-parser inspection**: the same
  bug class also hit `NginxParser`/`CloudTrailParser`/`SuricataEveParser`/
  `ChromeHistoryParser`'s own real output fields, none of which were ever
  mapped even before this change — `dynamic:false` would have made them
  silently unsearchable too. Added: `error.{code,message}`,
  `http.{hostname,request.method,request.referrer,response.status_code,response.body.bytes}`,
  `url.{path,domain}`, `user_agent.original`, `tls.{subject,sni}`,
  `alert.{signature,category,severity,action}`, `rule.id`,
  `dns.{rrname,rrtype,type}`, `file.{name,size}`, `event.duration`. Two
  deliberate non-`keyword` choices: `cloudtrail.request_parameters` is
  `{"type": "object", "enabled": false}` (genuinely variable-shape AWS API
  payload — stored, never indexed, not force-fit into a fixed schema);
  `chrome.title`/`error.message` are `text` (natural-language content, not
  exact-match targets). Re-ran the same before/after PoC after this addition
  — still 12/12 (regression-checked, not just assumed compatible).
- **Existing indices**: an index template only applies to newly-created
  indices — live `kronos-*` indices keep their current (dynamic) mapping.
  Documented, not silently left unaddressed: no reindex was performed as
  part of this pass (out of scope — would need a real rollover/reindex plan
  against production data, not appropriate to do unattended). New indices
  (new month, new case) get the hardened mapping automatically via ISM
  rollover.
- **A2 registry** (`src/application/ecs_field_registry.py`): an
  extensible `FieldMapping` ABC + `ECSFieldMappingRegistry`, plus
  `validate_against_index_template()` as the CI check the roadmap
  requires — it fails if a registered ECS path isn't mapped in the real
  template (that mismatch *is* this bug). Found by actually reading two
  parsers' real code (not assumed uniformly): `SuricataEveParser` already
  writes ECS-shaped keys directly into `extra` (`"source.ip"`,
  `"destination.port"`) — nothing to translate. `FastEvtxParser` preserves
  raw Windows EventData names under `winlog.event_data.*`
  (`winlog.event_data.CommandLine` never becomes `process.command_line`) —
  that's the real, concrete gap this registry closes. Deliberately did NOT
  map `winlog.event_data.Hashes` → `file.hash.sha256`: Sysmon's raw
  `Hashes` field is a composite string (`MD5=...,SHA256=...`), not a bare
  hash value, so a plain rename would misrepresent the data — needs real
  parsing logic, flagged as follow-up rather than guessed.
- **Remaining A2 scope**: `CloudTrailParser`, `NginxParser`, `PlasoParser`,
  `ChromeHistoryParser` have not yet been individually inspected the way
  `evtx.py`/`suricata.py` were here. Do not assume either way without
  reading their actual `extra[]` writes first.

## Verified, for real

`run_poc.py` against the real, live dev-stack OpenSearch 2.11.1
(`output.txt`): **12/12 passed** — the bug reproduced, the fix confirmed,
and the `dynamic:false` trade-off confirmed to behave as designed (accept,
don't index, don't drop).

`pytest tests/unit/application/test_ecs_field_registry.py`: **6/6 passed**
— registry behavior, the CI validator correctly passing for the real
default registry, and a regression guard confirming the validator actually
*catches* a deliberately-unmapped field rather than trivially passing
everything.

Full unit suite: see `PROGRESS.md`/task tracker for the latest confirmed
count (baseline before this change was 622 passed).
