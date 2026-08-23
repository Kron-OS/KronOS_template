# Gap Audit — Milestone OO (2026-08-23)

Continuation of `docs/GAP_AUDIT_2026-08-22_MILESTONE_NN.md`'s own named
next candidates: the individual parser/ingestion modules
(`src/external/parsers/*.py`) and the OpenSearch adapter layer. This pass
covered all four named parser modules and started on the remaining
OpenSearch adapters.

---

## 1. `archive.py`/`tar_archive.py`/`_container_common.py` reviewed, no new gap

Full direct read of `ZipArchiveParser`, `TarArchiveParser`, and their
shared `_container_common.py` (zip-bomb/tar-bomb defenses: a
`ContextVar`-backed `ExtractionBudget` shared *across* container types so
a zip-in-tar-in-zip nesting tree can't reset either counter by
alternating container type; `is_unsafe_member_path` correctly rejects
absolute paths and `..` segments for path traversal; neither parser ever
trusts a container's own declared member size, both bound the real read
instead; `tar_archive.py` correctly skips symlink/hardlink members
entirely — the exact CVE-2007-4559-class `extractall()` footgun — rather
than ever resolving a link target). Both parsers' recursive re-dispatch
(`_dispatch_member`/`_recurse_into_nested_container`) correctly reuses the
same registry and the same shared budget/depth state. No new gap found —
this is some of the most carefully defended code in the repo.

One thing checked and confirmed NOT a live issue: `is_unsafe_member_path`
doesn't reject a Windows-drive-letter-style absolute path (e.g.
`C:\evil\path`), only POSIX-style ones. Confirmed this has no real
exploit surface in this codebase specifically: extracted member bytes are
never written to a real filesystem path derived from the member's own
name (`zf.open()`/`tf.extractfile()` read in-memory; `member_path` is
only ever used as a display/dispatch string, never a write target) — a
real, different codebase that did materialize members to disk by their
own path would need this closed, but this one doesn't.

---

## 2. `PlasoParser` leaked its temp file on any parse failure or early consumer abort — FIXED

**Finding.** `PlasoParser.parse()` wrote the evidence bytes to a real temp
file, then only unlinked it *after* the `async for record in records:
yield record` loop completed normally — unlike `ZipArchiveParser`/
`TarArchiveParser`/`VolatilityModule` (all three confirmed to correctly
wrap their equivalent cleanup in `try/finally`). Any real Firecracker VM
failure, worker timeout, or a downstream consumer (enrichment/timeline-
ingest) aborting mid-stream left the temp file on the worker's local
`/tmp` indefinitely — a real disk-space leak, and an evidence-hygiene
concern since the leaked bytes could be a whole disk image or a registry
hive carrying real credentials, sitting outside MinIO's own audited WORM
bucket and chain-of-custody controls.

Confirmed `FirecrackerLauncher.run()` (`src/external/sandbox/
firecracker.py`) never touches `evidence_path` itself — it only reads
from it as a subprocess CLI argument — so `PlasoParser` was the sole
owner of this temp file's lifecycle, and the only one of the four
container/heavy parsers that got it wrong.

**Fix.** Wrapped the `launcher.run()` call and record consumption in
`try/finally`, matching the already-correct pattern used everywhere else
in this codebase.

**Tests.** Two new regression tests in `test_plaso_parser.py`: a real
Firecracker failure (`RuntimeError` from a fake launcher), and a consumer
aborting mid-stream (`gen.aclose()` after consuming one record, triggering
a `GeneratorExit` inside `parse()`). Both independently verified to fail
against the pre-fix code (`git stash` the fix, re-run — both failed with
"leaked" temp file assertions) and pass with the fix applied.

**Verification.** Full suite: **2030 passed, 2 skipped** (2028 + 2 new
tests). `ruff`/`black`/`mypy` clean (one `black` reformat needed on the
new test code, applied and re-verified).

---

## 3. `volatility.py` reviewed, no new gap

`VolatilityModule.extract_artifacts()` already correctly wraps its own
temp-file cleanup in `try/finally` — the one confirmation-by-contrast that
made `PlasoParser`'s own gap stand out as a real inconsistency rather than
a codebase-wide pattern. `supports()`'s extension-only detection (no
verified magic bytes exist for raw memory dumps) is honestly documented
and consistent with `validation.py`'s own `_MEMORY_DUMP_EXTENSIONS`. No
new gap found.

---

## 4. `dashboards_client.py` reviewed, no new gap

`DashboardsIndexPatternProvisioner.ensure_case_index_pattern()`'s two
inputs (`org_alias`, `case_id`) are both server-derived at the one real
call site (`src/external/routes/cases.py`): `tenant.org_alias` (from the
authenticated JWT, never client-supplied) and `case.case_id` (a
server-generated UUID from the just-created `Case`). No injection or
tenant-crossing risk into the OpenSearch Dashboards saved-object id/
`securitytenant` header. No new gap found.

---

## 5. Remaining seven OpenSearch adapters reviewed, no new gap

Full direct read of the rest of the Security Analytics/AD/ISM adapter
layer named in section 4's own recommendation:

- `detector_provisioner.py` — `SecurityAnalyticsDetectorProvisioner`'s
  check-then-create-only design (never PUT-updates an existing detector,
  documented real `EmptyMap`/`MutableMap` OpenSearch 2.11.1 bug) and its
  nested-query idempotency check against `.opensearch-sap-detectors-config`
  confirmed correct; per-org scoping via `kronos-{org_alias}-*` confirmed.
- `anomaly_detector_provisioner.py` — `OpenSearchAnomalyDetectorProvisioner`'s
  real race-condition handling for concurrent detector creation
  (`_NOT_READY_ERROR_MARKERS` distinguishing "org has no data yet" from a
  genuine failure) confirmed correct. Noted, but not fixed: this class
  sanitizes `org_alias` via `re.sub(r"[^a-z0-9-]", "-", org_alias.lower())`
  before building a detector name, while `detector_provisioner.py` does
  not sanitize at all. Not a live bug — org aliases are Keycloak-admin
  controlled, not open tenant self-service, and every write here goes
  through httpx's `json=` encoding, which cannot be used to inject into
  the request structure regardless of the string's contents. Worth
  normalizing for consistency in a future pass, not urgent.
- `custom_rule_client.py` — `SecurityAnalyticsCustomRuleClient` pushes raw
  Sigma YAML text (not JSON) to the rules endpoint with real, empirically
  confirmed 500-class failure modes documented (`ClassCastException` on a
  JSON body, `NullPointerException` on YAML missing `date:`); confirmed it
  has no field through which a caller could smuggle an index/tenant
  reference — Sigma has no such field.
- `custom_rule_detector_provisioner.py` — read specifically to verify
  `custom_rule_client.py`'s own claim that "the index pattern a rule ever
  runs against is decided entirely by the detector wrapping it, never by
  rule content." Confirmed true: `SecurityAnalyticsCustomRuleDetectorProvisioner.
  sync_custom_detector()` always builds `indices: [f"kronos-{org_alias}-*"]`
  from the caller-supplied `org_alias` parameter, and `custom_rules` only
  ever carries `{"id": ...}` (an opaque, server-generated rule id) — no
  path exists for rule/pack content to affect index scoping. Delete-and-
  recreate idempotency (never PUT-update, same real OpenSearch defect as
  `detector_provisioner.py`) confirmed correct, including the two early-
  return paths (already-matching rule set; empty desired set with no
  existing detector to delete).
- `ism_manager.py` — `OpenSearchIsmLifecycleManager.ensure_managed()`'s
  documented real finding (`POST _plugins/_ism/add/{index}` can return
  HTTP 200 with `{"failures": true, ...}` in the body, which a bare
  `raise_for_status()` would treat as success) is defended against via
  `_raise_if_ism_body_reports_failure()`, applied consistently to both
  `ensure_managed()` and `place_legal_hold()`. `is_managed_and_enabled()`'s
  post-search exact-name check defends against a non-exact match query.
  Confirmed correct.
- `rarity_baseline_client.py` — `OpenSearchRarityBaselineClient` always
  requests `order: {"_count": "asc"}` on its terms aggregation (confirmed,
  via the class's own cited live-cluster PoC, that the OpenSearch default
  descending order would silently make the entire rarity-hunting feature
  find nothing rare once cardinality exceeds `max_distinct_values`); the
  documented "aggregations key entirely absent when the index pattern
  matches zero indices" gap is correctly left for the caller to handle
  rather than papered over in this class. Confirmed correct.
- `anomaly_detection_client.py` — `OpenSearchAnomalyDetectionResultsClient`
  confirmed to always use the AD plugin's own dedicated results-search
  endpoint (`POST _plugins/_anomaly_detection/detectors/results/_search`)
  rather than querying the protected `.opendistro-anomaly-results*` system
  index directly — the class's own docstring documents a real, confirmed
  finding that a direct query against that index silently returns zero
  hits even as the admin superuser, regardless of real document count.
  Confirmed correct.

No new gap found in any of the seven. This closes out the parser +
OpenSearch adapter layer named across Milestones NN and OO — every file in
`src/external/parsers/` and `src/adapter/opensearch/` has now had at least
one independent direct-read review pass in this audit chain.

---

## Recommendation for the next wake-up cycle

The parser and OpenSearch adapter layers have now had a full independent
review pass with only one real bug found (`PlasoParser`'s temp-file leak,
section 2). Diminishing returns reached for this specific area — the next
milestone should pick a fresh, not-recently-reviewed area of the codebase
(e.g. the Celery task layer under `src/external/`, the SOAR/playbook engine
introduced in `feat(soar): H1 playbook engine`, or the frontend routes) as
its "recently-landed or never-independently-reviewed" candidate set, per
this chain's own established method (CLAUDE.md Section F/this doc's own
header note that re-scanning old audit docs stopped surfacing new findings
around Milestone CC).

Also still open from prior milestones, unchanged:
1. The lower-value optional SIEM/EDR secrets
   (`splunk_hec_token`/`sentinel_client_secret`/`defender_client_secret`)
   confirmed to degrade safely with `secrets_dir` but not yet moved off
   plaintext `environment:` in `docker-compose.prod.yml`.
2. Keycloak's own `KC_DB_PASSWORD`/`KC_ADMIN_PASSWORD` — no native
   file-secret convention exists in Keycloak 26.x itself.
3. The Postgres sync-replica ops-policy decision
   (`docs/POSTGRES_MINIO_HA_RESEARCH.md` §1.6) remains open for the
   project owner.
