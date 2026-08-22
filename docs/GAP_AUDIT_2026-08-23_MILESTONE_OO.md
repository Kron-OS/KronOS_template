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

## Recommendation for the next wake-up cycle

Remaining, not-yet-reviewed OpenSearch adapters (per Milestone NN's own
list, `dashboards_client.py` now done): `anomaly_detection_client.py`,
`anomaly_detector_provisioner.py`, `custom_rule_client.py`,
`custom_rule_detector_provisioner.py`, `detector_provisioner.py`,
`ism_manager.py`, `rarity_baseline_client.py`. These are the largest
remaining area with no recent independent review in the JJ-OO chain.

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
