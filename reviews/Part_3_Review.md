# Part 3 Review — Parsing Scope and Timeline Model

- **Date:** 2026-06-16
- **Spec section reviewed:** `Project_Specifications.md` §3
- **Tracking issues:** #3 (category), #13 (today's review)
- **Branch:** `claude/zen-cerf-575yj7`

---

## 1. What the spec currently says

The spec proposes:

1. Accept "all types of timeline-based files" — explicit list: EVTX, Prefetch, SRUM, Shimcache, Amcache, registry hives, browser SQLite, web/proxy/DNS/cloud logs (CloudTrail, GCP audit, Azure), Linux journald/syslog, web-server logs.
2. Use **log2timeline / Plaso** as the heavy-lifting parser; rely on `psort` and (possibly) its OpenSearch output module to push events directly into OpenSearch.
3. Verify whether Plaso handles automatic parser detection; if not, implement a dispatcher.
4. A **unified timeline event** with at minimum: UTC timestamp, message, source, host, user, plus extras.
5. **Celery workflow** driving status transitions `RECEIVED → PARSING → INGESTING → COMPLETE`, with `ERROR` on any failure.
6. Possibly **split large files into multiple Celery tasks** for parallelism.
7. **Everything in UTC.**

---

## 2. Work already done in the repo

| Artifact                                | Status                                                                  |
| --------------------------------------- | ----------------------------------------------------------------------- |
| `Project_Specifications.md` §3          | Narrative only — no parser list, no schema, no DAG                      |
| Parser/dispatcher code                  | None                                                                    |
| Celery topology                         | None                                                                    |
| Timeline schema definition              | None                                                                    |
| OpenSearch mapping for events           | None (template defined in §1 review for index naming only)              |
| Tests / fixtures                        | None                                                                    |

**Conclusion:** §3 is at the "intent / outline" stage. Hand-off point from §2 is `evidence.status = RECEIVED`; hand-off point into §4 is `evidence.status = COMPLETE` with documents indexed in OpenSearch under `kronos-{org_alias}-case-{case_id}-{yyyymm}`.

---

## 3. Feasibility research (state of the art, 2026)

### 3.1 Plaso / log2timeline today

- Plaso is on rolling releases (`20260512` at the time of writing) and remains the de-facto super-timeline tool.[^plaso-output][^plaso-parsers]
- It ships **two OpenSearch output modules**:
  - `opensearch` — generic, writes parsed events as documents.
  - `opensearch_ts` — Timesketch-flavoured, writes the fields Timesketch expects (`message`, `datetime`, `timestamp_desc`, `_source_type`).[^plaso-os-ts]
- Plaso provides **automatic format detection** via `pysigscan`: parsers register format specifications with signatures; `TextLogParser` additionally handles plain-text logs with multi-encoding support.[^plaso-parsers]
- **Parser presets** (`win_gen`, `win7`, `win7_slow`, `webhist`, `linux`, `macosx`, `android`) group parsers; we can call Plaso with `--parsers=win_gen` etc. to scope the work.[^plaso-parsers]
- Memory consumption is the historical pain point: on a 20-core/20 GB box, **11 of 17 workers used > 500 MB each, with peaks at 1.2 GB**, and parsers like SRUM are known to push workers past their memory limit.[^plaso-mem][^plaso-srum]

### 3.2 Faster alternatives for hot artefacts

- **evtx-rs** (`omerbenamram/evtx`, Rust) is on the order of **650–1600× faster than `python-evtx`** with multi-threading and ships Python bindings. For high-volume EVTX (DC security logs are typically several GB) this is a much better fit than Plaso's EVTX parser.[^evtx-rs]
- For other artefacts (Prefetch, REGF, SRUM) Plaso remains the best maintained option — we should not over-rotate to bespoke parsers.

### 3.3 Timeline schemas — Plaso native vs ECS vs OCSF

- **Plaso's native event schema** is what `psort` emits: `datetime`, `timestamp_desc`, `message`, `display_name`, `parser`, plus parser-specific fields. Adequate for Timesketch but not aligned with broader SIEM tooling.
- **Elastic Common Schema (ECS)** is the de-facto open spec for normalising event data into Elasticsearch/OpenSearch indices, with a stable field catalogue (`@timestamp`, `event.*`, `host.*`, `user.*`, `process.*`, `file.*`, …).[^ecs]
- **OCSF (Open Cybersecurity Schema Framework)** is the vendor-neutral schema pushed by Splunk/AWS/IBM/Cloudflare; richer category model than ECS but heavier ingest mapping and weaker tooling in OpenSearch land.[^ocsf-splunk][^ocsf-site]
- **Verdict for v1:** ECS, because (a) OpenSearch Dashboards has out-of-the-box ECS dashboards, (b) ECS field names are stable and well-documented, (c) we can layer a minimal `kronos.*` extension for chain-of-custody pointers without forking the schema.

### 3.4 Direct Plaso → OpenSearch vs an intermediate ingester

- The spec floats `psort -o opensearch` writing straight into OpenSearch. Pros: zero glue code. Cons:
  - We lose the per-event enrichment opportunity (custody fields `kronos.evidence_id`, `kronos.evidence_sha256`, `kronos.case_id`, `kronos.tenant_id`).
  - We lose ECS normalisation — Plaso's native fields land instead.
  - Errors at the OpenSearch boundary are silent.
- Better pattern: `psort -o json_line` to a temp file, then a Kronos **ingester worker** reads the JSONL, normalises into ECS + adds `kronos.*` fields, and bulk-indexes via `opensearch-py` with deterministic `_id`s (idempotency on retry).

### 3.5 Celery topology

- Celery canvas (`chain`, `group`, `chord`) is the right pattern for fan-out/fan-in:
  - `chain(detect_artefacts, group(parse_artefact x N), index_into_opensearch)`.
- Idempotency is **mandatory** for retries: tasks must be safe to run twice, and OpenSearch documents must have stable `_id`s so a re-run does upserts not duplicates.[^celery-canvas]
- Retry policy: exponential back-off with jitter for transient errors (OpenSearch 5xx, MinIO read timeout); **no retry** on parser exceptions (those are deterministic failures).

### 3.6 Large file splitting

- The spec says "for a 1 GB CSV we might split it". Real-world rules:
  - **Text logs** (CSV, NDJSON, plain-text syslog): split by line count, preserving the CSV header in every chunk. tus.io / S3 multipart already gives us bytes-level splits but never line-aware ones.
  - **Binary forensic artefacts** (EVTX, REGF, .pf, SQLite): **do not split**. They have global state (chunks, B-trees, transaction logs) that makes mid-file splits incorrect. Parallelise *across* files, not within one binary file.
- Plaso itself already parallelises across files via its task-based multi-processing system; we should let Plaso parallelise *within* a parse task and use Celery to parallelise *across* evidence items.[^plaso-mem]

### 3.7 UTC normalisation pitfalls

- Forensic artefacts mix sources of truth: EVTX records carry FILETIME (UTC), prefetch carries local-machine time, browser SQLite often carries unix-epoch with no TZ.
- `dateutil.tz` handles the **ambiguous-time / fold problem** (e.g. `02:30` on a fall-back day exists twice in CET), with `datetime_ambiguous()` / `datetime_exists()` and PEP-495 `fold` attribute support.[^dateutil-tz]
- Convention for Kron-OS: every event stores `@timestamp` in UTC (Z) and, when relevant, `event.timezone` (IANA name of the original source). `fold` is preserved in a side field `kronos.tz_fold` so the original ambiguity is not lost.

### 3.8 Timesketch as analysis UI?

- The spec assumes OpenSearch Dashboards. Timesketch is the alternative: it bundles per-event tagging, "stars", saved searches, and Sigma-rule playback — features that Dashboards does not have natively.
- Going Timesketch would mean using `opensearch_ts` output and Timesketch's own data model — incompatible with ECS. Hold this question for §4 (UI). v1 commits to OpenSearch Dashboards + ECS; Timesketch can be a v2 add-on.

---

## 4. Problems identified

### P1. Direct Plaso→OpenSearch output drops chain-of-custody fields
The spec's first instinct (`psort -o opensearch`) bypasses our `kronos.evidence_id` / `kronos.evidence_sha256` provenance. Every parsed event must carry a back-pointer to the source evidence record (§2) so an analyst can trace any timeline row back to a SHA-256-anchored file.

### P2. Plaso coverage is asserted, not verified
The spec lists 10+ artefact families but never matches each one to a concrete Plaso parser (or to a gap). The result is a list of intentions, not a capability statement. We need an `(artefact, plaso parser, supported?)` table — with a documented fallback for the gaps (e.g. CloudTrail JSON via a custom parser).

### P3. No commitment on timeline schema
Plaso-native vs ECS vs OCSF is left open. Choosing late means schema churn in OpenSearch indices, which is operationally painful.

### P4. SRUM and other heavy parsers blow up workers
Documented in Plaso issues: SRUM parser causes workers to exceed 1.2 GB. Without per-worker memory limits and a dedicated "heavy parsers" queue, one bad evidence item kills the whole worker pool.

### P5. "Split large CSVs into tasks" is naive
A bytes-level split mid-line corrupts CSV/NDJSON parsing. Header context is lost on chunks 2..N. A real split policy needs line-aware chunking and header replay.

### P6. UTC normalisation is hand-waved
Ambiguous DST times, parser timezones, fold attribute — none addressed. Forensic timelines that silently lose 1 hour twice a year are unusable.

### P7. Celery retry / idempotency semantics undefined
The spec catches errors and marks `ERROR`, but does not distinguish transient (retryable) from deterministic (terminal) failures, and does not commit to deterministic OpenSearch `_id`s. Retries will create duplicates.

### P8. Timesketch decision deferred without saying so
The spec hints at Timesketch (mentions `opensearch_ts`) but the UI design (§4) assumes OpenSearch Dashboards. These two stacks have incompatible schemas; we must pick one for v1.

### P9. Parser sandboxing (gVisor) cross-cuts §3 and §5
"Cautious of malformed files that could exploit parser vulnerabilities" appears in §3 with a "consider gVisor" note already raised in §5. Single owner = §5; cross-reference here only.

### P10. No mapping between Plaso events and our `evidence`/`audit_log` IDs
Each Plaso event must include the case, org, evidence and (where known) the originating host/account. The Plaso event has the data; the join only happens at ingest time. This needs to be the ingester's first job.

---

## 5. Plan to reach the objective — detailed

### 5.1 Parser dispatcher

- Input: `evidence` row (status `RECEIVED`), `artefact_type` from §2 allowlist, MinIO object key.
- Logic (in Celery task `dispatch_parse`):
  1. Resolve `artefact_type` → parser slot:
     - **EVTX** → `evtx_rs` fast parser (Rust + Python bindings).
     - **Prefetch, REGF, SRUM, Shimcache, Amcache, browser SQLite, journald, syslog, Apache/Nginx, CloudTrail/GCP/Azure** → Plaso preset (`win_gen`, `linux`, `webhist`, etc.).
     - **CSV/JSON/NDJSON** → custom line-aware parser with header replay.
  2. Enqueue parse to the matching queue (`q.parse.fast`, `q.parse.plaso`, `q.parse.text`).
  3. Update `evidence.status = PARSING`, write `evidence.parse.start` to `audit_log`.

### 5.2 Plaso execution model

- Plaso runs **inside its own container image** (`kronos/plaso:20260512`), one process per parse task — never in the API worker.
- Memory limit per parse: **2 GB** (cgroups); if Plaso exits 137 (OOM), mark `ERROR` with `error_reason='parser_oom'` and do **not** retry (bug-level event, not transient).
- Output: `psort -o json_line --output-time-zone UTC <storage.plaso> > /tmp/{evidence_id}.jsonl`.
- The container has no network egress and no MinIO credentials beyond a short-lived presigned GET URL for the single object being parsed — minimum blast radius.

### 5.3 Timeline event schema (ECS + `kronos.*` extension)

Mandatory fields per event:

```jsonc
{
  "@timestamp": "2024-09-14T13:42:01.123Z",      // ECS, always UTC
  "event": {
    "kind": "event",
    "category": ["process", "authentication"],   // ECS taxonomy
    "action": "logon",                            // ECS
    "module": "evtx",                             // parser name
    "dataset": "windows.security",                // sub-source
    "original": "<raw EVTX XML>",                 // ECS — full original record (truncated to 32 KB)
    "timezone": "UTC"
  },
  "host":    { "name": "WIN-DC01", "os": { "type": "windows" } },
  "user":    { "name": "alice", "domain": "EXAMPLE" },
  "process": { "name": "svchost.exe", "pid": 1234 },
  "message": "Successful logon by EXAMPLE\\alice from 10.0.0.5",

  // Kron-OS custody/provenance extension
  "kronos": {
    "tenant_id":       "f4d8...",                 // org_id
    "org_alias":       "acme",
    "case_id":         "b2a9...",
    "evidence_id":     "1c77...",
    "evidence_sha256": "9af2e3...",
    "tz_fold":         0,                         // 0 or 1 — preserves DST ambiguity
    "parser_version":  "plaso/20260512",
    "ingest_id":       "task-uuid-..."            // for idempotency
  }
}
```

- The index template that backs `kronos-{org_alias}-case-{case_id}-{yyyymm}` enforces this mapping. ECS fields use the official ECS types; the `kronos.*` block is custom.
- `event.original` is capped at 32 KB; larger raw records spill to MinIO and are referenced via `kronos.original_object_key`.

### 5.4 Idempotent ingestion

- OpenSearch `_id` is **deterministic**: `sha1(evidence_id + ":" + parser + ":" + record_index)`.
- The ingester uses `op_type=create` on first run; on retry it switches to `index` so duplicates are upserted, not multiplied.
- Bulk batches of 500 events with a 30 s flush interval (mirrors Timesketch's tuning).[^plaso-os-ts]
- Each batch carries `kronos.ingest_id` so we can later identify a partially-failed batch and re-replay it.

### 5.5 Celery DAG

```
RECEIVED
   │
   ▼
chain(
   dispatch_parse,                   ──► sets status=PARSING
   parse_artefact,                   ──► writes /tmp/{ev}.jsonl in parser container
   chord(
       group(index_chunk(0..N)),     ──► sets status=INGESTING (on first chunk)
       finalize_evidence              ──► verifies counts, sets status=COMPLETE
   )
)
```

- **Queues:**
  - `q.parse.fast` — evtx-rs, line-aware text parsers; concurrency = #CPU.
  - `q.parse.plaso` — Plaso container; concurrency = max(1, #CPU/4) because each Plaso task spawns its own internal workers.
  - `q.index` — OpenSearch bulk indexer; concurrency tuned to cluster bandwidth.
- **Retry policy:**
  - Transient errors (`OpenSearchTransportException`, MinIO 5xx, container start failure): max 5 retries, exponential back-off 30 s → 8 min, jitter ±10 %.
  - Deterministic errors (parser exception, format mismatch, OOM): immediate `ERROR`, no retry.
- **Orphan cleanup:** beat job `parse_orphan_sweeper` aborts parse tasks running > 6 h.

### 5.6 Large-file splitting (text logs only)

- Implemented in `parse_artefact` for `artefact_type in ('csv','ndjson','syslog','apache','nginx','cloudtrail')`:
  1. Read the file once to compute line count and locate header bytes.
  2. If `line_count > 1_000_000`, split into K chunks of ~500 k lines each by **byte offset rounded to the next `\n`**.
  3. Re-emit the header on every chunk except the first; each chunk becomes its own `index_chunk` Celery task.
- Binary artefacts (`evtx`, `pf`, `regf`, `sqlite`, `srum`, `journal`): single chunk, parsed in one process; parallelism is across files, not within.

### 5.7 UTC normalisation rules

- All parsers must emit ISO-8601 UTC with `Z` suffix in `@timestamp`.
- If the parser knows the source TZ → `event.timezone` carries the IANA name; if not → omit.
- Ambiguous DST input: parsers MUST attempt to resolve fold using artefact context (e.g. ordering within the same file, BIOS time, SRUM `LastVisitedTime`). Where unresolvable, store both candidates: `@timestamp` = early, `kronos.alt_timestamp` = late, `kronos.tz_fold = -1` flagging the ambiguity. Dashboards surfaces a warning badge.
- Implementation uses `dateutil.tz.datetime_ambiguous()` + `datetime_exists()` per [^dateutil-tz]; pytz is **not** used (deprecated semantics).

### 5.8 Parser-coverage matrix (v1)

| Artefact         | Parser slot   | Plaso parser name      | Notes                                                                 |
| ---------------- | ------------- | ---------------------- | --------------------------------------------------------------------- |
| EVTX             | `evtx_rs`     | (Plaso has `winevtx`)  | Use evtx-rs for speed; Plaso as a fallback for crafted/corrupt files. |
| Prefetch (.pf)   | Plaso         | `prefetch`             | Stable.                                                                |
| Registry hive    | Plaso         | `winreg/*` plugins     | Family of plugins driven by hive type detection.                       |
| SRUM             | Plaso         | `esedb/srum`           | **Quarantine to `q.parse.plaso.heavy`** with 4 GB memory limit.        |
| Shimcache        | Plaso         | `winreg/shimcache`     | via SYSTEM hive.                                                       |
| Amcache          | Plaso         | `winreg/amcache`       |                                                                        |
| Browser SQLite   | Plaso         | `sqlite/chrome`, `sqlite/firefox` | Plaso supports common schemas.                            |
| journald         | Plaso         | `systemd_journal`      |                                                                        |
| syslog           | Plaso         | `syslog`               |                                                                        |
| Apache/Nginx     | text          | (none — custom)        | Custom NDJSON/text parser, no Plaso preset.                            |
| CloudTrail JSON  | text          | (none — custom)        | JSON-lines parser, normalise to ECS `aws.cloudtrail.*`.                |
| GCP audit / Azure| text          | (none — custom)        | Same pattern as CloudTrail.                                            |
| EML / MBOX       | Plaso         | `mbox`, `eml`          |                                                                        |
| CSV (generic)    | text          | (none — custom)        | Header-aware chunker.                                                  |
| JSON / NDJSON    | text          | (none — custom)        |                                                                        |

### 5.9 Status transitions hand-off

- §2 → §3: `RECEIVED → PARSING` triggered by `dispatch_parse`.
- §3 → §4: `INGESTING → COMPLETE` triggered by `finalize_evidence` once OpenSearch returns the expected document count (`indexed_docs == parsed_records`). Mismatch ⇒ `ERROR` with `error_reason='ingest_count_mismatch'`.
- All transitions write to `audit_log` (vocabulary from §2 review).

### 5.10 Incremental milestones

| Milestone | Content | Exit criterion |
| --------- | ------- | -------------- |
| M3.1 | Parser slot framework + dispatcher + `q.parse.*` queues | A `RECEIVED` evidence row picks the right queue per artefact_type |
| M3.2 | Plaso sandbox container (`kronos/plaso`) + sample EVTX golden test | Plaso parses the test EVTX into JSONL, no network calls leave the container |
| M3.3 | ECS-based event schema + index template + custody enrichment | E2E test: one event from a known EVTX produces the documented fields including `kronos.evidence_sha256` |
| M3.4 | evtx-rs fast-path for `.evtx` + Plaso fallback | Throughput test: 500 MB DC security log parses ≥ 5× faster than Plaso-only baseline |
| M3.5 | Idempotent OpenSearch bulk ingester (deterministic `_id`, retries) | Re-run after partial failure produces zero duplicates in the index |
| M3.6 | Text-log header-aware splitter + chunked indexing | 1 GB synthetic NDJSON parses across N workers without losing the header |
| M3.7 | UTC + DST-fold handling (dateutil) | Unit tests on CET fall-back day cover both fold values |
| M3.8 | SRUM "heavy" queue with 4 GB cgroup + OOM-as-ERROR | Forced OOM on SRUM fixture lands in `ERROR`, no worker restart |

Each milestone lands as its own PR referencing issue #3.

---

## 6. Open questions for the reviewer

1. **Timesketch vs OpenSearch Dashboards** — confirm Dashboards + ECS for v1, with Timesketch deferred to v2? (Affects schema.)
2. **OCSF compatibility layer** — should we emit OCSF as a *secondary* serialisation (e.g. for export) or leave it out of v1?
3. **evtx-rs binding** — accept the operational cost of a Rust binary in the parse container, or stay Plaso-only for v1?
4. **Memory ceilings** — confirm 2 GB default and 4 GB heavy ceilings (drives node sizing).
5. **Maximum parse wall-time** — set the orphan-sweeper to 6 h, or a different ceiling per artefact size?
6. **Custom parsers (CloudTrail, GCP, Azure)** — in-scope for v1 or v2? They are the most "log-shaped" but also the most format-volatile.

---

## 7. Next-day plan

Tomorrow's review should target **Part 4 — Workflows and User Experience**. The ECS-shaped events defined here, the case-scoped index pattern from §1, and the `evidence` FSM from §2 are the inputs §4 has to design the UI around.

---

## References

[^plaso-output]: [plaso.output package — Plaso 20260512 docs](https://plaso.readthedocs.io/en/latest/sources/api/plaso.output.html)
[^plaso-os-ts]: [plaso.output.opensearch_ts module — Plaso docs](https://plaso.readthedocs.io/en/latest/_modules/plaso/output/opensearch_ts.html)
[^plaso-parsers]: [Parsers — Plaso 20260512 docs](https://plaso.readthedocs.io/en/latest/sources/user/Parsers-and-plugins.html)
[^plaso-mem]: [Multi-Processing and Performance — Plaso DeepWiki](https://deepwiki.com/log2timeline/plaso/6.1-multi-processing-and-performance)
[^plaso-srum]: [SRUM parser causes worker to exceed memory limit — log2timeline/plaso#3444](https://github.com/log2timeline/plaso/issues/3444)
[^evtx-rs]: [omerbenamram/evtx — Fast (and safe) EVTX parser](https://github.com/omerbenamram/evtx)
[^ecs]: [Elastic Common Schema (ECS) Reference](https://www.elastic.co/docs/reference/ecs)
[^ocsf-splunk]: [The OCSF: Open Cybersecurity Schema Framework — Splunk](https://www.splunk.com/en_us/blog/learn/open-cybersecurity-schema-framework-ocsf.html)
[^ocsf-site]: [Welcome to OCSF](https://ocsf.io/)
[^celery-canvas]: [Canvas: Designing Work-flows — Celery 5.6 docs](https://docs.celeryq.dev/en/stable/userguide/canvas.html)
[^dateutil-tz]: [tz — dateutil 3.9 docs](https://dateutil.readthedocs.io/en/stable/tz.html)
