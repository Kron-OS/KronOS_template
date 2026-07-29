# Ingestion Pipeline Audit — 2026-07

Scope: the evidence ingestion pipeline **from the moment the parser layer
receives a file's bytes to the moment records are ready for OpenSearch**.
Method: mapped the data flow, drove every stage end-to-end against real
sample files, verified the *contents* of the resulting documents, root-caused
each defect, fixed it, and locked it with a real-path regression test.

---

## 1. Logical schema of the pipeline

```
        ┌──────────────── autonomous, server-side only ────────────────┐
        │                                                              │
 upload/finalize ─► _promote() ─► enqueue dispatch_parse (q.index)
        │
        ▼
 dispatch_parse ─► start_parsing()                     [RECEIVED ─► PARSING]
        │              │
        │              ├─ _detect_parser(): read first 8 KB
        │              │     └─ ParserRegistry.get_parser(filename, ctype, header)
        │              │           first parser whose supports() is True wins
        │              └─ enqueue parse_artefact_fast | parse_artefact_heavy
        ▼
 parse_artefact_(fast|heavy) ─► execute_parse()        [PARSING ─► COMPLETE/ERROR]
        │
        ├─ reconcile tenant.org_alias  ◄── evidence.metadata (authoritative)
        ├─ _detect_parser()  (again, over the evidence bucket)
        ├─ parser.parse(stream, evidence, tenant)  ── AsyncIterator[TimelineRecord]
        │     FAST: in-process (nginx, cloudtrail, evtx-rs, chrome-history)
        │     HEAVY: FirecrackerLauncher ─► kronos-plaso-worker.py (subprocess)
        │             worker: log2timeline.py ─► psort.py -o json_line ─► JSONL
        ├─ _annotate_records(): stamp document_id (SHA1 evidence:parser:idx)
        │                       + org_alias
        └─ TimelineIngestionService.ingest_records()
              ├─ ensure_ism_policy (idempotent, tolerates 409)
              ├─ build_index_name(org_alias, case_id, @timestamp)
              │     └─ kronos-<org>-case-<case_id>-<yyyymm>
              ├─ ECSNormalizer.to_document(): flat ECS ─► nested + kronos.*
              └─ bulk_index(batch)  ─► OpenSearch
```

Object transformations:

| Stage | In | Out |
|---|---|---|
| detection | filename, content_type, first 8 KB | a `ForensicParser` (or `None` → ERROR) |
| parse | byte stream + `Evidence` | `AsyncIterator[TimelineRecord]` (ECS-flat + `kronos.*`) |
| annotate | `TimelineRecord` | same + deterministic `document_id`, reconciled `org_alias` |
| normalize | `TimelineRecord` | nested-ECS `dict` (dotted `extra` keys expanded, `None` pruned) |
| route | record `@timestamp` + case_id + org_alias | monthly per-tenant index name |

Design invariants confirmed sound: parser selection is polymorphic
(`supports()`, first-match-wins — no if/elif chains); every record carries a
full `kronos.*` provenance block; `document_id` is deterministic so a Celery
retry re-indexes idempotently; the pipeline is fully server-driven after
finalize.

---

## 2. Findings and remediations

Ordered by severity. All fixed this pass unless marked otherwise.

### F1 — nginx detection anchored to byte 0 (recurring "No parser found")  ✅
`supports()` used a regex anchored to the file's first byte, so any leading
blank line, operator annotation, or W3C/IIS `#Fields:` header rejected the
whole file — the reported `access.log` failure. Also, detection and parsing
used **two separate regexes** that had to be hand-kept in sync and had drifted.
**Fix:** one canonical line regex, used by both; detection scans up to 50
leading content lines, skipping BOM/blank/comment lines. "Detected" now
strictly implies "parseable."

### F2 — Chrome/Chromium History produced no data  ✅
A `History` SQLite DB matched only the generic SQLite branch of Plaso and
dead-ended at the `plaso:placeholder` stub (seen in the user's OpenSearch
export). **Fix:** native `ChromeHistoryParser` (stdlib `sqlite3`, FAST,
read-only+immutable open) yielding one ECS record per visit with correct
WebKit-epoch timestamp conversion; registered before Plaso; other SQLite still
falls through. Fully verified end-to-end.

### F3 — Plaso worker could never emit events  ✅ (code) / ⚠️ (live-unverifiable)
`_run_plaso` misused Plaso's internal API (log2timeline given a bogus
`output_module`, `parsers=""` selecting nothing, reading raw EventObjects that
have no `.message`). Every Plaso artifact produced only the placeholder.
**Fix:** driven through Plaso's stable CLI (`log2timeline.py` → `psort.py -o
json_line`), which applies formatters so events carry real messages; argv-only
(no shell), bounded timeouts, temp cleanup, honest placeholder fallback with a
logged reason. Live extraction can't run in this sandbox (Plaso not installed);
verified at the two testable boundaries (worker placeholder path + launcher
JSONL→record mapping).

### F4 — all evidence indexed under `kronos-system-case-*`  ✅
The Celery task tenant carries no `org_alias`, so it defaulted to `"system"`,
which named the per-tenant index and DLS role — collapsing every org into one
`system` namespace and breaking the `kronos-<org>-*` DLS pattern. **Fix:**
`execute_parse` reconciles `org_alias` from the authoritative, immutable
evidence metadata (org already matched via `get_by_id(org_id)`, so no
cross-tenant risk).

### F5 — retry of a failed parse was permanently doomed  ✅ (earlier commit)
`execute_parse` marked evidence terminal-ERROR on any failure, so a Celery
retry immediately failed its own `state == PARSING` precondition. Fixed via
`is_final_attempt` so only the last retry makes ERROR terminal.

### F6 — Plaso worker stderr swallowed on clean exit  ✅ (earlier commit)
Diagnostic was only read on non-zero exit, but the worker always exits 0 (even
on stub fallback). Now surfaced on every run.

### Observations (not defects)
- `DE_RDP_Tunnel_5156.zip` → ERROR is expected: no archive extractor yet
  (Track C1 in the ingestion roadmap).
- FAST parsers buffer the whole file to memory/temp (evtx, cloudtrail,
  chrome-history). Acceptable at current sizes; streaming is a future item for
  very large artifacts.

---

## 3. Verified output (contents, not counts)

Driven through the real path (`registry.get_parser → parse → _annotate_records
→ ECSNormalizer.to_document → build_index_name`), asserting document contents —
see `tests/unit/test_pipeline_end_to_end.py`:

| Parser | Real sample | Records | Verified fields |
|---|---|---|---|
| nginx | apache_access.log | 15 | source.ip, url.path, http.*, category=web |
| cloudtrail | aws_cloudtrail.jsonl | 6 | cloud.service, user.name, action, ts=2022 |
| evtx-rs | system.evtx | 194 | event.module=windows, event.code, host.name |
| chrome-history | constructed real DB | per-visit | url.full/domain, WebKit ts, transition |
| plaso (heavy) | — | — | mapping verified at launcher boundary |

Every document also satisfies: non-empty `@timestamp`, 40-hex deterministic
`_id`, `kronos-<org>-case-…` index, and a fully populated `kronos.*` block.

---

## 4. Adding a new parser (extensibility)

The framework makes this a three-step, zero-orchestration-change operation —
`ChromeHistoryParser` is the worked example:

1. Subclass `ForensicParser`; implement `parser_name/version/type`,
   `supports(filename, content_type, header_bytes)`, and
   `async def parse(...) -> AsyncIterator[TimelineRecord]` yielding ECS-flat
   records with a full `kronos.*` block.
2. `registry.register(...)` in `get_parser_registry()` — order matters only for
   overlapping `supports()` (register the specific parser before the general
   one, as Chrome History precedes Plaso).
3. Add a real-sample test through the end-to-end path.

No changes to `execute_parse`, the registry, ingest, or normalization are ever
required.
