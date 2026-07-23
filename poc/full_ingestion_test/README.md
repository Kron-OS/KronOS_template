# full_ingestion_test — real end-to-end ingestion on the live dev stack

**Goal:** not a new integration PoC in the CLAUDE.md §F sense (no new
component pair is being designed here) — this is a real, full end-to-end
regression pass over the *already-shipped* pipeline: login → case creation →
evidence upload/finalize → autonomous parse pipeline → OpenSearch query,
run against the actual `docker/docker-compose.dev.yml` stack (fresh
`down -v` + `up -d`, all 18 services), not a hand-picked subset.

## What this covers

One real sample per `ParserRegistry`-registered parser
(`src/external/dependencies.py:178-197`, registration order):

| Parser | Sample | Source |
|---|---|---|
| `cloudtrail` | `aws_cloudtrail.jsonl` | Plaso's own test corpus (`tests/fixtures/samples/real/`) |
| `nginx` | `apache_access.log` | Plaso's own test corpus |
| `chrome-history` | `History` | Hand-built here (real Chrome/Chromium schema: `urls`+`visits` tables, real WebKit-epoch timestamps) — no real Chrome History sample existed anywhere in the repo |
| `evtx-rs` (fast) | `system.evtx` | Plaso's own test corpus |
| `plaso` (heavy) | `CMD.EXE-087B4001.pf` | Plaso's own test corpus (real uncompressed Windows 10 Prefetch) |

## How to run

```
docker compose -f docker/docker-compose.dev.yml -p kronos-dev up -d
/home/reca/venv/bin/python3 poc/full_ingestion_test/login.py             # sanity: real PKCE login
/home/reca/venv/bin/python3 poc/full_ingestion_test/run_ingest.py        # creates a case, uploads+finalizes all 5
# ... poll GET /api/cases/{case_id}/evidence until every item's state is COMPLETE ...
/home/reca/venv/bin/python3 poc/full_ingestion_test/fetch_documents.py   # pull real docs -> file + verify
```

`fetch_documents.py` queries OpenSearch directly at
`kronos-{org_alias}-case-{case_id}-*` (a wildcard, not one index — event
timestamps span real historical dates so records land in whichever monthly
index each event's own `@timestamp` maps to), reading `case_id` from
`evidence_ids.json` (written by `run_ingest.py`) unless passed explicitly.

## Verifying real content, not just doc counts (`fetch_documents.py`)

The `kronos.parser` terms aggregation used earlier in this pass (see below)
proves documents *exist* per parser, but a document existing is not the same
as it having parsed correctly. A parser can emit a failure marker that
still counts as a normal document: e.g. `docker/plaso/kronos-plaso-worker.py`
falls back to a `data_type: "plaso:placeholder"` event with message
`"Plaso: no events extracted from ..."` whenever real extraction produces
nothing (Plaso not installed, or a genuine extraction failure) — that would
pass the aggregation check with a healthy-looking count while silently
carrying zero real forensic content.

`fetch_documents.py` closes that gap: it pulls every real document for the
case (`_source` included, not just the aggregation), writes them to
`documents.json`, and scans each doc's normalized `message`/`data_type`
fields (deliberately *not* raw `event.original` — real CloudTrail/nginx
content legitimately contains the word "error", e.g. AWS `errorCode`/HTTP
status codes, which would false-positive if the raw text were scanned) for
known failure markers (`plaso:placeholder`, "no events extracted", "parsing
error", "parse error"). Results — the full per-parser doc-count breakdown,
the flagged list, and a `PASS`/`FAIL` verdict — are written to
`ingestion_verification.json` for repeatable, file-based verification
instead of an ad hoc query each time.

## Real bug found and fixed

`src/application/validation.py`'s `MagicByteValidator._MAGIC_TABLE` only
recognized MAM-*compressed* Prefetch (`MAM\x04` at offset 0). The real
sample above is uncompressed (`SCCA` at offset 4) — a format
`PlasoParser.supports()` (`src/external/parsers/plaso.py`) already
explicitly accepts, with its own comment noting real-world Prefetch is
frequently uncompressed. Result: `finalize_upload` rejected the file with a
422 before the parser ever ran. This is exactly the class of bug CLAUDE.md
§F exists to catch — a parser-level unit test would never exercise the
shared upload-validation path at all. Fixed by adding
`(4, b"SCCA", "prefetch-scca")` to `_MAGIC_TABLE`.

## Captured output (real run, 2026-07-23)

Login (`login.py` claims, case-lead):
```
mfa_path=none
token claims: {
  "iss": "http://localhost:8080/realms/kronos",
  "aud": "kronos-backend",
  "sub": "10000000-0000-4000-8000-000000000003",
  "acr": "aal1",
  "org_id": "f541df34-91f6-45cb-b763-ba4c6e441700",
  "organization": {"kronos-dev": {"id": "f541df34-91f6-45cb-b763-ba4c6e441700"}},
  "roles": ["case-lead"]
}
```

Ingestion (`run_ingest.py`, after the validator fix — all 5 finalize 200):
```
create_case -> 201 {"id":"8f2057bf-1821-4a8c-a810-dcbf4497818e", ...}
cloudtrail finalize -> 200 {"state":"RECEIV...
nginx finalize -> 200 {"state":"RECEIV...
chrome-history finalize -> 200 {"state":"RECE...
evtx-rs finalize -> 200 {"stat...
plaso finalize -> 200 {"id":"aa726919-6bb2-4600-908d-01bcae619748", ...}
```

Poll to completion (`GET /api/cases/{id}/evidence`, states by filename):
```
{'aws_cloudtrail.jsonl': 'COMPLETE', 'apache_access.log': 'PARSING',   'History': 'COMPLETE', 'system.evtx': 'PARSING', 'CMD.EXE-087B4001.pf': 'COMPLETE'}
... (5 polls, 5s apart) ...
{'aws_cloudtrail.jsonl': 'COMPLETE', 'apache_access.log': 'COMPLETE', 'History': 'COMPLETE', 'system.evtx': 'COMPLETE', 'CMD.EXE-087B4001.pf': 'COMPLETE'}
```

Real OpenSearch query (`_cat/indices` — records span 9 real monthly
indices, confirming forensic event-time is preserved, not overwritten with
ingest time):
```
kronos-kronos-dev-case-...-201303   2 docs
kronos-kronos-dev-case-...-201601   5 docs
kronos-kronos-dev-case-...-202104   2 docs
kronos-kronos-dev-case-...-202202   6 docs
kronos-kronos-dev-case-...-201508 194 docs
kronos-kronos-dev-case-...-202607   6 docs
kronos-kronos-dev-case-...-201505   3 docs
kronos-kronos-dev-case-...-201801   4 docs
kronos-kronos-dev-case-...-201911   1 docs
```

`kronos.parser` terms aggregation across all 9 indices (223 total docs):
```json
{
  "hits": {"total": {"value": 223}},
  "aggregations": {"by_parser": {"buckets": [
    {"key": "evtx-rs", "doc_count": 194},
    {"key": "nginx", "doc_count": 15},
    {"key": "cloudtrail", "doc_count": 6},
    {"key": "plaso", "doc_count": 5},
    {"key": "chrome-history", "doc_count": 3}
  ]}}
}
```

`kronos.org_id`/`kronos.case_id` aggregations: single bucket each, 223/223
docs, matching the real case ID and the real `kronos-dev` org ID — no
cross-tenant leakage.

Per-parser sample document spot-checks confirmed real, not stubbed, output:
`evtx-rs` yielded a real Windows Security-Auditing event (EventID 4608);
`nginx` a real parsed access-log line (`GET / 200`, real `user.name`/
`source.ip`); `cloudtrail` the real `DescribeInstances` API call event;
`chrome-history` the exact 3 crafted visit rows with correct
`chrome.page_transition`/`visit_count`; `plaso` a genuine Plaso `fs:stat`
`AttributeContainer` (proves `FirecrackerLauncher`'s subprocess path
(`src/external/sandbox/firecracker.py`) actually invokes real Plaso inside
the `celery-worker-plaso` container, not a mock).

## Captured output — `fetch_documents.py` (real run, 2026-07-23, new case)

A second fresh pass (new case, same 5 samples) exercising the full flow
including the new document-fetch step:

```
by parser: {'chrome-history': 3, 'cloudtrail': 6, 'evtx-rs': 194, 'nginx': 15, 'plaso': 5}
flagged as parsing-error/placeholder markers: 0
wrote .../poc/full_ingestion_test/documents.json (223 docs)
wrote .../poc/full_ingestion_test/ingestion_verification.json -- verdict: PASS
```

`documents.json` holds the full real `_source` for all 223 documents (not
just the aggregation); `ingestion_verification.json` holds the summary
(`total_documents`, `by_parser`, `flagged_parsing_errors`, `verdict`) for
repeatable review without re-querying OpenSearch. Spot-checked the 5 real
`plaso` documents in `documents.json` directly: `windows:prefetch:execution`,
`windows:volume:creation`, and 3× `fs:stat` — genuine Plaso `data_type`
values, not the `plaso:placeholder` failure marker, confirming this run's
Plaso extraction genuinely succeeded (full `output.txt` has the complete
captured run).

The flagging logic itself was sanity-checked against synthetic docs (not
just the real, currently-clean run) to confirm it actually fires: a
`{"data_type": "plaso:placeholder", "message": "Plaso: no events extracted from /tmp/x"}`
doc is correctly flagged, while a `cloudtrail` doc whose message legitimately
contains "errorCode" is correctly left unflagged (see `fetch_documents.py`'s
`_ERROR_MARKERS` — narrow, specific phrases, not a bare "error" substring).
