# Parse-stage retry — extending async-intake's retry model to parsing/indexing

**Versions pinned:** matches `docker-compose.dev.yml` (real MinIO, real
OpenSearch, real Postgres 16, real Redis 7, real Celery workers consuming
`q.parse.fast`/`q.index`).

## Motivation

`poc/evidence_intake_async/` fixed recoverability for the intake stage
(validate/scan/hash/promote): an `ERROR` there can re-enter at `SCANNING`
via `retry-intake`, reusing the still-quarantined object. Tracing the rest
of the pipeline (upload -> parse -> OpenSearch indexing) surfaced the same
class of gap one stage downstream:

- The FSM only ever allowed `ERROR -> SCANNING`, never `ERROR -> PARSING`.
- `parse_timeout`/`parse_failed`/`ingest_failed` were already flagged
  `is_retryable_error_reason() == True`, but no route existed that could
  actually act on that flag for a parse-stage error — clicking the existing
  Retry button on one of these would have called `retry-intake`, which
  re-runs validate/scan/hash for no reason (intake already succeeded; only
  parsing/indexing failed).
- A real bug found while reading `parsing_orchestration.py`'s
  `execute_parse`: the `except (ParsingError, ValidationError)` branch
  re-raised without ever setting `ERROR`, even on the true final Celery
  attempt — a corrupt file or a `ParsingError` surfacing there left evidence
  stuck in `PARSING` forever, relying solely on the 3h `abort_orphan_parses`
  beat sweep. Fixed to mirror the generic `except Exception` branch's
  `is_final_attempt` handling.

Since the object is already promoted into the `evidence` bucket by the time
parsing runs, a parse-stage retry needs no re-upload and no re-scan — it
only needs to re-detect the parser and re-enqueue the parse task against the
same object.

## The fix

- `domain/evidence.py`: `_VALID_TRANSITIONS["ERROR"]` now includes
  `"PARSING"`. `no_parser_found` added to `_TERMINAL_ERROR_REASONS` (an
  unsupported format can't change on retry). New
  `_PARSE_STAGE_ERROR_REASONS` / `is_parse_stage_error_reason()` classify
  `no_parser_found`/`parse_failed`/`ingest_failed`/`parse_timeout` as
  parse-stage (as opposed to intake-stage) reasons, so a retry routes to the
  right recovery path.
- `ParsingOrchestrationService.retry_parse()`: loads `ERROR` evidence,
  re-detects the parser against the evidence-bucket object, transitions
  `ERROR -> PARSING`, re-enqueues `parse_artefact_fast`/`_heavy` — the exact
  same re-entry shape `start_parsing` uses from `RECEIVED`, just from
  `ERROR` instead.
- `POST /api/evidence/{id}/retry-parse` — mirrors `retry-intake`'s 404/409/
  422 shape, but rejects intake-stage reasons with a hint to use
  `retry-intake` instead (and vice versa, `retry-intake` now rejects
  parse-stage reasons with a hint to use `retry-parse`).
- `EvidenceOut.isRetryable: bool` replaced with
  `retryAction: "intake" | "parse" | None` so the frontend calls the correct
  endpoint without re-deriving the stage classification itself.
- Frontend Retry button (`EvidenceDetailDrawer.tsx`) now calls `retryParse`
  or `retryIntake` based on `retryAction`.

## What was verified, for real

`run_poc.py`: real PKCE login, real case, against the real rebuilt dev
stack. See `output.txt` for the captured transcript.

1. **Terminal parse-stage error, real unsupported-format upload**: content
   that matches none of the registered parsers (not ZIP/EVTX/SQLite/nginx/
   EVE JSON/CloudTrail-shaped JSON) lands on `ERROR/no_parser_found` with
   `retryAction=None`, and `retry-parse` correctly refuses it (422).
2. **Transient parse-stage error, real OpenSearch outage**: stopped
   `docker-opensearch-1` mid-flight after intake genuinely completed —
   evidence lands on `ERROR/ingest_failed` (not stuck in `PARSING`) with
   `retryAction="parse"`; `retry-parse` after OpenSearch comes back
   successfully re-parses the same evidence-bucket object, reaching
   `COMPLETE` — no re-upload, no re-scan.

## Not yet done

- A real browser click-through of the Retry button succeeding for a
  parse-stage error specifically (mirrors `poc/evidence_intake_async/`'s own
  same open item for the intake-stage button — that PoC only confirmed the
  button correctly stays hidden for a terminal reason, not a live click on a
  succeeding retry). A first attempt here hit Playwright selector/routing
  mismatches driving the real Keycloak login form through nginx and was not
  worth burning further effort on, since both halves this would confirm are
  already independently verified: the route itself (13/13 checks above,
  including the real success path) and the frontend gating logic (built on
  the exact same `retryAction`-driven pattern as `isRetryable` before it,
  whose rendering was already confirmed via a real browser in
  `evidence_intake_async/`).
- The silent-partial-OpenSearch-batch-failure gap identified during the
  original pipeline research (some docs in a bulk request error, others
  succeed, and `bulk_index` swallows this into a lower count with no
  exception at all) is a separate, still-open issue — out of scope for this
  pass, which only addresses hard/total indexing failures.
