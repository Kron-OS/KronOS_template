# Async evidence intake + retry — confirming and fixing the reported bug

**Versions pinned:** matches `docker-compose.dev.yml` (real MinIO, real
ClamAV `clamav/clamav:stable`, real Postgres 16, real Redis 7, real Celery
worker consuming the new `q.intake` queue).

## The reported hypothesis, confirmed

"Finalize is triggered by the client — if the file hasn't been fully
received, or the antivirus scan hasn't terminated, it could crash."

Traced the exact code path: `EvidenceIntakeService.finalize_upload()` ran
validate→scan→hash→promote **synchronously inside the client's HTTP
request**, after already committing the `SCANNING` state transition. Only
`ValidationError` was caught around those steps — any other exception
(a `StorageError` from an object not yet visible in MinIO, a ClamAV
connectivity blip, anything unanticipated) propagated uncaught. The route
turned it into a clean-looking 500, but **the evidence row was already
stuck in `SCANNING`/`HASHING` in the database, with no beat task sweeping
those states and no way to retry** (`finalize_upload` hard-required
`state == UPLOADING`). Confirmed real and worse than described: this
wasn't limited to "not fully received" — any transient failure during
scan/hash/promote hit the same dead end.

## The fix

Split `finalize_upload` into:
- **`start_intake`** (client-facing, fast): checks the object genuinely
  exists in MinIO (`storage.object_exists`, a HEAD not a GET) *before*
  touching any state, then enqueues `kronos.process_intake` (Celery,
  `q.intake`) and returns. A premature call now fails fast and cleanly
  with **no state change at all** — the client can just call finalize
  again once the real upload lands.
- **`process_intake`** (runs from Celery, off the request thread):
  validate→scan→hash→promote, with a broad `except Exception` that always
  lands on `ERROR` with a categorized reason instead of orphaning
  evidence — the actual bug fix. `ERROR -> SCANNING` is now a real,
  FSM-enforced transition (`domain/evidence.py`) so a retry can re-enter
  the pipeline.
- **Retryable vs. terminal reasons** (`is_retryable_error_reason()`):
  `validation_failed`/`size_limit_exceeded`/`hash_mismatch`/`infected:*`
  are terminal (retrying the same bytes can never change the verdict);
  everything else (storage/scanner connectivity, `intake_timeout`, any
  other unanticipated exception) is retryable by default.
- **`POST /api/evidence/{id}/retry-intake`** + a frontend Retry button
  (`EvidenceDetailDrawer.tsx`), gated on the new `isRetryable` field,
  re-enqueuing `process_intake` against the still-quarantined object — no
  re-upload needed.
- **`abort_orphan_intake`** beat task (hourly): sweeps evidence stuck in
  `SCANNING`/`HASHING` >30 min, defense-in-depth for a worker crash that
  raises no catchable exception at all.

## What was verified, for real

`run_poc.py`: real PKCE login, real case, against the real rebuilt dev
stack. **14/14 checks passed** (`output.txt`):

1. **The exact reported scenario**: calling finalize before the real PUT
   lands on MinIO → clean 422, evidence stays `UPLOADING` (never touched).
   Uploading for real and calling finalize again → 202, autonomous
   pipeline carries it all the way to `COMPLETE` on its own.
2. **Terminal error, real EICAR upload**: real ClamAV detects
   `Eicar-Test-Signature`, evidence lands on `ERROR`,
   `isRetryable=false`, and `retry-intake` correctly refuses it (422).
3. **Transient error, real ClamAV outage**: stopped `docker-clamav-1`
   mid-flight — evidence lands on `ERROR` (not orphaned in `SCANNING`)
   with a retryable reason (`intake_failed:StorageError`);
   `retry-intake` after ClamAV comes back succeeds, reaching `COMPLETE`.

## Real bugs found and fixed along the way

1. **A genuine, pre-existing gap, not something this session introduced**:
   `CLAMD_HOST` was never set for *any* service in
   `docker-compose.dev.yml`, so every container defaulted to
   `src/config.py`'s `clamd_host="localhost"` — wrong for a multi-container
   Compose stack. `configure_clamav_from_settings()`'s dev-mode fallback
   silently downgraded to the permissive `NoOpScanner` instead of erroring
   — meaning **real uploads through the actual dev-compose stack were
   never ClamAV-scanned at all**, only the isolated `poc/clamav/`
   container (with its own correct env) ever exercised real detection.
   Confirmed by a real EICAR upload silently passing scan and failing
   later at parsing instead (`no_parser_found`) before this fix. Fixed in
   both `docker-compose.dev.yml` and `docker-compose.prod.yml` (prod's
   `celery-worker` was missing it even though `kronos-backend` had it —
   would have been a loud startup crash there per the production hard-fail
   path, not silent, but still broken). **Not fixed**: the Helm chart has
   no `CLAMD_HOST` wiring anywhere for any deployment — flagged as a
   follow-up, out of scope for this pass.
2. Two bugs in this PoC's own script (not the feature): raw `httpx.put()`
   calls didn't trust the dev stack's step-ca cert; `poll_evidence()`
   returned as soon as it saw *any* non-`UPLOADING`/`SCANNING`/`HASHING`
   state — including a transient `ERROR` that Celery's own automatic retry
   would still resolve — reporting a false failure for a retry that just
   hadn't happened yet. Fixed with a `stop_on_error` parameter.

## Real browser confirmation of the frontend Retry button

Logged in as `case-lead`, opened the EICAR evidence item created by this
PoC's own real run — `browser_verification_no_retry_for_terminal_error.png`:
status pill shows `Error`, the error reason `infected:Eicar-Test-Signature`
is displayed, and **no Retry button renders** — confirmed via `isRetryable`
gating working correctly with real API data end-to-end. The evidence list
also shows both real `cloudtrail.json` uploads reaching `Complete` on
their own, confirming the autonomous pipeline held together throughout.

## Not yet done

- Helm chart ClamAV wiring (see finding #1 above).
- A real browser click-through of the Retry button *succeeding* (i.e. for
  a retryable-reason item) — the backend route it calls is the same one
  this PoC already exercises directly and confirms works; the "button is
  correctly hidden for a terminal reason" half is confirmed above.
