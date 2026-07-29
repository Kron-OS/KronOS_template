# Fix: evidence status never updated live in the UI (SSE silently did nothing)

**User's request**: "make the frontend update more regularly when we have
uploaded a file to update ingestion status" — while investigating a real
`forensic2.E01` upload, the user had to keep querying the API/reloading the
page to see current status, instead of it updating on its own.

## Root cause: two compounding bugs, found by reading backend + frontend together

Read `src/external/routes/sse.py` (the real event-generator) side by side
with `frontend/src/hooks/useEvidenceSSE.ts` (the real consumer):

1. **Wrong event listener API.** The backend always sends *named* SSE
   frames: `event: status\ndata: ...`, `event: ping`, `event: done`. The
   frontend registered `es.onmessage = ...`. Per the SSE/EventSource spec,
   `onmessage` is shorthand for `addEventListener('message', ...)` and is
   **never invoked** for a frame carrying an explicit event name other than
   `message`. The connection opened fine (no error, so the polling fallback
   never kicked in either) — it just silently received zero events, forever.
2. **Field-name mismatch, would have broken it anyway.** The backend sent
   `{"evidence_id": ..., "state": ...}` (snake_case); the frontend's
   `SSEStatusEvent` type expected `{"evidenceId": ..., "status": ...}`
   (camelCase, different key). Even with the listener fixed, `'status' in
   event` would always be `false` and `event.evidenceId` would be
   `undefined`, so no row would ever match.
3. **Partial-patch gap** (found while fixing #1/#2): the one place that
   *did* handle an SSE payload only patched the `state` field via
   `setQueryData`, leaving `errorReason`/`retryAction`/`sha256`/etc. stale
   until an unrelated refetch (window refocus, remount, or a manual
   reload) happened to occur.

Net effect: the SSE push path had never worked end-to-end. The only way
status ever updated was a full page reload, or an incidental React Query
refetch (`staleTime: 15_000` plus a refocus/remount trigger) — which
matches exactly what the user experienced.

## The fix

- `src/external/routes/sse.py`: payload key renamed `evidence_id` →
  `evidenceId` to match the frontend's field-naming convention (same
  pattern every other DTO in this codebase already follows).
- `frontend/src/types/index.ts`: `SSEStatusEvent.status` renamed to
  `state` (matches `Evidence.state`/`EvidenceOut.state` elsewhere); removed
  the dead, never-emitted `SSEErrorEvent` type.
- `frontend/src/hooks/useEvidenceSSE.ts`: `es.onmessage` replaced with
  `es.addEventListener('status', ...)`; added `es.addEventListener('done', ...)`
  to close the stream cleanly when all evidence reaches a terminal state,
  instead of letting the browser's automatic-reconnect hit the (already
  one-shot-consumed) ticket, 401, and spin up an unneeded polling fallback.
- `frontend/src/pages/CaseDetailPage.tsx`: `handleSSEEvent` now both
  optimistically patches `state` (instant pill flip) **and**
  `invalidateQueries` on every status event, so the full row (error
  reason, retry action, hashes, etc.) refreshes immediately, not just the
  status word.

## Verified, for real

`browser_verify.py` (Playwright/Chromium against the real, rebuilt dev
stack): real Keycloak login through the actual login form, a real case
created via the UI, a real file uploaded via the UI's own drawer — then,
**without reloading the page**, the Status cell in the evidence table was
polled every 500 ms from the test script (not from the app, which now
updates on its own via the live `EventSource`). 5/5 checks
(`output.txt`):

1. Real login lands on `/cases`.
2. Real case created via the UI.
3. Real file uploaded via the UI, finalize accepted.
4. **The status pill changed on its own, without a reload**: observed
   sequence `['Uploading', 'Complete']`.
5. Evidence reached `Complete` live.

Screenshot: `browser_live_status_update.png`.

Backend: 7/7 `test_sse_routes.py` tests still pass (one pre-existing slow
test in that file takes ~300s for an empty case with no evidence — a
5-minute stream-loop with no early exit condition for zero evidence items;
unrelated to this fix, not touched). Full unit suite: no regressions
(confirmed separately).

## Not yet done / out of scope

- The pre-existing ~300s `test_valid_ticket_consumed_once` slow test
  (`tests/unit/test_sse_routes.py`) wasn't sped up — out of scope for this
  fix, flagged as a known slow test, not a bug.
- Backend poll interval (5s) was left unchanged — the defect was "the
  frontend never received any push events at all," not "the interval is
  too slow." Once actually delivered, a 5s cadence is reasonably prompt.
