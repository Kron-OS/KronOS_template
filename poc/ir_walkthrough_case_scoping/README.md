# PoC: full IR walkthrough -- does `kronos-attest case-report` see containment/SIEM-sync activity?

**Task context:** post-Milestone-II full multi-angle assessment (the second
full assessment `docs/GAP_AUDIT_2026-08-21_MILESTONE_II.md` itself
recommended), incident-response-walkthrough angle. Walks a real analyst
scenario end to end -- detection fires -> analyst investigates/triages ->
contains (real Keycloak session revocation) -> notifies SIEM -> an auditor
runs `kronos-attest case-report` offline -- through the real, unmodified
routes/CLI, looking specifically for places two independently-solid
features (H2's containment action, roadmap Milestone W's SIEM-sync action,
both already deeply verified individually per `docs/GAP_AUDIT_2026-08-19_MILESTONE_EE.md`)
interact badly.

## Versions / real dependencies (CLAUDE.md SS F.2 step 1)

- Keycloak 26.2.5 (`quay.io/keycloak/keycloak:26.2`, `docker-keycloak-1`,
  already running) -- real Authorization Code + PKCE login for the
  `analyst` dev user, real Admin API session list/revoke.
- Postgres 16 (`postgres:16-alpine`), but a **fresh, throwaway
  `kronos-poc-ir-postgres` container** (port 15433), not the shared
  `docker-postgres-1` -- mirrors `poc/evidence_download/`'s own precedent
  of avoiding that database's separately-tracked schema drift, since this
  PoC only needs Case/Detection/AuditLog tables freshly created from
  current metadata.
- `kronos-attest` CLI run as a real subprocess (`python -m kronos_attest.cli
  case-report`), against a real JSON export produced by the real
  `GET /api/audit/export` route.
- A real local `ThreadingHTTPServer` standing in for a configured SIEM sink
  (`HttpJsonIntegrationSink` + a generic, non-vendor-specific mapper,
  mirroring `poc/integration_sink_foundation/`'s own `HecJsonHandler`
  pattern) -- the named-vendor sinks (Splunk HEC/Sentinel/CEF) already have
  their own dedicated, real PoCs; this run's focus is what happens
  downstream of a successful push, not re-proving vendor wire formats.
- `httpx.ASGITransport` against the real, unmodified `create_app()` --
  the same in-process idiom `poc/evidence_download/` and
  `poc/revoke_session_route/` already established (FastAPI's own
  `TestClient` is incompatible with an async SQLAlchemy engine created in
  this coroutine's own loop).

## Real friction hit while running this (not fabricated)

The dev stack's nginx/step-ca leaf cert had already expired (valid only
through 2026-08-19 23:08 UTC; this PoC ran on 2026-08-21) -- the same
recurring friction `docs/NEXTGEN_SOC_ROADMAP.md` SS5 documents and every
prior PoC touching a real Keycloak browser login has hit. Fixed via the
documented remedy (`docker compose -f docker/docker-compose.dev.yml up -d
tls-init && docker restart docker-nginx-1`) before the login step; verified
via a direct `openssl s_client` check before and after (expired ->
`notAfter=Aug 19 23:08:12 2026 GMT`, fixed -> `notAfter=Aug 22 10:22:06
2026 GMT`).

## What this proves (THE FINDING)

1. A real `Case` is created via `POST /api/cases`.
2. A `Detection` is saved (`PostgresDetectionRepository.save()`) with
   `case_id` set to that real case's id -- a real, correct case
   correlation (standing in for `DetectionSyncService`'s own best-effort
   `_extract_case_id`, already separately verified in
   `poc/detection_finding_sync/`; this PoC's own scope starts once a
   correctly-case-scoped `Detection` already exists).
3. The analyst lists/filters (`GET /api/detections?caseId=...`) and gets
   (`GET /api/detections/{id}`) the detection, then triages it
   NEW -> INVESTIGATING -> TRUE_POSITIVE via `POST .../triage`.
4. **Real containment:** the analyst's own real, live Keycloak session
   (obtained via a real PKCE login) is revoked via
   `POST /api/detections/{id}/contain/revoke-session` -- independently
   re-confirmed gone via a fresh Admin API call.
5. **Real SIEM notification:** `POST /api/detections/{id}/sync-to-siem/test_webhook`
   pushes the detection to the real local webhook receiver, which
   genuinely receives it.
6. **The auditor's step:** `GET /api/audit/export` is fetched, saved to a
   temp file, and the real `kronos-attest case-report --audit-log <file>
   --case-id <case_id>` CLI is run as a subprocess.

**Result:** the org's full audit export contains 13 (first run) / 26
(second, cumulative run against the same throwaway DB) real events,
including real `containment.action_attempted`/`containment.action_executed`
and `sink.push_attempted`/`sink.push_executed` rows that reference this
exact `detection_id` inside their own `details.params`/`details
.detection_ids`. **Every single one of them is invisible to
`kronos-attest case-report --case-id <this case>`** -- the report's own
`event_count` is only 3 (case creation + 2 triage transitions) both runs.
Root cause, confirmed by direct reading and now empirically: neither
`ContainmentAction.execute()` (`src/application/containment_action.py`)
nor `DetectionSinkPushService.push()` (`src/application/detection_sink_push.py`)
ever pass `case_id=` to `AuditLogService.log()`, even though the acting
`Detection`'s own `case_id` is known at the call site in the SIEM-sync
case (`SyncDetectionToSiemAction` already has the full `Detection` object)
and is at least available via `detection_id` -> lookup for containment.
`AttestationReport.case_report()` (`kronos_attest/report.py`) filters
strictly on `e.get("case_id") == case_id`, so an event with `case_id: null`
can never appear in any case's report, no matter how directly it relates
to that case's own Detection.

**Contrast, proving this is a specific, fixable omission and not a
platform-wide export bug:** `DetectionTriageService.transition()`
(`src/application/detection_triage.py:62,78`) *does* correctly pass
`case_id=detection.case_id` on every triage audit event -- both of this
run's own triage events show up in the case-report correctly. The same
discipline was simply never applied to the two newer action types built
on top of the generic `PlaybookAction`/`ContainmentAction` abstractions,
which don't have a `Detection` (or its `case_id`) naturally in scope the
same way a Detection-specific service does.

## Run

```
docker run -d --name kronos-poc-ir-postgres -e POSTGRES_DB=kronos \
  -e POSTGRES_USER=kronos -e POSTGRES_PASSWORD=kronos_dev_password \
  -p 15433:5432 postgres:16-alpine
~/venv/bin/python3 poc/ir_walkthrough_case_scoping/run_poc.py
docker stop kronos-poc-ir-postgres && docker rm kronos-poc-ir-postgres
```

Requires the real, shared `docker-keycloak-1` already running and reachable
via `kronos.local:8443` with a non-expired leaf cert.

**21/21 real checks passed** (`output.txt` -- second/idempotency-confirming
run's unedited stdout).

## Scope note (findings-only)

This PoC deliberately does not fix the gap it demonstrates -- it exists
purely to convert a code-reading inference into an empirically confirmed
finding for the review this PoC was written for. See the review's own
written report for severity/priority framing and suggested remediation
shape (passing `case_id` through where it's already available, and
deciding what a Detection-less containment action like session-revocation
should do when no `case_id` is resolvable at all).
