# Gap Audit — Milestone KK (2026-08-21)

Continuation of `docs/GAP_AUDIT_2026-08-21_MILESTONE_JJ.md`'s second
multi-scenario assessment (Task #14, round 2). JJ fixed the most severe
finding (approval-gate resource-mismatch bypass) and documented the
remaining findings from the security, scale/reliability, and
incident-response angles as not-yet-actioned. This milestone closes the
one concrete, high-value finding from the fourth angle: UX/onboarding.

## Background: the UX/onboarding subagent died twice

The UX/onboarding review was dispatched twice in this assessment round.
The first attempt died with zero real progress and was redispatched. The
second attempt (worktree `agent-a590c347e9cd70189`) hit a session-limit
cutoff mid-flight, but left real, usable partial progress: a Playwright
script (`poc/ux_onboarding_review_pass2/run_poc.py`) that had already
identified the org had no seeded cases/detections to walk, and a
second, half-finished script (`run_poc_evidence.py`, its own docstring
already stating the goal precisely: "real case-lead login, real new case,
real evidence upload via the actual UI, then inspect the Evidence tab for
a download affordance -- live confirmation of the source-level finding
(no download button/link anywhere in EvidenceTab.tsx /
EvidenceDetailDrawer.tsx) against the real running app, not just static
analysis"). The subagent's own last message before the cutoff: "Good, a
sample exists. Let's extend the Playwright script to do the case-lead
journey: create case, upload evidence, and inspect the evidence tab
live."

Rather than redispatching a third subagent for what was now a
well-scoped, well-understood, low-risk fix (add a UI affordance for an
already-real, already-verified backend route), the orchestrator finished
it directly, per this initiative's own established precedent (DD1/CC1:
"small well-understood fixes are fine to do directly").

## The finding: no way to download evidence from the UI at all

Independently confirmed via grep before any fix, not taken on the
subagent's word: zero matches for "download" in
`frontend/src/components/EvidenceDetailDrawer.tsx`,
`frontend/src/pages/CaseDetailPage.tsx`, and `frontend/src/api/evidence.ts`.
The backend route this should call,
`GET /api/cases/{case_id}/evidence/{evidence_id}/download`, has existed
and been real-PoC-verified since Gap Audit X1 (`poc/evidence_download/`)
and had a real availability bug fixed in it since (Milestone DD1,
`sanitize_content_disposition_filename`) — the backend side was solid and
totally unreachable from the UI.

## The fix

- **`frontend/src/api/evidence.ts`**: new `downloadEvidence(caseId,
  evidenceId, fallbackFilename)` — fetches the real route via the shared
  `apiClient` (so the in-memory Bearer token from `keycloak.ts` is
  attached the same way every other authenticated call already gets it;
  a plain `<a href>` navigation would never carry it, since tokens are
  deliberately never written to `localStorage`/cookies for the SPA to
  read). Reads the real filename from the response's
  `Content-Disposition` header (new exported helper
  `filenameFromContentDisposition`, falling back to the evidence's own
  known filename), then triggers a real browser save via
  `URL.createObjectURL` + a synthetic `<a download>` click.
- **`frontend/src/components/EvidenceDetailDrawer.tsx`**: new Download
  button next to the status pill, gated on evidence state —
  hidden while `UPLOADING`/`SCANNING`/`HASHING` (mirrors the backend
  route's own "not yet promoted" 404 condition, `minio_evidence_key is
  None` until hashing completes), shown for every state past that. An
  inline error message appears if the download itself fails (e.g. a race
  against a not-yet-promoted object).

### Tests

- `frontend/src/__tests__/evidenceDownload.test.ts`: unit tests for
  `filenameFromContentDisposition` (quoted/unquoted filename extraction,
  fallback when the header is absent or has no filename directive).
- `frontend/src/__tests__/EvidenceDetailDrawer.test.tsx`: component tests
  (mocking `../api/evidence`) confirming the Download button is hidden
  for `UPLOADING`/`SCANNING`/`HASHING` and shown for
  `RECEIVED`/`PARSING`/`INGESTING`/`COMPLETE`/`ERROR`, and that clicking
  it calls `downloadEvidence` with the real case id, evidence id, and
  filename.

### Verification performed

- Full frontend suite: `npx vitest run` → **66 passed** (13 new, 53
  pre-existing, zero regressions).
- `npx tsc --noEmit` → clean.
- `npm run lint` (oxlint) → clean (one pre-existing, unrelated warning in
  `ErrorCatalogue.tsx`).
- **Live browser verification against the real dev stack** (not just
  unit tests) — `poc/evidence_download_ui/run_poc.py`: rebuilt
  `docker-nginx-1` from the new frontend source
  (`docker compose -f docker/docker-compose.dev.yml build nginx`), real
  Keycloak login as `case-lead`, real case creation, real evidence
  upload through the actual `UploadDrawer` UI, polled the real evidence
  row until the autonomous pipeline promoted it past hashing, opened the
  real `EvidenceDetailDrawer`, clicked the real Download button, and
  confirmed the browser saved a real file whose name and SHA-256 match
  the uploaded sample byte-for-byte. **9/9 checks passed.** See
  `poc/evidence_download_ui/README.md` and `output.txt`.

### Real, unrelated infra issue found and worked around while verifying

`docker compose up -d nginx` (naive form) recomputed the whole dependency
graph and attempted to recreate `db-migrate`, which failed (`kronos-backend
:dev`'s image genuinely has no `alembic` on `PATH` and no shell — a
pre-existing, real, broken one-shot migration image, unrelated to this
fix). This cascaded into recreating `postgres`/`opensearch-init`/
`tls-init` too and left `nginx` stuck in `Created`. Real Postgres data
was independently confirmed intact before and after (44 cases / 65
evidence rows / 2201 audit events, unchanged — named volumes survive
container recreation). Worked around with
`docker compose up -d --no-deps nginx` (nginx's actual `depends_on` list
does not include `db-migrate` at all). The broken `db-migrate` image
itself is a real, separate gap, out of scope for this fix — flagged below
for a future pass.

---

## Recommendation for the next wake-up cycle

Task #27 (the second multi-scenario assessment) is now complete: all
four angles (security, scale/reliability, incident-response,
UX/onboarding) produced real, independently-verified findings; the most
severe (JJ) and one concrete UX gap (this milestone) are fixed and
verified; the rest are honestly documented below rather than guessed at
or silently dropped. Remaining real, not-yet-actioned items, in priority
order:

1. **Case-scoped audit trail gap** (JJ's item 3) — `ContainmentAction
   .execute()`/`DetectionSinkPushService.push()` don't pass `case_id` to
   their audit log calls, unlike `DetectionTriageService.transition()`.
   Small, mechanical, same pattern already proven elsewhere.
2. **Redis prod secret CLI exposure** (JJ's item 1) — move
   `redis-auth-streams`/`redis-celery` to a secret-file-based entrypoint,
   mirroring `docker/postgres/replica-entrypoint.sh`.
3. **`db-migrate`'s broken image** (found this milestone) — the
   `kronos-backend:dev` image has no `alembic` on `PATH`, so
   `docker compose up` cannot actually run migrations through the
   compose-defined path; real production risk if this same image is ever
   used for a genuinely fresh deploy rather than an already-migrated,
   long-uptime dev stack. Needs investigation: is `alembic` missing from
   the image's dependency install, or is `db-migrate`'s entrypoint/command
   wrong?
4. **Postgres sync-replica documentation gap** (JJ's item 2) — needs at
   minimum a docs fix; the deeper ops-policy question (timeout/alerting/
   runbook) should be flagged to the project owner, not decided
   unilaterally.
5. **Remaining frontend UX gaps**: no UI for `revoke-session`/
   `sync-to-siem` containment actions; `riskScore`/`riskFactors` computed
   server-side but never surfaced in the frontend `Detection` type or UI.
   Larger scope than this milestone's single-button fix — worth their own
   milestone.
