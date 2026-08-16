# Multi-Scenario Assessment Synthesis (Task #14 → Milestone W)

**Status:** synthesis complete, 2026-08-15. Reconciles the four real,
independently-dispatched assessments — `docs/assessments/
incident_response_walkthrough.md`, `security_red_team_review.md`,
`ux_onboarding_review.md`, `scale_reliability_review.md` — into one
prioritized execution plan, mirroring exactly how Milestone T's own gap
audit became Milestone V's plan: real findings first, a real priority
order second, dispatched/verified fixes third.

---

## §0 The one finding that dominates everything else

All four assessments, working completely independently and from different
angles, converged on the **same structural pattern**, found four separate
times:

| Where found | What's wired but never triggered |
|---|---|
| Incident-response walkthrough F1 | `DetectionSyncService.sync_org_findings()` — no route, no beat task |
| Incident-response walkthrough F2 | `BatchSealingService.seal_pending()` / `StreamNormalizationService.normalize_batch()` — no scheduler |
| Incident-response walkthrough F3 | `PlaybookExecutionService.execute()` — no HTTP route calls it, ever |
| Scale/reliability review §5 | `GenericPollSource.run_poll_cycle()` — no beat task (a fourth, independent recurrence of the identical pattern) |

**The real consequence, stated plainly:** every one of the six EDR/SIEM
connectors this initiative spent Milestones Q/R building (Wazuh,
Suricata/Zeek, Defender as sources; Splunk, CEF, Sentinel as sinks) is
individually PoC-verified and correctly wired at the DI-container level
(per V2's own fixes), but a Wazuh alert or Suricata event accepted today
still cannot autonomously become a triaged `Detection` or trigger a SOAR
response in a real running deployment — every step past "land in a Redis
Stream" requires a human manually invoking the equivalent of `poc/
l3_chain_collector_to_detect/`'s own three-stage manual pipeline. This is
the single highest-value fix available: it doesn't require inventing
anything new, every piece already exists and is individually correct, it
just needs the same "add a beat task pointing at code that already works"
fix V2 already proved out for `poll_defender_alerts`.

This is Milestone W's **W1**, ranked above every other finding below —
not because the other findings aren't real, but because this one
determines whether the platform's entire core value proposition (autonomous
detection response) actually functions today, which is a categorically
higher-stakes question than any individual hardening item.

---

## §1 Prioritized finding list (all four assessments, deduplicated)

Legend: **P0** urgent/actively-wrong-today · **P1** real functional gap ·
**P2** hardening/polish. Size: **S** (<1 day) · **M** (1–3 days) · **L**
(multi-day/needs design).

### P0 — urgent

| # | Finding | Source | Size |
|---|---|---|---|
| P0-W1 | **CLOSED (2026-08-15, verified live — see §2 W1 STATUS below).** ~~The autonomous streaming-detection-to-response pipeline has FOUR separate "wired but never triggered" gaps~~ (§0 above) — all four now wired and proven autonomous end-to-end against real services, `poc/autonomous_detection_pipeline/run_poc.py`, 24/24 checks. | IR walkthrough F1/F2/F3, scale review §5 | L (four real beat-task/route additions, each individually small, but the design work of sequencing them correctly — seal → normalize → sync → (optionally) auto-response — needs care) |
| P0-W2 | **CLOSED (2026-08-15, commit `53aab6c`).** ~~`README.md`'s local frontend-dev instructions are actively wrong~~ — rewritten to state the real `kronos.local` requirement and point at `docs/lan-dev-access.md`. | UX review §2 | S |
| P0-W3 | **CLOSED (2026-08-15, commit `53aab6c`).** ~~A fresh Helm install silently reports all pods Ready with an empty Postgres schema~~ — `charts/kronos/templates/backend/migrate-job.yaml` added, a `pre-install,pre-upgrade` hook Job running `alembic upgrade head` before the backend Deployment is ever created/updated (mirrors `keycloak/provision-org-job.yaml`'s shape), default-enabled. Verified via real `helm lint`/`helm template` output. | UX review §2 | M |

### P1 — real functional gaps

| # | Finding | Source | Size |
|---|---|---|---|
| P1-W4 | **CLOSED (2026-08-16, commit `7a56a49`).** ~~`kronos-attest case-report`/`day-report` has no real export mechanism~~ — `GET /api/audit/export` added, verified against the real installed CLI. Surfaced a new, separate, NOT-yet-fixed bug in the process: see P1-W19 below. | IR walkthrough F4 | M |
| P1-W5 | **CLOSED (2026-08-16, commit `b25d1c6`).** ~~`StaticApiKeyProvisioning` has no real per-(org, source) provisioning route~~ — real Postgres-backed `IntegrationSourceKeyRepository` (hash-only storage, plaintext never persisted) + `POST/GET/DELETE /api/admin/integration-sources/...` routes, ORG_ADMIN + aal2 step-up gated on mutations, audited. Verified end-to-end against the real dev-stack Postgres: provision → real key → real push accepted → revoke → same key rejected. | IR walkthrough F6, Gap Audit P1-7 | L (needs a design decision first, same as when Gap Audit originally flagged it) |
| P1-W6 | **CLOSED (2026-08-15, commit `993ae81`).** ~~`poll_defender_alerts` can get permanently stuck~~ — `DefenderPollSource.poll()` now truncates-and-continues at the page cap (returns the valid partial batch with an advanced cursor) instead of raising, so the next scheduled cycle drains the next slice of backlog autonomously; a genuinely zero-progress capped run still fails loudly. Independently verified: 1873→1874 tests. | Scale review §2 | S |
| P1-W7 | **CLOSED as research (2026-08-16, commit `137c4ac`), matching how V10 itself closed.** ~~Prod Redis's real combined blast radius is wider than documented anywhere~~ — `docs/REDIS_BLAST_RADIUS_RESEARCH.md` documents the real four-role blast radius, researches DB-role separation vs. Sentinel vs. Cluster against real vendor docs, and gives a reasoned verdict: adopt DB-role separation now (zero code changes, `src/config.py` already models each role as an independent DSN), defer Sentinel HA behind named trigger conditions, rule out Cluster entirely for the Celery broker/backend roles (Kombu has no supported Redis Cluster broker integration). Actual role-separation implementation remains open as a real follow-up item (§7 of that doc), by design — this item's own scope was research, not implementation, mirroring V10. | Scale review §3 | M (documentation + a real design decision on whether DB-role separation across ≥2 Redis instances is worth the operational cost — mirrors V10's own research-first discipline) |
| P1-W8 | **CLOSED (2026-08-15, commit `53aab6c`).** ~~`Helm secret-creation snippet` in `README.md` has the wrong secret name~~ — fixed to `kronos-app-secrets` with correct key casing, matching `docs/deployment.md` and every chart template's real `secretRef`. | UX review §2 | S |
| P1-W19 | **CLOSED (2026-08-16, commit `e026d9f`).** `kronos_attest/report.py`'s `case_report()`/`day_report()` re-verify the hash chain (`ChainVerifier.verify()`) over an *isolated, case-/day-filtered subset* of the export, re-chaining from a fixed genesis hash. Any org with more than one case (or an audit history spanning more than one day) gets a spurious `chain_valid: false` for its case/day reports, even with zero tampering, because the filtered subset's real `prev_row_hash` values point at whatever org-wide event actually preceded them — not the previous event *in the filtered list*. Confirmed live with a real, deliberately multi-case Postgres scenario (`poc/kronos_attest_export/`, full root-cause writeup in that PoC's `README.md`); pre-existing since `0a6ee04`, unrelated to the new W3 export route (which correctly always serves the full, unfiltered chain). `poc/chain_of_custody/`'s own earlier single-case demo never exposed it by coincidence (its filtered subset happened to equal the whole chain). | Found via W3 (`poc/kronos_attest_export/README.md`) | M (needs real design work on `ChainVerifier`/`AttestationReport`'s contract — verify the full chain for tamper-detection, report a case/day-scoped event count and its own leaf-hash Merkle root separately, rather than re-deriving a broken isolated chain; touches `kronos_attest/verifier.py`, `report.py`, `cli.py`, and their existing tests) |

### P2 — hardening / polish

| # | Finding | Source | Size |
|---|---|---|---|
| P2-W9 | **CLOSED (2026-08-15, commit `14474fb`).** ~~Inbound integration-source API-key comparison uses a plain `dict.get()`~~ — replaced with a linear `hmac.compare_digest` scan over every provisioned key, no early exit. | Security review P2-SEC-2 | S |
| P2-W10 | **CLOSED (2026-08-15, commit `14474fb`).** ~~Five repository lookup methods lack `org_id` scoping~~ — `org_id` added to all five (ABC + Postgres + InMemory), real `WHERE org_id = ...` filtering, every internal call site threaded (zero real route call sites existed). | Security review P2-SEC-3 | S |
| P2-W11 | **CLOSED (2026-08-15, commit `14474fb`).** ~~`python-jose` pinned floor-only~~ — tightened to `>=3.4` (fixes CVE-2024-33663/-33664); `KeycloakTokenValidator`'s RS256/PS256 allow-list mitigation re-confirmed solid before this was treated as pin-hygiene rather than a live vuln. | Security review P2-SEC-4 | S |
| P2-W12 | **CLOSED (2026-08-16, commit `b1606bf`).** ~~Dark-mode toggle in `Layout.tsx` is real, clickable, and persisted — but only 2 CSS rules respond to it~~ — all 15 files using hardcoded gray-scale/indigo classes paired with real `dark:` variants; a second real bug (theme never applied on `/login`, which never mounts `Layout`) found via actual browser testing and fixed by hoisting the sync effect to `App.tsx`. Verified with real Playwright screenshots (light/dark) of `/login` and an authenticated page. | UX review §4 | M |
| P2-W13 | **CLOSED (2026-08-16, commit `b1606bf`).** ~~No root React error boundary anywhere~~ — real class-component `ErrorBoundary` wraps the router in `App.tsx`, themed fallback UI (no stack trace exposed — info-disclosure-conscious for a forensics product), `console.error` logging only (no error-reporting sink exists yet, not invented here). Verified with a real screenshot + a real caught-error unit test. | UX review §1 | S |
| P2-W14 | **CLOSED (2026-08-16, commit `b9179f3`).** ~~No "connector status" view in the frontend~~ — `GET /api/admin/connectors/status` + `/admin/connectors` page, honestly split into self-service PUSH sources (W8's key repository, audit-derived recency) vs. platform-configured Defender POLL status, never implying false per-org self-service. Verified end-to-end against real Postgres + real Playwright screenshots. | UX review §1 | M |
| P2-W15 | **CLOSED (2026-08-16, commit `6ef2aa6`).** ~~`docs/ingestion-pipeline.md` is stale~~ — rewritten to match the real current `process_intake`-split pipeline, every claim cross-checked against the actual code. | IR walkthrough F5 | S |
| P2-W16 | **CLOSED (2026-08-16, commit `6ef2aa6`) as docs-only guidance, per its own "needs real measurement" framing.** ~~OpenSearch resource sizing doesn't obviously reconcile with the "100+ GB evidence" design goal~~ — `docs/deployment.md` now states plainly that pinned heap values are demo defaults, cites real OpenSearch heap-sizing guidance, and names exactly what real measurement work is still needed before a production sizing claim could be made honestly. The underlying measurement work itself remains undone (by design — this item's own scope was docs, not a real load test). | Scale review §4 | M (needs real measurement, not just a values.yaml bump) |
| P2-W17 | **CLOSED as "not warranted" (2026-08-16), same legitimate-conclusion pattern as the Kafka and Redis Cluster questions.** ~~`GenericPollSource` has zero production scheduler~~ — confirmed by direct grep (`src/external/dependencies.py`, `src/external/startup.py`, `src/config.py`): `GenericPollSource` has ZERO real config/DI wiring anywhere in this codebase, only self-references in its own file and one docstring cross-reference from `defender.py`. It is explicitly a reference/stand-in implementation proving the `IntegrationSource` abstraction (see its own module docstring, "Not a named vendor... this is the real 'lowest common denominator' cursor-poll shape"), not a connector any real org could configure today. A beat task scheduling it would first require inventing a full `Settings`-level config surface (base_url/org_id/auth) for a component with zero real users — not "add a beat task pointing at code that already works" (V2/W1's own established pattern), a materially different and unjustified scope expansion for a stand-in. Revisit only if/when this becomes a real, named connector with real config wiring (at which point it stops being this finding and becomes a new Defender-shaped item). | Scale review §5 | S |
| P2-W18 | Six Q/R connectors are correctness-proven, never throughput-proven — no real load/sustained-volume test exists for any of them. Not urgent absent a real production deployment, but should be closed before any customer-facing throughput claim. | Scale review §5 | L (needs a real load-test harness, its own scoped design) |

---

## §2 Proposed execution plan — Milestone W

Grouped in priority order, objectives only (mirroring the Gap Audit's own
§3 convention) — the orchestrator writes full dispatch briefs from these
at execution time, same as V1–V10.

**W1 · Wire the autonomous detection pipeline end-to-end (P0-W1).** The
single highest-value item in this whole synthesis. Four real beat
tasks/routes, sequenced correctly:
  (a) a `seal_pending`-calling beat task (per `SealingTriggerPolicy`'s own
      interval, per registered org/source);
  (b) a `normalize_batch`-calling beat task (triggered on seal, or
      polled);
  (c) a `sync_org_findings`-calling beat task (per org, on an interval,
      mirroring `poll_defender_alerts`'s own just-proven pattern);
  (d) a real HTTP route (`POST /api/detections/{id}/playbook/{action_name}`
      or similar) so `PlaybookExecutionService.execute()` is finally
      reachable, gated the same way `/triage` already is.
  Verification-first: a real end-to-end PoC (a real Wazuh alert →
  Redis Stream → sealed batch → normalized document → synced Detection →
  triaged → a real SOAR action fires) before any `src/` change, mirroring
  `poc/l3_chain_collector_to_detect/`'s own manual proof but now
  autonomous.

  **W1 STATUS (2026-08-15): CLOSED, verified live.** All four beat
  tasks/routes (a)-(d) exist in `src/external/celery_app.py` +
  `src/external/celery_streaming.py` + `src/external/routes/detections.py`,
  and `poc/autonomous_detection_pipeline/run_poc.py` proves the full
  autonomous chain end-to-end against real services with zero manual
  `seal_pending()`/`normalize_batch()`/`sync_org_findings()` calls: real
  Redis Stream event → autonomous seal (beat-triggered,
  `BatchSealingService.seal_pending()`) → autonomous normalize
  (event-chained) → real per-org SA detector fires on its own schedule →
  autonomous `DetectionSyncService.sync_org_findings()` creates the
  `Detection` row (beat-triggered) → real
  `POST /api/detections/{id}/sync-to-siem/splunk` reaches
  `PlaybookExecutionService.execute()` and a real stand-in SIEM receiver
  observes the push. Run twice for a two-round proof (a second, later
  trigger event through the whole chain again with the detector already
  live) plus idempotency (a second sync cycle creates zero duplicate
  `Detection` rows) and provenance linkage (`Detection.matched_document_ids`
  → real OpenSearch doc → `kronos.batch_id` matches the real sealed batch).
  24/24 real checks passed, `TOTAL wall-clock window T0 -> T_detected` ~204s
  for one full run (see `poc/autonomous_detection_pipeline/`). Two real,
  narrow bugs were found and fixed in the course of getting a clean run —
  both in the PoC harness itself, not in the `src/` integration code: (1)
  an early attempt reused one Keycloak org's `org_id`/`source_id` pair
  across multiple runs, colliding with stale `sealed_batches` watermark
  history from a previous run for that exact pair — fixed by using a
  fresh, run-unique org every run; (2) the PoC's own round-2 wait budget
  for `seal_pending_streams` was 60s against the real, correct, unmodified
  production `_SEAL_MAX_AGE_SECONDS = 60.0` threshold in
  `celery_streaming.py` (never loosened) plus the PoC's own detector name
  didn't match `SecurityAnalyticsDetectorProvisioner`'s real
  `kronos-{org_alias}-{log_type}-detector` naming convention, so
  `DetectionSyncService`'s findings query could never discover it; both
  fixed in `poc/autonomous_detection_pipeline/run_poc.py` and
  `_beat_schedule_override.py` only.

**W2 · Fix the two actively-wrong onboarding docs (P0-W2, P0-W3, P1-W8).**
Small, urgent, no design ambiguity: sync `README.md`'s Keycloak
redirect/frontend-dev instructions and Helm secret snippet to match
reality (`docs/deployment.md`'s own already-correct version for the
latter), and add a real Alembic/`db-migrate` mechanism to the Helm chart
(or, at minimum, a real pre-install/post-install hook that fails loudly
if migrations haven't run, closing the "silent empty schema" gap).

**W3 · `kronos-attest` report export (P1-W4).** Closes Gap Audit P2-5 for
real — add a real `GET /api/audit/cases/{case_id}/export` (or admin CLI)
shaping `AuditLogRepository` rows into the JSON contract `case_report()`/
`day_report()` already expect.

**W3 STATUS (2026-08-16, commit `7a56a49`): CLOSED, verified live.**
`GET /api/audit/export` (ORG_ADMIN-gated, always a full-org export by
design — never case-/day-scoped server-side, see the route's own
docstring for why that would be actively wrong) streams
`stream_by_org()`'s real events shaped exactly as
`poc/chain_of_custody/`'s own already-proven-correct field mapping.
Verified against a real Postgres-backed repository and the real installed
`kronos-attest` CLI subprocess (`poc/kronos_attest_export/`) — route-level
checks all pass. Building this verification honestly surfaced P1-W19 (a
real, separate, pre-existing bug in `kronos_attest` itself) rather than
hiding it — see that row above and **W11** below.

**W4 · `poll_defender_alerts` stuck-backlog recovery (P1-W6).** Small,
well-scoped: either raise `_MAX_PAGES_PER_POLL` with real justification,
or add a dedicated recovery/alerting path so a stuck cycle doesn't fail
identically forever with no visibility.

**W5 STATUS (2026-08-16, commit `137c4ac`): CLOSED as research** — see P1-W7 row above and `docs/REDIS_BLAST_RADIUS_RESEARCH.md` directly.

**W5 · Redis blast-radius documentation + design decision (P1-W7).**
Mirrors V10's own research-first discipline: document the real combined
blast radius plainly (this synthesis §1 already does the first pass), then
make a real, scoped decision on whether splitting step-up/Celery/
stream-ingest across ≥2 Redis instances is worth the operational cost —
do not implement without that research pass first.

**W6 · Security P2 cleanup batch (P2-W9, P2-W10, P2-W11).** Three small,
independent, low-risk hardening fixes — fold into one dispatch.

**W7 · Frontend polish batch (P2-W12, P2-W13, P2-W14).** Dark-mode fix (or
honest removal of the broken toggle until it's real), a root error
boundary, and a connector-status view — three real, independent frontend
items, could be one dispatch or three depending on how much frontend
context-loading overhead sharing one dispatch saves.

**W7 STATUS (2026-08-16, commit `b1606bf`): P2-W12/P2-W13 CLOSED, verified
live. P2-W14 (connector-status view) deliberately deferred** — it needs
its own design pass (what does "connector health" mean per source: last
successful poll? last error? per source_type or per source_id? does it
build on W8's new `GET /api/admin/integration-sources` list, which only
covers inbound-push keys, not poll-mode connectors like Defender?) rather
than being folded opportunistically into a dispatch scoped for the other
two items. Real bug found via actual Playwright browser testing (not
visible from source alone): the theme-sync effect lived only inside
`Layout`, which never mounts on `/login` — a cold load of `/login` always
rendered light-mode-only regardless of saved preference. Fixed by hoisting
`useDarkMode()` to `App.tsx` so it runs on every route. This repo had no
browser-automation tooling before this item; Playwright was added as a
real devDependency (kept, not stripped back out) since it worked and
closes a real gap in this frontend's own verifiability. Independently
verified: real screenshots inspected directly (`poc/frontend_theme_fix/`),
`npm run build`/`npm run lint` clean, vitest 43→47 tests (+4, real
before/after delta via a detached-HEAD checkout of the parent commit).

**W14 STATUS (2026-08-16): CLOSED, verified live.** Design decision made
on the question W7 deferred: the view honestly splits connectors into two
kinds rather than presenting one uniform "health" concept. PUSH sources
(Wazuh/Suricata-Zeek/generic webhooks) are real per-org self-service —
`GET /api/admin/connectors/status` enriches W8's
`IntegrationSourceKeyRepository.list_by_org` with a real `lastIngestedAt`/
`status` derived from the org's own audit log
(`INTEGRATION_SOURCE_PUSH_INGESTED`). Microsoft Defender, the one real
POLL source, is NOT per-org self-service — it is wired from a single
global `Settings.defender_poll_org_id` — so its entry is included only
when that setting names the caller's own org, and is labeled
"platform-configured (global)" in the UI, never implying an org admin can
change it from this view. `GenericPollSource` stays untouched (closed
not-warranted, P2-W17). New frontend page at `/admin/connectors`
(`ConnectorStatusPage.tsx`), nav-linked from `Layout.tsx`'s existing
admin-only section. Verified per CLAUDE.md SS F:
`poc/connector_status_view/run_poc.py` proves the route end-to-end
against real Postgres (real key provisioning, a real webhook push,
real audit-derived `lastIngestedAt`, and real Defender inclusion/exclusion
via the real `Settings`/DI path); `run_poc_frontend.mjs` captures real
Playwright screenshots of the page in light and dark mode. 16 new backend
unit tests (1932→1948 passing), 6 new frontend tests (47→53 passing);
`ruff`/`black`/`mypy` clean on touched files (mypy: the same 29
pre-existing errors, unchanged).

**W8 · `StaticApiKeyProvisioning` real provisioning route (P1-W5).**
Larger, needs the same design-decision-first treatment Gap Audit P1-7
already flagged (how does an operator issue a key — admin route? CLI?
Vault-seeded?) — sequence after W1 lands, since W1 makes this gap's real
impact concrete rather than theoretical.

**W8 STATUS (2026-08-16, commit `b25d1c6`): CLOSED, verified live.**
Design decision made: real Postgres-backed `IntegrationSourceKeyRepository`
(`src/adapter/repository/integration_source_key.py`/
`postgres_integration_source_key.py`) replaces the old boot-time-only
static dict (`configure_static_api_key_provisioning`, confirmed zero real
callers anywhere in `src/` before this) — queried per-request so an
admin-provisioned key takes effect immediately, no backend restart. Only
a SHA-256 hash of each 256-bit random key (`secrets.token_urlsafe(32)`) is
ever persisted; the plaintext is returned exactly once, at provision time
(standard "shown once" API-key UX). New `POST/GET/DELETE
/api/admin/integration-sources/...` routes, `ORG_ADMIN`-gated, mutations
also aal2-step-up-gated identically to `DELETE /api/evidence/{id}`, every
mutation audited. Real Alembic migration for the new table. Superseded
Milestone W6/P2-W9's in-memory `hmac.compare_digest` linear-scan fix (that
concern is moot once lookups are real, hash-indexed DB queries — reasoning
documented in the repository module's own docstring). Verified per
CLAUDE.md SS F: `poc/integration_source_key_provisioning/` ran a real
`alembic upgrade head` against the real dev-stack Postgres, then
end-to-end via `httpx.ASGITransport` (the pattern W3 established): real
provision → real returned key → real `POST /api/integrations/push/...`
accepted with that exact key → real revoke → same key rejected (401) →
real audit rows confirmed, neither containing the plaintext. Independently
verified: 1899→1932 tests (+33, all passing, `git stash`-equivalent
before/after delta), ruff/black clean, mypy 29 pre-existing errors
unchanged (none in touched files).

**W9 · Docs/sizing cleanup batch (P2-W15, P2-W16).** `docs/
ingestion-pipeline.md` refresh + a real OpenSearch sizing pass — low
urgency, fold together when convenient.

**W9 STATUS (2026-08-16, commit `6ef2aa6`): CLOSED.** Both docs rewritten/
added, every factual claim cross-checked against the real current code
(not carried over from old text). The real OpenSearch load-measurement
work itself is intentionally still open — tracked as P2-W18's own
throughput-proof scope (W10), not duplicated here.

**W10 · `GenericPollSource` scheduler + Q/R throughput proof (P2-W17,
P2-W18).** Lowest priority in this synthesis — the generic stand-in
scheduler is cheap but low-value (no real named connector uses it
directly), and a real load-test harness for the six connectors is a
genuine, separate, scoped project, not a quick fix.

**W10 STATUS (2026-08-16): P2-W17 CLOSED as "not warranted"** — see that
row above for the full reasoning. **P2-W18 (Q/R throughput proof) remains
open, deliberately not attempted** — it is its own genuine, separately-scoped
project (a real load-test harness, real sustained-volume runs against each
of the six connectors), not urgent absent a real production deployment
hitting a real throughput ceiling, and should not be rushed into a
generic W-item dispatch. Tracked here as the one remaining legitimately
open item from the entire Task #14 → Milestone W cycle.

**W11 · Fix `kronos_attest` case/day report chain-validity bug (P1-W19,
new 2026-08-16).** Real design work, not a quick patch: `ChainVerifier`/
`AttestationReport`'s contract needs to separate "is the full org chain
intact" (verify unfiltered, always) from "what does this case/day's own
subset look like" (event count + a subset-scoped Merkle root over that
subset's own leaf hashes — NOT a re-derived, isolated hash *chain*, which
is the actual bug). Touches `kronos_attest/verifier.py`, `report.py`,
`cli.py`'s JSON output contract (adding/changing fields callers may
already depend on — check for any real external consumer before changing
shape), and their existing tests
(`tests/unit/test_kronos_attest.py`, `tests/unit/test_attest.py`,
`poc/chain_of_custody/`, `poc/kronos_attest_export/`). A real regression
test using a deliberately multi-case/multi-day scenario (mirroring
`poc/kronos_attest_export/`'s own scenario) is required before this can be
called fixed — the existing single-case/single-day PoCs already proved
insufficient to catch this once. Should sequence reasonably soon given
this affects the legal-admissibility attestation story CLAUDE.md names as
core to the product ("A.5.28 Collection of evidence") for any real
multi-case deployment, i.e. every real deployment.

**W11 STATUS (2026-08-16, commit `e026d9f`): CLOSED, verified live.**
`case_report()`/`day_report()` now verify the full, unfiltered chain once
and scope `chain_valid`/`break_count` down to breaks whose `event_id`
falls within the case/day being reported, rather than re-deriving a
broken isolated chain — exactly the fix objective above. New
`org_chain_fully_intact` field surfaces the org-wide picture separately.
New regression tests (`TestCaseReportMultiCaseRegression`/
`TestDayReportMultiDayRegression` in `tests/unit/test_attest.py`) use a
new `_make_multi_case_chain()` helper that builds one real, contiguous,
interleaved-case chain — the existing `_make_event()` default silently
built isolated single-genesis links and would not have caught this bug.
Development also surfaced and correctly preserved a real, intentional
security property: a tamper legitimately cascades forward to every event
chained after it (regardless of case/day), which an initial, incorrect
test expectation caught and corrected — documented explicitly in
`report.py`'s docstrings. Re-ran the exact real `poc/kronos_attest_export/`
scenario that originally found this bug (real Postgres-backed org, real
installed `kronos-attest` CLI subprocess): all 24 checks now pass,
including the two that originally failed. Independently verified:
1896→1899 tests (+3, `git stash -u` delta), ruff/black clean, mypy 2
pre-existing errors in untouched `kronos_attest/tsa.py` only.

---

## §3 What was NOT re-derived, by design

Per the assessments' own explicit scope discipline, this synthesis does
not re-litigate: V10's own Postgres/MinIO HA verdicts (scale review
explicitly confirmed it did not duplicate that work, only broadened it via
the Redis finding above); the Gap Audit's own already-closed items
(V1–V10); or P1-SEC-1 (SSE ticket case-access bypass), which was found by
the security review and already fixed, verified, and committed
(`2a2bd68`) in the same session this synthesis was written, not deferred
to Milestone W.
