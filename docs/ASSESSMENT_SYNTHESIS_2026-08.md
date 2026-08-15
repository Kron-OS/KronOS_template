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
| P0-W2 | **`README.md`'s local frontend-dev instructions are actively wrong**, not stale — `kronos.local` has been the only valid Keycloak redirect URI for 3 weeks (commits `06e243939`/`dcf7047`/`c173c14`), but the README still documents `localhost:5173`, which cannot log in at all. This is the single biggest blocker to a "10-minute local demo." | UX review §2 | S |
| P0-W3 | **A fresh Helm install silently reports all pods Ready with an empty Postgres schema** — V4 removed `create_tables()`-at-boot in favor of a real `db-migrate` init container, but `charts/kronos/templates/` has zero Alembic/migration mechanism, and every pod's healthcheck is deliberately DB-independent. A newcomer (or a real production operator) gets no error signal at all. | UX review §2 | M |

### P1 — real functional gaps

| # | Finding | Source | Size |
|---|---|---|---|
| P1-W4 | `kronos-attest case-report`/`day-report` has no real export mechanism to produce the JSON file they require — confirmed still true (Gap Audit's own P2-5, re-confirmed live). Blocks the report step of a real incident close-out. | IR walkthrough F4 | M |
| P1-W5 | `StaticApiKeyProvisioning` has no real per-(org, source) provisioning route — confirmed still true (Gap Audit P1-7, unaddressed by V1–V10). Blocks step 2 of the IR scenario at the very first hop for any org without a manually-seeded key. | IR walkthrough F6, Gap Audit P1-7 | L (needs a design decision first, same as when Gap Audit originally flagged it) |
| P1-W6 | **`poll_defender_alerts` can get permanently stuck** if a real backlog ever exceeds the 50-page pagination cap — the cursor only persists on success, so a stuck cycle re-fails identically forever with no dedicated recovery task (unlike the evidence pipeline's own orphan sweeps). | Scale review §2 | S |
| P1-W7 | **Prod Redis's real combined blast radius is wider than documented anywhere** — one instance serves step-up tickets (DB0), Celery broker (DB1), Celery result backend (DB2), AND the stream-ingest backbone for all six Q/R connectors (DB3). One outage halts evidence processing, breaks privileged-action auth, and drops all new telemetry simultaneously — a wider single-outage impact than either Postgres or MinIO, neither of which was captured by V10's own (correctly-scoped) Postgres/MinIO-only research. | Scale review §3 | M (documentation + a real design decision on whether DB-role separation across ≥2 Redis instances is worth the operational cost — mirrors V10's own research-first discipline) |
| P1-W8 | `Helm secret-creation snippet` in `README.md` has the wrong secret name (`kronos-secrets` vs. real `kronos-app-secrets`) and wrong key casing — `docs/deployment.md`'s equivalent is already correct, so this is a sync fix, not new research. | UX review §2 | S |

### P2 — hardening / polish

| # | Finding | Source | Size |
|---|---|---|---|
| P2-W9 | Inbound integration-source API-key comparison (`StaticApiKeyInboundAuthenticator`) uses a plain `dict.get()`, not `hmac.compare_digest` — theoretically timing-attackable, low real-world exploitability over HTTP given real network jitter, but a cheap, real fix. | Security review P2-SEC-2 | S |
| P2-W10 | Five repository lookup methods (`rule_pack`/`yara_rule_pack`/`ioc_feed`) take an id with no `org_id` scoping — confirmed unreachable from any current route, a defense-in-depth gap if ever exposed. | Security review P2-SEC-3 | S |
| P2-W11 | `python-jose` pinned floor-only; the specific algorithm-confusion CVE class is already independently mitigated by `KeycloakTokenValidator`'s own explicit RS256/PS256 allow-list (confirmed by direct code read) — this is a pin-hygiene item, not an active vulnerability. | Security review P2-SEC-4 | S |
| P2-W12 | Dark-mode toggle in `Layout.tsx` is real, clickable, and persisted — but only 2 CSS rules respond to it, producing a visibly broken half-themed page (worse than the feature being absent). | UX review §4 | M |
| P2-W13 | No root React error boundary anywhere — a render exception produces a blank screen rather than a real error state. | UX review §1 | S |
| P2-W14 | No "connector status" view in the frontend — a real, user-visible gap given six connectors now exist; a new user has no way to see whether Wazuh/Splunk/etc. are configured/healthy. | UX review §1 | M |
| P2-W15 | `docs/ingestion-pipeline.md` is stale (describes a synchronous in-request flow the code no longer has, post the `process_intake` Celery split) — actively misleading for anyone debugging a stuck upload mid-incident. | IR walkthrough F5 | S |
| P2-W16 | OpenSearch resource sizing (2GB heap, single-node everywhere, zero Helm resource block) doesn't obviously reconcile with the "100+ GB evidence" design goal — not urgent (no evidence of a real customer hitting this), but worth a real sizing pass before any production claim is made publicly. | Scale review §4 | M (needs real measurement, not just a values.yaml bump) |
| P2-W17 | `GenericPollSource` has zero production scheduler — same class of gap as P0-W1's Defender-specific instance, but for the generic stand-in itself (lower priority since it's a stand-in, not a named connector). | Scale review §5 | S |
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

**W4 · `poll_defender_alerts` stuck-backlog recovery (P1-W6).** Small,
well-scoped: either raise `_MAX_PAGES_PER_POLL` with real justification,
or add a dedicated recovery/alerting path so a stuck cycle doesn't fail
identically forever with no visibility.

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

**W8 · `StaticApiKeyProvisioning` real provisioning route (P1-W5).**
Larger, needs the same design-decision-first treatment Gap Audit P1-7
already flagged (how does an operator issue a key — admin route? CLI?
Vault-seeded?) — sequence after W1 lands, since W1 makes this gap's real
impact concrete rather than theoretical.

**W9 · Docs/sizing cleanup batch (P2-W15, P2-W16).** `docs/
ingestion-pipeline.md` refresh + a real OpenSearch sizing pass — low
urgency, fold together when convenient.

**W10 · `GenericPollSource` scheduler + Q/R throughput proof (P2-W17,
P2-W18).** Lowest priority in this synthesis — the generic stand-in
scheduler is cheap but low-value (no real named connector uses it
directly), and a real load-test harness for the six connectors is a
genuine, separate, scoped project, not a quick fix.

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
