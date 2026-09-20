# Gap Audit — Milestone WWW (2026-08-30)

**Scope:** closes Milestone VVV's own recommendation #1 — the one
HEAVY-tier (`q.parse.plaso`) parser still with zero real, full-pipeline
verification: `VolatilityModule` (memory-forensics ingestion via real
`volatility3`). This is a backend-only integration PoC, not a frontend E2E
spec — VolatilityModule has no frontend read surface at all (confirmed
again this cycle, unchanged since Milestone VVV; intentional per
`CLAUDE.md` §G.2), so there is nothing for a browser test to observe beyond
the evidence table reaching `Complete`, which already happens for every
other parser.

---

## Fixed / verified this cycle

### `poc/volatility_pipeline_ingest/` — real end-to-end pipeline verification

`poc/volatility_memory_module/` (an earlier cycle, predating this
initiative) verified `VolatilityModule.extract_artifacts()` in isolation —
a real, sandboxed `volatility3` subprocess run producing real
`StructuredArtifact` objects in-process — but its own "Gaps / honestly out
of scope this pass" section explicitly named what it hadn't done: *"Full
HTTP upload -> validate -> parse -> Postgres pipeline was not driven
end-to-end."* This cycle closes exactly that, with the same real sample
(`cridex.vmem`, 536,870,912 bytes, cached from that earlier run — still
deliberately never committed to this repo, per that PoC's own reasoning
about fixture size).

Real, full pipeline driven live against the dev stack: real login → real
case creation → real presigned-PUT upload of the 512 MiB file → real
`finalize_upload` → real Celery `q.intake` → `process_intake`/
`dispatch_parse` → real `q.parse.plaso` (the same queue/worker Milestones
UUU/VVV proved for Plaso/archive/EWF) → `VolatilityModule.extract_artifacts()`
(real `volatility3` subprocess) → real `ArtifactIngestService` → real
Postgres `structured_artifacts` rows. Verified by querying Postgres
directly (there is no HTTP read API for `StructuredArtifact` — confirmed
again by grepping every route and frontend component, unchanged from
Milestone VVV's own finding), not by trusting the evidence state alone.

**Real observed state sequence**: `SCANNING` (real ClamAV scan of the
512 MiB file, ~100s — the slowest single stage, and the first time this
initiative has driven a file anywhere near this size through the real
scan step) → `HASHING` → `PARSING` → `COMPLETE`.

**Real result**: exactly 2 `StructuredArtifact` rows, matching the earlier
PoC's own already-documented finding for this sample+version —
`volatility.pstree` (real, correctly empty: a genuine Volatility3/XP-era
`PsActiveProcessHead` interop limitation already root-caused in that
earlier PoC, not a KronOS bug) and `volatility.psscan` (the automatic
fallback plugin, 17 real process rows — the same well-known public census
of this classic sample the bare-CLI ground-truth run already confirmed).
Every row's `evidence_id`/`case_id`/`sha256` provenance verified to match
the real upload exactly.

**Real friction hit and fixed, not glossed over**: the first run failed
with a real `CERTIFICATE_VERIFY_FAILED: certificate has expired` —
`kronos.local`'s step-ca leaf cert (24h TTL, a known recurring issue for
this initiative) had expired between the previous cycle's verification and
this one. Fixed with the established remedy (`docker compose -p docker -f
docker-compose.dev.yml up -d tls-init && docker restart docker-nginx-1`),
re-ran cleanly.

**Real operational decision, not a shortcut**: ran against the already-running
dev stack rather than building a new isolated test-stack, specifically
because this host's memory was genuinely constrained going in (`free -h`
showed ~1.4 GiB free, swap already in use, before starting) — standing up
a second full stack (Postgres/OpenSearch/Keycloak/MinIO/backend/2 celery
workers/nginx) alongside the always-on dev stack for one large-file PoC
would have meaningfully increased real OOM/swap-thrashing risk for no
corresponding benefit; the dev stack's `celery-worker-plaso` already had
`volatility3` installed and `VOLATILITY_WORKER_PATH` set (confirmed via
`docker inspect`, not assumed).

## What this proves that the earlier PoC didn't

- Real Celery routing for a `.vmem` upload specifically, not inferred from
  `q.parse.plaso` already being proven for other HEAVY parsers.
- `ArtifactIngestService` persists real rows from a real Celery task
  execution (not an in-process call) — including
  `_annotate_artifacts()`'s org_alias correction and full tenant/case/org_id
  provenance stamping flowing through correctly for this parser.
- Evidence with **zero** `TimelineRecord`s (`VolatilityModule.parse()` is a
  documented no-op) legitimately reaches `COMPLETE` through the real
  orchestration logic — confirmed via the real state sequence, not read off
  the code.
- The largest file this initiative has driven through the real pipeline by
  a wide margin (512 MiB vs. `kape_triage.E01`'s 62 KiB) — the real
  `SCANNING` stage alone took longer than most other specs' entire run,
  a real data point for anyone reasoning about upload-pipeline timeouts at
  realistic forensic file sizes.

## Documented, not fixed / out of scope this cycle

1. **Not wired into any automated CI test, deliberately** — the same
   reason the original PoC never committed the fixture applies here: a
   512 MiB real memory image cannot be committed, and a CI runner has no
   persistent cache to avoid re-downloading it on every run without adding
   real cost/flakiness. This is real, captured, human-triggerable
   verification (CLAUDE.md §F) — not a `frontend-e2e-smoke`/
   `security-integration-tests.yml` candidate. If CI coverage for the
   *wiring* (not real forensic correctness) is ever wanted, the honest
   path is a tiny synthetic `.vmem`-extension fixture exercising only
   "does an unrecognizable memory-dump-shaped file reach a terminal state
   without hanging" — not attempted this cycle, and would need its own
   real run to characterize how `volatility3`/`VolatilityLauncher` actually
   behaves on garbage bytes before writing it (unverified assumption, not
   guessed at here).
2. Only `.vmem`/XP-sample re-verified — `.mem`/`.raw`/`.dmp`/`.lime`
   extension routing remains covered only by existing unit tests, not
   independently re-run this cycle.
3. Carried unchanged: intake-stage retry E2E coverage; no spec covers two
   simultaneous dependency failures or a degraded-not-hard-down dependency;
   `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8; Milestone RRR's "no
   workflow has ever run on real GitHub Actions" finding remains true;
   `DashboardsIndexPatternProvisioner`'s backgrounded call (Milestone VVV)
   still hasn't been independently observed stalling for real.

## Status

Every HEAVY-tier parser this repository currently has (Plaso direct,
`ZipArchiveParser`/`TarArchiveParser` container recursion, EWF/E01
whole-image routing, and now `VolatilityModule`) has been driven through
the real, autonomous, full pipeline at least once with captured, inspected
output — closing the coverage arc Milestones UUU/VVV/WWW have been working
through since Milestone PPP first flagged "heavy parsers structurally
unexercised by any CI path" as a named gap. `q.parse.plaso` is no longer a
blind spot for any parser that routes to it.

## Recommendation for the next cycle

1. This is a natural point for the next multi-scenario subagent assessment
   (security/CI-reliability/coverage-gap) — the last one was Milestone TTT
   (Cycle 17); three implementation-focused cycles (UUU/VVV/WWW) have
   landed since without an independent cross-check.
2. Intake-stage retry E2E coverage (carried since Milestone TTT).
3. `security-stack` also booting `kronos-backend`, RBAC access-denial
   specs, or `docs/PLAYWRIGHT_E2E_TEST_PLAN.md` §3.6-§3.8 remain open.
4. Periodically re-check Milestone RRR's finding (no workflow has ever run
   against this branch).
5. If `DashboardsIndexPatternProvisioner`'s backgrounded call (Milestone
   VVV) is ever observed stalling for real, apply the same fix
   `SecurityAnalyticsDetectorProvisioner` itself still needs.
