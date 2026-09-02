# poc/volatility_pipeline_ingest — real full-pipeline VolatilityModule ingestion

**Re-run for Milestone CCCCC (2026-09-02)**: same real pipeline, same real
`cridex.vmem` sample, now exercising the rewritten multi-plugin worker
(`docker/volatility/kronos-volatility-worker.py`, shared-context
architecture, see `poc/volatility_multiplugin/`) instead of the original
single-plugin/fallback-pair worker. Real result (current
`evidence_ids.json`/`final_state.json`/`artifact_verification.json`):
evidence reached `COMPLETE`, **7** real `structured_artifacts` rows landed
(one per eager plugin: `volatility.pstree`, `volatility.psscan` with the
real 17-process census, `volatility.dlllist`, `volatility.cmdline`,
`volatility.malfind`, `volatility.filescan`, `volatility.registry.hivelist`
— up from 2 rows pre-CCCCC), all provenance fields (`evidence_id`/
`case_id`/`sha256`) matched the real upload, verdict `PASS`. A
now-superseded note below ("no HTTP read API for StructuredArtifact yet")
predates Milestone AAAAA's `GET /{case_id}/artifacts` route — left as
written for historical accuracy of the original run rather than edited.

Closes the gap `poc/volatility_memory_module/README.md`'s own "Gaps /
honestly out of scope this pass" section named explicitly: *"Full HTTP
upload -> validate -> parse -> Postgres pipeline was not driven end-to-end
for this item... Wiring through ArtifactIngestService/Postgres/the Celery
q.parse.plaso queue for real is the natural next verification step."*
Milestone VVV's own recommendation #1 pointed at exactly this. That earlier
PoC verified `VolatilityModule.extract_artifacts()` in isolation (in-process
call, no HTTP, no Celery, no Postgres); this PoC drives the *entire* real
autonomous pipeline: real login → real case creation → real presigned-PUT
upload → real `finalize_upload` → real Celery `q.intake` →
`process_intake`/`dispatch_parse` → real `q.parse.plaso` →
`VolatilityModule.extract_artifacts()` (real `volatility3` subprocess via
`VolatilityLauncher`) → real `ArtifactIngestService` → real Postgres
`structured_artifacts` rows — then queries Postgres directly to confirm
those rows, since there is no HTTP read API for `StructuredArtifact` yet
(confirmed by grepping every route in `src/external/routes/` and every
frontend component; this is intentional per `CLAUDE.md` §G.2, not a gap).

## Versions / stack

- Ran against the **live dev stack** (`docker-compose.dev.yml`, project
  name `docker`), not an isolated test-stack build — a deliberate choice
  given this host's real, confirmed memory pressure (`free -h` showed
  ~1.4 GiB free / swap already in use before this run) and the dev stack's
  `celery-worker-plaso` already having `volatility3==2.28.0` installed and
  `VOLATILITY_WORKER_PATH` set (confirmed via `docker inspect
  docker-celery-worker-plaso-1` before running, not assumed) — standing up
  a second, fully duplicate isolated stack for a single large-file PoC
  would have doubled memory pressure for no real benefit.
- Same real sample as `poc/volatility_memory_module/`: `cridex.vmem`
  (536,870,912 bytes, sha256 `02a63be2fcf3a63446c3c8ca9151aff963f888204d141e46c6be60ddde7c3e8d`),
  cached at `/home/reca/scratch/kronos-poc-volatility/cridex.vmem` from that
  earlier pass — **never committed to this repo** (see that PoC's own
  README for the download URL/sha256 if it needs re-fetching).

## Real, reproduced friction hit during this run

`kronos.local`'s step-ca leaf cert had expired (24h TTL, a known recurring
issue for this initiative) — `run_ingest.py`'s first attempt failed with a
real `CERTIFICATE_VERIFY_FAILED: certificate has expired`. Fixed with the
established remedy: `docker compose -p docker -f docker-compose.dev.yml up
-d tls-init && docker restart docker-nginx-1`. Re-ran cleanly afterward.

## How to run

```bash
# 1. Ensure the real sample is present (download per
#    poc/volatility_memory_module/README.md if needed), then:
KRONOS_CRIDEX_VMEM_PATH=/path/to/cridex.vmem \
  /home/reca/venv/bin/python3 poc/volatility_pipeline_ingest/run_ingest.py

# 2. Poll to a terminal state and verify real Postgres rows:
KRONOS_POC_POSTGRES_DSN=postgresql://kronos:kronos_dev_password@localhost:5432/kronos \
  /home/reca/venv/bin/python3 poc/volatility_pipeline_ingest/verify_artifacts.py
```

Both env vars default to this host's own real dev-stack paths/DSN if unset.

## Real result (captured run, 2026-08-30)

See `output.txt` for the full real transcript. Summary
(`artifact_verification.json` has the complete row dump):

```json
{
  "case_id": "99ccd04f-775e-495e-b089-0f17f032a043",
  "evidence_id": "eab213ad-a70a-4593-97cc-c9a41b0afbdf",
  "final_evidence_state": "COMPLETE",
  "structured_artifact_row_count": 2,
  "by_kind": {"volatility.pstree": 1, "volatility.psscan": 1},
  "psscan_process_count": 17,
  "all_rows_evidence_id_matches": true,
  "all_rows_case_id_matches": true,
  "all_rows_sha256_matches_upload": true,
  "verdict": "PASS"
}
```

Real state sequence observed live: `SCANNING` (real ClamAV scan of the
512 MiB file, ~100s) → `HASHING` → `PARSING` → `COMPLETE`. Exactly 2 real
`StructuredArtifact` rows landed in Postgres, matching
`poc/volatility_memory_module/`'s own already-documented finding for this
exact sample+version: `volatility.pstree` real but empty (a genuine
Volatility3/XP-era `PsActiveProcessHead` interop limitation, not a KronOS
bug — see that PoC's own README for the full root-cause investigation),
and `volatility.psscan` (the automatic fallback plugin
`kronos-volatility-worker.py` runs when the primary comes back empty) with
17 real process rows — the same well-known public census of this classic
sample (System, smss.exe, csrss.exe, winlogon.exe, services.exe, lsass.exe,
svchost.exe ×4, spoolsv.exe, explorer.exe, alg.exe, wuauclt.exe ×2,
reader_sl.exe) the bare-CLI ground-truth run in the earlier PoC already
confirmed. Every row's `evidence_id`/`case_id`/`sha256` provenance matches
the real upload exactly.

## What this proves that the earlier PoC didn't

- The real Celery routing actually works for a `.vmem` upload specifically
  (not just Plaso/.pf/.zip/.E01, which Milestones UUU/VVV already proved
  for `q.parse.plaso`) — confirmed live, not inferred from the queue
  configuration being shared.
- `ArtifactIngestService` actually persists real `StructuredArtifact` rows
  from a real Celery task execution (not just from an in-process call, as
  the earlier PoC's step 5 was) — including that `_annotate_artifacts()`'s
  org_alias correction (`src/application/parsing_orchestration.py`) and
  the tenant/case/org_id provenance stamping all flow through correctly
  for this parser specifically.
- Evidence with **zero** `TimelineRecord`s (VolatilityModule's `parse()` is
  a documented no-op) still legitimately reaches `COMPLETE` through the
  real orchestration logic, not just by reading the code — confirmed via
  the real evidence state transition sequence above.
- A 512 MiB file exercises the real upload/ClamAV-scan/hash/parse pipeline
  at a materially larger scale than any fixture previously used in this
  initiative (`kape_triage.E01` is 62 KiB) — the `SCANNING` state alone
  took longer than most other specs' entire run.

## Honestly out of scope / not verified this pass

- Only the `.vmem` extension/XP-sample path was re-verified — `.mem`/
  `.raw`/`.dmp`/`.lime` extension routing was already covered by
  `MagicByteValidator`/`VolatilityModule.supports()` unit tests
  (`tests/unit/adapter/test_validation.py`,
  `tests/unit/parsers/test_volatility.py`), not re-run here.
- Not wired into any automated CI test — deliberately, for the same reason
  the original PoC never committed the fixture: a 512 MiB real memory
  image cannot be committed to this repo, and a CI runner has no
  persistent scratch cache to download it from repeatedly without adding
  real, recurring cost/flakiness for a real external download dependency.
  This PoC is real, captured, human-triggerable verification (CLAUDE.md
  §F), not a candidate for `frontend-e2e-smoke`'s or
  `security-integration-tests.yml`'s own automated suites.
