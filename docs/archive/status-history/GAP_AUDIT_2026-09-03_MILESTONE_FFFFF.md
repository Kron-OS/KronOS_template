# Gap Audit — Milestone FFFFF (2026-09-03)

**Scope:** checkpoint 4 (final) of the project owner's "huge work" request —
the frontend for Milestone EEEEE's on-demand path: a "Child Files" view
(the user's own phrase) for real extracted files, and an interactive
"Registry Browser" for real, scoped `windows.registry.printkey` drill-down.
Full plan at `/home/reca/.claude/plans/abstract-imagining-umbrella.md`
(approved).

## What changed

- **`frontend/src/components/ArtifactViews.tsx`**: `FileScanView` gained
  the real "Extract this file" action (a button per row, driven by the
  row's own `Offset` — the real physical address `windows.dumpfiles` needs
  per Milestone EEEEE's PoC finding), with `Extracting…`/`Extracted`/
  `Failed — retry?` states. New `DumpFilesView` ("Child Files") — a table
  of real extracted-file artifacts (filename/size/sha256), a real Download
  button, and a disabled, tooltipped "Check reputation — VirusTotal coming
  soon" placeholder (UI-only, per the user's own "eventually," nothing
  wired). New `RegistryBrowser` — hive picker → breadcrumb-driven,
  one-level-at-a-time key drill-down, real-verified live that
  `windows.registry.printkey`'s `key` parameter takes the **full**
  backslash-joined path from hive root (not an incremental single-level
  name), re-confirmed against `Challenge.raw` (`"ControlSet001\\Control"`
  returns `Control`'s own children directly).
- **`frontend/src/pages/CaseDetailPage.tsx`**: `ArtifactsTab` gained two
  new nav entries — `volatility.dumpfiles` ("Child Files", a real kind,
  discoverable once `volatility.filescan` is present even before any
  extraction) and `__registry_browser__` (a synthetic pseudo-kind, never a
  real `StructuredArtifact.kind`, unlocked whenever
  `volatility.registry.hivelist` is present). New on-demand orchestration:
  `useMutation` wrappers around `requestVolatilityDumpFile`/
  `requestVolatilityRegistryKey`, a polling toggle on the existing
  `['artifacts', caseId]` query (`refetchInterval` while a request is in
  flight — the plan's own documented deviation from "subscribe via SSE,"
  see Milestone EEEEE's doc for why), and a client-side 20s timeout that
  turns a genuinely failed extraction into an honest "Failed — retry?"
  state instead of spinning forever (see "Real bugs found live" below).
- **`frontend/src/api/cases.ts`**: `requestVolatilityDumpFile`,
  `requestVolatilityRegistryKey`, `downloadDerivedArtifact` (mirrors
  `downloadEvidence`'s real Content-Disposition-aware blob download).
- **`frontend/e2e/fixtures/seed_volatility_artifacts.py`** /
  `VolatilityArtifactSeeder.ts`: new opt-in `--include-on-demand` flag
  (default off — `case-artifacts-ui.spec.ts`, Milestone DDDDD, already
  asserts exactly 7 seeded kinds via this same shared script) that seeds
  the two on-demand kinds using real physaddr/hive-offset/row values
  captured live this session, **and** uploads a real (freshly generated,
  honestly-labeled) payload to the real derived-artifact MinIO bucket so
  the seeded fixture's Download button round-trips genuinely matching
  bytes, not just a metadata row.
- **New `frontend/e2e/case-artifacts-on-demand-ui.spec.ts`**: real,
  committed E2E coverage — Child Files (real filename/size, real download
  round-trip, VirusTotal placeholder present and inert) and Registry
  Browser (hive selection, drill into `ControlSet001`, breadcrumb back to
  root).
- **`frontend/e2e/a11y.spec.ts`**: extended the existing Artifacts-tab scan
  to also cover the Child Files and Registry Browser states.

## Real bugs found and fixed via live verification (not caught by any unit test)

Per CLAUDE.md §F, the on-demand routes' *service* layer was fully unit-
and route-tested in Milestone EEEEE with a mocked launcher — but a live,
real end-to-end run (real evidence bytes, real Celery worker, real
volatility3 subprocess) surfaced three real gaps unit tests structurally
could not catch:

1. **Wrong worker script path in the real deployed image.**
   `VolatilityOnDemandService` built its own `VolatilityLauncher()` with no
   `worker_path`, so it fell back to a path computed relative to the
   launcher's own source file (`/app/docker/volatility/...`) — but
   `docker/Dockerfile.plaso-worker` actually `COPY`s the worker script to
   `/app/volatility-worker/kronos-volatility-worker.py` and sets
   `VOLATILITY_WORKER_PATH` accordingly. `VolatilityModule._run_volatility`
   already read `settings.volatility_worker_path` correctly; the on-demand
   path didn't. First real symptom: `FileNotFoundError`. **Fixed**:
   `VolatilityOnDemandService` now accepts `worker_path`, threaded through
   from `celery_runtime.py`'s `_build_task_resources()` (which already has
   `Settings()` in scope) exactly like the eager path.
2. **Stale worker image.** Even after fixing the path, the real
   `docker-celery-worker-plaso-1` container was still running the
   *pre-EEEEE* worker script — `docker/volatility/kronos-volatility-worker.py`
   is `COPY`'d into the image at build time, not bind-mounted (`src/` is;
   `docker/` isn't) — so Milestone EEEEE's own worker-script changes were
   never actually deployed to this live container despite being real,
   correct code on disk. **Fixed** operationally: rebuilt and recreated
   `celery-worker-plaso` (and, later, `nginx` for the frontend bundle) via
   `docker compose -p docker build/up --force-recreate` — the `docker`
   project name matters here (this repo's compose file declares
   `name: kronos-dev`, but the actually-running stack is project `docker`;
   an unscoped `docker compose build` silently builds a same-named-but-
   disconnected image under the wrong project, confirmed live when a first
   attempt built `kronos-dev-celery-worker-plaso` while the running
   container stayed on `docker-celery-worker-plaso`).
3. **A genuinely failed extraction left the UI stuck forever.** Once the
   real chain worked end-to-end, a live click against a real
   `windows.filescan` row that has no recoverable bytes (a real, honest
   volatility3 outcome — not every offset is extractable, matching
   `poc/volatility_dumpfiles/`'s own documented negative case) revealed
   that nothing ever clears the "Extracting…" pending marker on a real
   async failure (the trigger POST itself still returns a real `202`; the
   failure happens later, inside the Celery task, with no HTTP-layer error
   to catch). **Fixed**: a 20s client-side timeout (comfortably above
   every real measured on-demand turnaround this session, worst case
   ~14s) turns a stuck pending marker into an honest `Failed — retry?`
   state for both dumpfiles extraction and registry-key requests.

A fourth, smaller bug was found via the live **a11y** run specifically
(not the functional run): `volatility.registry.printkey` is a real
`StructuredArtifact.kind` (each drilled-into key is its own row), but was
never meant to be its own nav tab — it leaked into the "Other" cluster as
a raw, confusing kind string the moment more than the eager 7 kinds
existed for an evidence file. **Fixed**: explicitly excluded from
`kindsPresent` in `ArtifactsTab` (only ever reachable via the "Registry
Browser" synthetic entry). A fifth, related one: `PostgresArtifactRepository.
list_by_case`/`list_by_evidence` had no `ORDER BY`, so the frontend's
"default-selected kind = first returned" behavior was silently relying on
Postgres returning rows in insertion order — true by luck on an
uncontended table with few rows, and exactly what broke (default selection
became "Command Lines" instead of "Process Tree") the moment more rows
were added for the same evidence file. **Fixed**: `ORDER BY created_at` on
both methods, restoring the real, intended "earliest analysis result
first" semantic deterministically. A sixth: a genuine WCAG AA contrast
violation (2.36:1, needs 4.5:1) in the new VirusTotal placeholder's
`text-gray-400`/`bg-gray-100` pairing — fixed to this file's own
established compliant convention (`text-gray-600 dark:text-gray-400`).

None of these six were caught by `tsc`/`oxlint`/`vitest`/the backend unit
suite — they surfaced only because this milestone included live,
end-to-end verification (real evidence, real Celery, real browser) as a
required step, not an optional nice-to-have. This is exactly the failure
mode CLAUDE.md §F exists to catch.

## Real, live verification performed

- **Backend, direct service call** inside `docker-celery-worker-plaso-1`
  (after the image rebuild): `VolatilityOnDemandService.extract_dump_file`
  against the real `Challenge.raw` evidence, real `physaddr=88029040` →
  real 49,152-byte file, real sha256 matching Milestone EEEEE's PoC
  exactly, real MinIO object confirmed (byte-identical, no Object Lock),
  real Postgres row, real audit event.
  `VolatilityOnDemandService.extract_registry_key` (hive root, then
  `key="ControlSet001"`) → real 9 then 5 rows, matching the PoC exactly.
- **Backend, real HTTP routes** via `httpx.AsyncClient` + `ASGITransport`
  wrapping the real, fully-`wire_dependencies_async()`-wired app (real DB,
  real Celery broker, real MinIO — only `get_tenant_context` overridden):
  `GET .../artifacts/{id}/download` → `200`, byte-identical content, real
  `Content-Disposition`; both trigger routes → real `202` + real Celery
  `taskId`; both real Celery tasks confirmed `succeeded` in the worker's
  own logs, with new real Postgres rows.
- **Full real browser run** (Playwright against `https://kronos.local`,
  real Keycloak login as `admin`, real case `"First case"`/`Challenge.raw`):
  clicked "Extract" on a real `cache2` filescan row → real `202` → real
  polling → real row appeared in "Child Files" → clicked "Download" → a
  real file downloaded with the real suggested filename → clicked into
  "Registry Browser" → selected the real `SYSTEM` hive → real root rows
  rendered → drilled into `ControlSet001` → real one-level-deeper rows
  rendered. (An earlier run against an arbitrary/unlucky filescan row is
  what surfaced bug 3 above — re-run against the known-good row after the
  fix, decisive success.)
- `tsc -b` / `oxlint` / `vitest run` (120/120) clean throughout; full
  backend suite `1994 passed, 1 skipped`, 89.13% coverage, `ruff` clean.
- New committed E2E (`case-artifacts-on-demand-ui.spec.ts`) and extended
  `a11y.spec.ts` both passing against the live dev stack; pre-existing
  `case-artifacts-ui.spec.ts` (Milestone DDDDD, 7-kind assertion) re-run
  and confirmed unaffected by the shared seed script's new opt-in flag.

## Status

This closes the full 4-checkpoint "huge work" initiative (CCCCC → DDDDD →
EEEEE → FFFFF): real CERT-analyst memory-forensics coverage from a
process-tree-only starting point to eager DLL/suspicious-region/file/
registry listings plus a fully real, live-verified on-demand byte
extraction and registry drill-down path, front-to-back. Remaining
follow-ups (`pycryptodome` for `hashdump`/`lsadump`/`cachedump`, a final
full regression pass) are Milestone GGGGG, not this doc.
