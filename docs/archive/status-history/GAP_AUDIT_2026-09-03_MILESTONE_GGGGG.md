# Gap Audit — Milestone GGGGG (2026-09-03)

**Scope:** final cleanup checkpoint of the project owner's "huge work"
memory-forensics initiative (CCCCC → DDDDD → EEEEE → FFFFF): the
`pycryptodome` dependency gap named (but deliberately not fixed) in
Milestone CCCCC's own doc, plus a full E2E/a11y regression pass across the
whole initiative before considering it closed.

## `pycryptodome` fix

`docker/Dockerfile.plaso-worker` now installs `pycryptodome>=3.21.0,<4` —
the exact version constraint volatility3==2.28.0 itself declares under its
`extra == "full"` optional dependency (confirmed via
`importlib.metadata.distribution("volatility3").requires`, not guessed).
Real root cause (confirmed against the real installed package source, not
assumed): `windows.registry.{hashdump,lsadump,cachedump}` each do
`try: from Crypto.Cipher import ...` — without `pycryptodome`, that import
fails and (per the fallback branch's own comment) only Debian/Ubuntu-style
`Cryptodome`-namespace installs would recover it, which this image never
had either.

**Deliberately still not added to any analyst-facing plugin set this
cycle** — matches Milestone CCCCC's own scope note: real password/hash
material is a materially more sensitive capability than DLLs/malfind/
registry-keys and deserves its own explicit go-ahead, not silent
inclusion via a dependency fix. This closes only the "these three plugins
can't even import" infrastructure gap.

**Real, live verification**: rebuilt `celery-worker-plaso` for real
(`docker compose -p docker build/up --force-recreate` — the real running
project name, not the compose file's own declared `name: kronos-dev`, per
Milestone FFFFF's own finding), then inside the real container:
`from Crypto.Cipher import ARC4, DES, AES` succeeds; a real
`framework.import_files(volatility3.plugins, True)` call reports **zero**
import failures for `hashdump`/`lsadump`/`cachedump`; all six real plugin
variants (`windows.hashdump.Hashdump`, `windows.registry.hashdump.Hashdump`,
and the `lsadump`/`cachedump` equivalents) are correctly registered.

## Full E2E/a11y regression pass

Ran the complete 39-spec Playwright suite (`npx playwright test
--project=chromium`, no filter) against the live dev stack after all four
checkpoints' changes. **50 passed, 13 failed** (25.3 minutes). Every
Milestone CCCCC-FFFFF-specific spec passed:
`case-artifacts-ui.spec.ts` (Milestone DDDDD, 7-kind assertion — confirmed
unaffected by the new opt-in `--include-on-demand` seed flag),
`case-artifacts-on-demand-ui.spec.ts` (new, Milestone FFFFF), and the
extended Artifacts-tab `a11y.spec.ts` scan (now covering Child Files and
Registry Browser states too).

### The 13 failures are a real, pre-existing, unrelated environmental issue — not a regression

All 13 failures are in specs that need real OpenSearch timeline ingestion
(`evidence-upload*.spec.ts`, `evidence-parse-retry.spec.ts`,
`evidence-intake-retry.spec.ts`, `resilience-sse-drop.spec.ts`,
`visual-regression-pills.spec.ts`) or a second isolated compose stack
(`evidence-upload-storage-outage.spec.ts` — the already-documented Tier 2
item 8 "test-stack twin" gap, `container 'kronos-test-minio-1' not
found`). Investigated live rather than assumed:

1. `docker-opensearch-1` had restarted mid-run (`Up 41 seconds`,
   `OOMKilled=false`, `ExitCode=0`) under real host memory pressure
   (`free -h`: 526Mi free, 2.0Gi swap in use out of 4.0Gi — consistent
   with the already-documented Tier 2 item 8 host constraint).
2. After the restart, real bulk-index calls kept failing. A direct,
   minimal `_bulk` probe against the real running OpenSearch (not a
   guess) returned the real, decisive reason: `"this action would add [2]
   total shards, but this cluster currently has [1000]/[1000] maximum
   shards open"` — `cluster.max_shards_per_node`'s default (1000 for a
   single-node cluster) has been genuinely exhausted by months of
   accumulated real E2E-created case indices (this codebase's ISM
   rollover convention creates a new index per case per month, never
   deleted — a real, previously-undocumented finding, now recorded as
   Tier 2 item 11 in `docs/HANDOFF_AND_ORCHESTRATION.md`).
3. Confirmed this is unrelated to any code this initiative touched:
   `StructuredArtifact` (everything Milestones CCCCC-FFFFF built)
   persists via `PostgresArtifactRepository`, never OpenSearch bulk
   indexing at all — exactly why the artifact-tab specs above were
   immune while `TimelineRecord`-dependent specs weren't.

**Deliberately not fixed this session**: freeing shard capacity means
either deleting old E2E-created indices or raising
`cluster.max_shards_per_node` — both are real, impactful operational
choices on a long-lived shared host this agent didn't provision, not an
agent's unilateral call (CLAUDE.md's own destructive-action guidance).
Flagged in `HANDOFF_AND_ORCHESTRATION.md` for the project owner instead of
guessed at.

## Backend

Full backend suite re-run after the `pycryptodome` Dockerfile change (no
`src/` changes this cycle): `1994 passed, 1 skipped`, 89.13% coverage,
`ruff` clean — unaffected, as expected (a Dockerfile-only change).

## Status — full initiative closed

This closes Milestones CCCCC → GGGGG, the complete "huge work" real
CERT-analyst memory-forensics expansion the project owner requested:
process tree/listing → DLLs/suspicious-regions/files-in-memory/registry
hives (eager) → on-demand byte extraction and registry drill-down
(backend, then frontend) → dependency cleanup and full regression. Every
real external-tool integration in this initiative (volatility3, MinIO,
Celery, the real worker subprocess boundary) was verified against real
running services with real captured output at every step, per CLAUDE.md
§F — including, this cycle, catching a real cluster-capacity issue on the
shared dev host that predates and is unrelated to any of this initiative's
own code.
