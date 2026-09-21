# PoC: VMware `.vmsn`/`.vmss` companion-file support for `VolatilityModule`

**Closes the feature request from the "how do `.vmem`/`.vmsn` interact"
research session**: a real evidence upload of a VMware memory image
(`memory.vmem`) reached `COMPLETE` with every linked-list-walk Linux
plugin returning zero rows, because volatility3's own `VmwareStacker`
needs the companion `.vmsn`/`.vmss` file co-located on disk under a
matching basename to correctly interpret guest-physical memory regions —
and nothing in KronOS could supply that, since every evidence upload was
a fully independent object. This PoC — and the real feature it verifies
before/during/after building — closes that gap. Per `CLAUDE.md` §F/§G.5,
every step below was run for real against the real files, not assumed.

## Real files used throughout

Case `be2ae41a-0390-4f70-a65e-9c3f06f9ad0b`: `memory.vmem` (4 GiB) +
`memory.vmsn` (5.3 MiB), the project owner's own real VMware guest
memory capture. Local copies kept at `samples/` for fast repeated
iteration (gitignored — see `.gitignore`'s `poc/*/samples/` rule).

## Part 1 — proving the mechanism before writing any `src/` code

Staged both real files in the same directory under a matching basename
(exactly what `volatility3/framework/layers/vmware.py`'s `VmwareStacker`
requires — same-directory, same-basename filesystem adjacency, no flag
or API) and ran the real worker module's `_run_all_plugins()` directly.

| Plugin | Without `.vmsn` | With `.vmsn` staged correctly |
|---|---|---|
| `linux.pstree.PsTree` | 0 rows | Full real process tree (`systemd`, `vmware-vmblock-`, `vmtoolsd`, etc.) |
| `linux.pslist.PsList` | 0 rows | 344 real rows, each with a real `CREATION TIME` |

Decisive: the missing companion was the entire cause. `psscan` (pattern
scan, no address translation needed) was unaffected either way — expected,
consistent with the mechanism.

## Part 2 — implementation (domain → application → adapter → route → frontend)

- `Evidence.companion_evidence_id` (domain) + `COMPLETE → PARSING` FSM
  re-entry (a real, deliberate case, not a bug — re-parsing after a
  *successful* completion because new information arrived).
- `ParsingOrchestrationService.attach_companion_and_reparse()`
  (application): validates same-case, not-self, companion has finished
  intake; re-enters PARSING; re-enqueues.
- `CompanionFileResolver` (`src/external/parsers/volatility.py`): single-
  responsibility class, downloads the companion and writes it next to the
  primary temp file under a matching basename. Deliberately generic in
  its public contract (no VMware/Volatility naming) so a future parser
  needing its own multi-file format doesn't need a second resolver.
- `POST /api/evidence/{id}/companion` route + `EvidenceOut.canAttachCompanion`
  (mirrors `retryAction`'s "server computes the gate" shape).
- Frontend: `EvidenceDetailDrawer`'s new "Attach companion file" section,
  `attachCompanion()` API client call.

## Part 3 — real bugs found and fixed while verifying the built feature end to end

Verification-first surfaced four real, independent bugs — none guessed,
all confirmed by driving the real production Celery pipeline against the
real files, not unit tests alone:

### Bug 1: primary temp file leaked if companion staging raised
The companion-staging block originally ran *before* the `try/finally`
that deletes the primary evidence temp file. A real
`RuntimeError` while staging (see Bug 2) leaked a full 4 GiB temp file
every time it fired. Fixed by moving companion staging inside the same
`try/finally`. Regression test:
`test_primary_temp_file_cleaned_up_even_if_companion_staging_raises`.

### Bug 2: `get_evidence_repository()` doesn't work inside a Celery worker
The original design assumed this FastAPI-DI global getter was safe to
call anywhere post-startup (mirroring how `Settings()` is already
constructed inline in this exact method). Real, live-verified finding:
`celery_runtime.py`'s own module docstring already explains why — Celery
workers deliberately leave Postgres repositories unconfigured as process
singletons, building a fresh, event-loop-scoped
`PostgresEvidenceRepository` per task instead (avoids reusing an asyncpg
connection across a different `asyncio.run()` event loop). Calling the
global getter raised `RuntimeError: EvidenceRepository is not configured`
the first time this ran for real. Fixed by mirroring
`_build_task_resources()`'s own fresh-engine-per-call pattern exactly.

### Bug 3: two Linux plugins are pathologically slow on real data
Real per-plugin isolated timing (fresh subprocess each, no cumulative
shared-context memory pressure) against the real 4 GiB image:

| Plugin | Elapsed | Status |
|---|---|---|
| `linux.pstree.PsTree` | 24.7s | ok |
| `linux.psscan.PsScan` | 87.8s | ok |
| `linux.pslist.PsList` | 20.4s | ok |
| `linux.psaux.PsAux` | 20.0s | ok |
| `linux.bash.Bash` | 20.3s | ok |
| `linux.malware.malfind.Malfind` | **304.0s** | ok (but far slower than everything else) |
| `linux.library_list.LibraryList` | **>320s** | **timed out, never finished** |

Removed from `LINUX_DEFAULT_PLUGINS` (eager set) — same real, measured
reasoning `windows.consoles` was already excluded from `DEFAULT_PLUGINS`
for. Both remain available via the on-demand curated-plugin picker
(`VolatilityOnDemandService`) for an analyst who explicitly wants them.

### Bug 4 (the real root cause of the "still doesn't finish" reports): O(n²) artifact batching
Even after fixing Bug 3, a real companion-linked run still hit
`SoftTimeLimitExceeded` — but the actual Volatility scan now completed in
~7 minutes (healthy). The real culprit, found by process-of-elimination
timing analysis (a real 7 MiB Postgres JSONB insert of the exact
production content took **17.6ms** — ruling out the database) was
`rows_to_artifacts()`'s row-batching loop:

```python
for row in rows:
    candidate = [*batch, row]
    size = len(json.dumps(candidate, default=str).encode("utf-8"))  # O(n) EVERY row
```

Re-serializing the *entire growing batch* to JSON on every row is O(n²)
overall. Invisible against every plugin this module had ever been real-
verified against before (a few hundred rows) — but a real companion-
linked `linux.lsof.Lsof` result recovered **24,562 real rows** (correctly,
*because* the companion fix made lsof's underlying data walkable at all
for the first time), turning the O(n²) cost into a 30+ minute silent hang
inside one Python loop with no intermediate logging. Fixed by computing
each row's own serialized size exactly once and keeping a running total
— O(n). Regression test: `test_batching_is_linear_not_quadratic_in_row_count`
(25,000 real-shaped rows, asserts completion under 5s; the old code would
not finish within any reasonable test timeout).

### Also found: Celery's own automatic retry can race a manual re-dispatch
`kronos.parse_artefact_heavy` has `max_retries=2`. A task that hit
`SoftTimeLimitExceeded` earlier in this investigation was silently
retried by Celery itself ~2 minutes later, sitting in the broker
independent of any container restart — and that zombie retry's own
final-attempt failure raced against a fresh, manually-redispatched task
for the same evidence, flipping its state to `ERROR` moments after the
fresh task had legitimately started succeeding. Not a code bug to fix,
but a real operational lesson: check `celery_app.control.inspect()`'s
`scheduled()`/`reserved()`/`active()` before assuming a queue is
"empty" just because no container shows it running.

## Final, real, end-to-end result

`kronos.parse_artefact_heavy` succeeded in **513 seconds** total
(companion download + banner detection + 8-plugin scan + timeline ingest
+ artifact ingest), against the real production Celery pipeline, real
Postgres, real MinIO, real OpenSearch:

- Evidence reached `COMPLETE`, `error_reason: null`.
- `parse()` dual-emitted **344 real `TimelineRecord`s** (from
  `linux.pslist.PsList`'s real `CREATION TIME` column).
- `extract_artifacts()` persisted real `StructuredArtifact`s for every
  plugin in the trimmed eager set: `pstree`, `psscan` (1493 rows),
  `pslist` (344), `psaux` (344), `bash` (28), `lsof` (24,562 rows,
  correctly split across multiple 7 MiB-capped artifacts), `lsmod`,
  `hidden_modules`.

Also increased `kronos.parse_artefact_heavy`'s Celery time limits
(`src/external/celery_app.py`) and `VolatilityModule`'s own internal
timeout to a realistic budget for genuine forensic tooling processing
genuine large datasets — bounded, not infinite, but no longer tuned for
a web-request-shaped workload.
