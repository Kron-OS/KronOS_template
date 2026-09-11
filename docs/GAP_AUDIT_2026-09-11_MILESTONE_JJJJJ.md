# Gap Audit — Milestone JJJJJ (2026-09-11)

**Scope:** the project owner reported that most memory-dump evidence on a
real case (`https://kronos.local/cases/43097ab0-aae3-4968-915b-8f0229ac3865`)
wasn't producing analysis results, and asked for the root cause (real file
type / format checks, not guessed) plus a plan to fix it.

## Real diagnosis (no code changed yet at this stage)

Queried the real case's 10 evidence rows directly (Postgres +
real header-byte inspection from MinIO). Only `Challenge.raw` (a genuine
1.6 GB Windows 7 memory image) had ever produced artifacts. Found four
distinct, real root causes:

1. **`ch2.dat`** (`state=ERROR`, `validation_failed`) — raw memory has no
   reliable magic bytes at all (confirmed live), so `MagicByteValidator`
   only accepted memory dumps by a fixed extension allowlist
   (`.vmem/.mem/.raw/.dmp/.lime`). `.dat` wasn't on it.
2. **`ch2.dmp`/`ch2.vmem`/`contact_me.dmp`/`.raw`/`.mem`** (all
   `state=COMPLETE`, 0 artifacts) — correctly routed to `VolatilityModule`,
   but volatility3's own automagic genuinely can't identify these images'
   kernel (`WindowsIntelStacker` finds a real DTB, `KernelPDBScanner` finds
   no kernel) — a real, external limitation, and the analyst had zero
   visibility into *why* (the empty-state message claimed "check the Audit
   tab," which never actually contained a reason).
3. **`forensic2`** (no extension, `state=COMPLETE`, 0 artifacts, routed to
   Plaso) — real magic bytes confirmed genuine EWF/E01, but its real media
   payload (extracted via `pyewf`, `poc/ewf_memory_extraction/`) turned out
   to be a **tar archive** containing `image.dd` + `memory.dmp` — an
   already-documented incident (`TarArchiveParser`'s own docstring,
   roadmap E1) at a layer nothing had unwrapped yet: an EWF container
   whose own payload is itself a container.
4. **The product's own diagnostic message was false** — Volatility failures
   were silently discarded with a comment claiming they were "logged
   elsewhere," but nowhere the analyst could actually see.

## What was built

### Phase 1 — Stop the silent Volatility failures
- `VolatilityModule.extract_artifacts()` (`src/external/parsers/
  volatility.py`) now yields a `volatility.diagnostic` `StructuredArtifact`
  (real per-plugin error strings, e.g. `"UnsatisfiedException: "`) when
  **every** plugin in a run fails, instead of silently producing nothing.
- **Real, deeper bug found along the way**: `VolatilityLauncher.run()`
  (`src/external/sandbox/volatility_launcher.py`) itself *raised* and
  discarded every plugin's real error whenever all plugins failed — so the
  new diagnostic artifact was unreachable until this was also fixed to
  return the result normally (only a truly empty `plugins` payload — no
  plugin even attempted — still raises).
- Frontend: `VolatilityDiagnosticView` (`ArtifactViews.tsx`) renders the
  real per-plugin errors; `CaseDetailPage.tsx`'s case-wide empty-state text
  no longer claims the Audit tab has detail it never had.
- **Live-verified** against the real `ch2.dmp`/`contact_me.dmp` bytes with
  production's full 7-plugin set: both now produce a real
  `volatility.diagnostic` artifact with the actual captured error text.

### Phase 2 — Accept a memory dump under any extension
- `EvidenceMetadata.declared_format` (new, optional, additive field) lets
  an analyst explicitly declare "this is a memory image" at upload time.
  Threaded through `UploadRequestIn.declaredFormat` (route DTO, `Literal["memory_dump"] | None`),
  `EvidenceIntakeService.request_upload`, `MagicByteValidator` (bypasses
  its magic-table check when set), and `ParsingOrchestrationService.
  _detect_parser` (short-circuits straight to the registered `volatility3`
  parser via new `ParserRegistry.get_by_name`).
- **Real bug caught only by a Postgres-backed integration test, not the
  in-memory unit tests**: `declared_format` was added to the domain model
  but `PostgresEvidenceRepository`'s row mapping (`_to_row`/`_from_row`)
  was never updated, so real Postgres silently dropped the value on
  re-fetch. Fixed (new `declared_format` column,
  `migrations/versions/20260910_2130_c3d8f6a91b02_...py`), applied to the
  real dev DB, and confirmed with a new
  `test_declared_format_round_trips_through_real_postgres` test.
- Frontend: `UploadDrawer.tsx` gains a "This is a memory image" checkbox;
  `validateFileMagic.ts`'s own client-side pre-check honors the same
  override.
- **Live-verified end-to-end**: two new Playwright specs
  (`evidence-upload-declared-memory-format.spec.ts`) reproduce the
  original rejection without the checkbox and confirm the same bytes
  upload successfully with it, against the real dev-stack backend/Postgres.

### Phase 3 — Unwrap EWF containers that wrap another container
- New `EwfContainerParser` (`src/external/parsers/ewf_container.py`),
  registered ahead of `PlasoParser`. Unwraps every EWF file's real media
  payload (via `pyewf` — already installed, a transitive `dfvfs`
  dependency, **no new dependency added**) and either (a) re-dispatches it
  through the existing `ParserRegistry` if the decoded media matches a
  known container (the real `forensic2` case — lands on
  `TarArchiveParser`, which already correctly routes `image.dd` to Plaso
  and `memory.dmp` to `VolatilityModule`, **zero further changes needed**
  to either), or (b) falls back to `PlasoParser` on the original,
  un-decoded EWF bytes — today's existing, unchanged behavior for a
  genuine EWF disk image. Shares `TarArchiveParser`/`ZipArchiveParser`'s
  own recursion-depth/extraction-budget `ContextVar`s.
- **Automatic, not on-demand** — a deliberate change from the originally
  planned design (an analyst-triggered button): real measurement showed
  the EWF-peek step is cheap regardless of file size (sub-second even for
  the real 250 MB `forensic2`), and Volatility only actually runs when the
  decoded media genuinely contains a `.dmp`-extension tar member — so there
  was no real cost problem to gate behind a manual click. This also means
  **no new route/Celery task/frontend button was needed at all** — the fix
  is fully automatic via the existing ingest pipeline.
- Real PoC (`poc/ewf_memory_extraction/`) against the real `forensic2`
  bytes: confirmed the extracted media is a genuine POSIX `ustar` tar
  header (not memory — 0 DTB hits when volatility3's automagic is run
  directly against it, decisively different from `ch2.dmp`'s real-DTB
  result).
- **Live-verified against real production data**: calling the real,
  wired `get_parser_registry()` against the real `forensic2` bytes now
  selects `ewf-container` and yields 6 real `volatility3` process-creation
  events (`System`, `csrss.exe`, `wininit.exe`, real 2016 timestamps).
  **Regression check**: the same call against a real, genuine EWF disk
  image already on this case (`CNC.E01`) yields the identical 15 records
  a direct `PlasoParser` call produces — byte-for-byte unchanged behavior
  for the common case.

## Known, deliberately out-of-scope follow-up

`TarArchiveParser.extract_artifacts()` is YARA-scan-only — it does not
recursively call each member's own `extract_artifacts()`. This means a
tar-wrapped `memory.dmp` (EWF-wrapped or not) gets Volatility's real
dual-emit timeline records (via `parse()`, confirmed above) but not its
richer `StructuredArtifact` output (process tree table, DLL list, malfind,
etc.) — a real, pre-existing `TarArchiveParser` limitation, not introduced
by this work, and not fixed here given scope. Flagged, not silently
ignored — the next real gap-audit pass should consider extending
`TarArchiveParser`/`ZipArchiveParser`'s own member recursion to also
dispatch `extract_artifacts()`, symmetrically for both container types.

Volatility3's own inability to identify `ch2.dmp`/`contact_me.dmp`'s
kernel (root cause #2) is a genuine external limitation, not a KronOS bug
— Phase 1 makes that failure honestly visible; it is not "fixed" because
it cannot be.

## Verification

- Full backend suite: `2052 passed, 2 skipped`, 89% coverage, `ruff`/`mypy`
  clean on every touched file.
- Full frontend suite: `tsc`, `oxlint`, `vitest` (135 tests) clean.
- Real dev-stack E2E: new declared-format Playwright specs passing against
  the real backend/Postgres/browser.
- Real production-path verification (not a synthetic test) against actual
  evidence already on this dev stack, both the fixed case (`forensic2`)
  and a regression check (`CNC.E01`), via the real, wired parser registry.

## Delivery

Three separable commits (one per phase), pushed to
`feat/nextgen-soc-cert-platform`, no PR, per this session's standing
convention.
