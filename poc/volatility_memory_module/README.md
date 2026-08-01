# PoC: Volatility3 memory-dump module (roadmap E5)

Real, captured verification for `VolatilityModule` (`src/external/parsers/volatility.py`)
+ `VolatilityLauncher` (`src/external/sandbox/volatility_launcher.py`), per
CLAUDE.md Section F. See `output.txt` for the full, real, captured transcript
of the last run described below.

## Versions pinned

- **`volatility3==2.28.0`** — re-confirmed current on PyPI at the start of
  this pass: `pip index versions volatility3` listed `2.28.0` as the top
  (latest) entry, matching `reviews/DFIR_Artifact_Landscape.md`'s prior
  research. Base install pulls in only `pefile>=2024.8.26` (verified via
  `pip download --no-deps` + inspecting the wheel's own `METADATA`) — light
  enough to add to `docker/Dockerfile.plaso-worker`'s existing builder stage
  rather than needing its own Dockerfile variant (see that file's own
  comment for the full reasoning).
- Python: this repo's pinned dev interpreter (`~/venv`, Python 3.14) and a
  separate scratch venv used only for this PoC's own `vol` CLI invocations.

## Real sample

- **`cridex.vmem`** (Windows XP SP3, Cridex/Feodo banking trojan), downloaded
  from the documented Wayback Machine snapshot:
  `https://web.archive.org/web/20210304131300/http://files.sempersecurus.org/dumps/cridex_memdump.zip`
- Real, captured download: `HTTP_CODE:200 SIZE:40352364` (40,352,364 bytes),
  matching the `Content-Length: 40352364` already documented in
  `reviews/DFIR_Artifact_Landscape.md`.
- Real sha256 of the downloaded zip:
  `6453d0986352f7d5287cb90eeb6b72bc7bc16b03e964bb5767d93f85c3a483b2`
- Extracted `cridex.vmem`: 536,870,912 bytes (512 MiB), real sha256:
  `02a63be2fcf3a63446c3c8ca9151aff963f888204d141e46c6be60ddde7c3e8d`
- **Never committed to this repo** — downloaded to a local scratch path
  (`/home/reca/scratch/kronos-poc-volatility/` on the machine this PoC ran
  on) outside the git working tree. Treated the fetched zip as untrusted
  data only (no embedded-instruction content found in the binary; nothing to
  flag).

## Magic-byte / detection finding (real, verified — the open question this
item was told to resolve)

Read the real file's own first 4096 bytes directly:

```
first 16 bytes: b'S\xff\x00\xf0S\xff\x00\xf0\xc3\xe2\x00\xf0S\xff\x00\xf0'
PAGEDUMP in first 4096 bytes: False
PAGEDU64 in first 4096 bytes: False
LiME magic bytes 'LiME' in first 4096 bytes: False
```

**Finding: no verified magic bytes exist for this real sample.** `cridex.vmem`
is a bare physical-memory snapshot (no crash-dump header, no LiME header) —
raw kernel page-table bytes start at offset 0 with no file-format header at
all. This confirms the open question `reviews/DFIR_Artifact_Landscape.md`
§2 flagged: Microsoft crash-dump (`PAGEDUMP`/`PAGEDU64`) and LiME magics are
real, documented signatures *for those specific formats*, but this repo's
one real sample is neither — it's a plain `.vmem` capture, which genuinely
has no header. **Extension-only detection is the honest answer** for at
least the `.vmem`/raw case, exactly as the roadmap item anticipated. Wired
into `MagicByteValidator._MEMORY_DUMP_EXTENSIONS` and
`VolatilityModule.supports()` as `.vmem`/`.mem`/`.raw`/`.dmp`/`.lime` — the
`.dmp`/LiME magics themselves were **not** independently verified against a
real sample of those specific formats in this pass (none was downloaded);
this is stated honestly rather than invented.

**Collision check against `PlasoParser`'s real fixed-offset magics** (the
reason `VolatilityModule` is registered *last*, after `PlasoParser`, in
`get_parser_registry`): read the real sample's own bytes at every one of
`PlasoParser`'s fixed magic offsets — none collide:

```
offset3-11 (NTFS):               b'\xf0S\xff\x00\xf0\xc3\xe2\x00'
offset54-62 (FAT16/12):          b'\x00\xf0W\xef\x00\xf0P\xf5'
offset82-90 (FAT32):             b'\x00\xf0Y\xf8\x00\xf0e"'
offset1080-1082 (ext superblock): 0000
offset0-4 (REGF):                b'S\xff\x00\xf0'
offset0-15 (SQLite):             b'S\xff\x00\xf0S\xff\x00\xf0\xc3\xe2\x00\xf0S\xff\x00'
offset0-9 (EWF):                 b'S\xff\x00\xf0S\xff\x00\xf0\xc3'
```

## Real finding: `windows.pstree`/`windows.pslist` return zero rows for this
sample + version — not a wrapper bug

Ground-truth, bare `vol` CLI runs (no KronOS code at all):

```
$ vol -q -r json -f cridex.vmem windows.info      -> Kernel Base 0x804d7000, DTB 0x39000,
                                                       NtBuildLab 2600.xpsp.080413-2111 (real XP SP3)
$ vol -q -r json -f cridex.vmem windows.pslist     -> []   (returncode 0, no exception)
$ vol -q -r json -f cridex.vmem windows.pstree     -> []   (returncode 0, no exception)
$ vol -q -r json -f cridex.vmem windows.psscan     -> 17 real process rows (System, smss.exe,
                                                       csrss.exe, winlogon.exe, services.exe,
                                                       lsass.exe, svchost.exe x4, spoolsv.exe,
                                                       explorer.exe, alg.exe, wuauclt.exe x2,
                                                       reader_sl.exe) -- matches the well-known
                                                       public census of this classic sample.
```

Independently confirmed this is real and not a mistaken invocation:
- `windows.info` proves the kernel base / DTB / symbol table (a real,
  bundled `ntkrnlpa.pdb` ISF) resolve correctly for this exact image.
- `-vvv` output shows `Successfully constructed windows.pslist.PsList`
  followed by zero yielded rows — no exception anywhere in the trace.
- `windows.pslist --pid 4` (PID 4 = "System", confirmed present via
  `psscan`) still returns nothing — ruling out a plain filter/argument
  mistake.
- `windows.pslist --physical` / `windows.pstree --physical` — same, empty.

Root cause (not fully resolved, out of scope to chase further this pass):
`windows.pslist`/`pstree` walk the kernel's `PsActiveProcessHead` doubly-
linked list (`ActiveProcessLinks`); `windows.psscan` is an independent
pool-tag scanner that never touches that linked list. A GitHub issue search
turned up known XP-era pslist problems in volatility3 (e.g. issue #524) but
nothing pinpointing this exact zero-row symptom — treated as a genuine,
reproducible tool/sample-era interaction, not a bug in this repo's own
wrapping code (proven by the bare-CLI runs above, which involve zero KronOS
code).

**Resulting design decision:** `kronos-volatility-worker.py` runs the
configured primary plugin (`windows.pstree` by default) and, only if its own
JSON result is an empty list, automatically also runs a configured fallback
plugin (`windows.psscan` by default) against the same file and reports both.
`VolatilityModule.extract_artifacts()` yields one `StructuredArtifact` per
plugin that actually ran — `kind="volatility.pstree"` (real, honestly empty
for this sample) and, because the primary came back empty,
`kind="volatility.psscan"` (real, 17 rows) — see `output.txt` STEP 5.

## Real run transcript

See `output.txt` for the complete, real, captured output of the last run of
`run_poc.py`, covering all 5 steps:

1. Real sample presence + sha256.
2. Real magic-byte investigation (reproduced above).
3. Ground-truth bare `vol` CLI runs for `windows.info`/`windows.pstree`/`windows.psscan`.
4. The real, sandboxed `VolatilityLauncher` (subprocess + JSON-io) run against
   the same real file — `used_fallback: True`, 17 real fallback rows.
5. The real `VolatilityModule.extract_artifacts()` run — 2 real
   `StructuredArtifact`s (`volatility.pstree` empty, `volatility.psscan` with
   17 rows), each carrying a real, fully-populated `EvidenceProvenance`
   block.

To reproduce:

```bash
# 1. Download + verify the sample (see URL/sha256 above), then:
python3 -m venv /tmp/vol-scratch-venv
/tmp/vol-scratch-venv/bin/pip install volatility3==2.28.0

# 2. Run the PoC with vol on PATH and the real sample path set:
PATH="/tmp/vol-scratch-venv/bin:$PATH" \
  KRONOS_CRIDEX_VMEM_PATH=/path/to/cridex.vmem \
  DATABASE_URL=postgresql+asyncpg://x:x@localhost/x REDIS_URL=redis://localhost \
  MINIO_ENDPOINT=localhost:9000 MINIO_ACCESS_KEY=x MINIO_SECRET_KEY=x \
  OPENSEARCH_URL=https://localhost:9200 OPENSEARCH_USERNAME=x OPENSEARCH_PASSWORD=x \
  KEYCLOAK_URL=https://localhost KEYCLOAK_CLIENT_SECRET=x \
  VAULT_URL=https://localhost:8200 VAULT_TOKEN=x \
  CELERY_BROKER_URL=redis://localhost CELERY_RESULT_BACKEND=redis://localhost \
  ~/venv/bin/python3 poc/volatility_memory_module/run_poc.py
```

(The dummy `DATABASE_URL`/etc. values are only needed because
`VolatilityModule.extract_artifacts()` instantiates the real `Settings()` to
read `volatility_worker_path` — it never connects to any of those services;
see `src/external/parsers/volatility.py`.)

The same real sample also exercises `tests/unit/test_volatility_launcher.py`'s
`test_real_worker_falls_back_to_psscan_on_real_cridex_sample` when
`KRONOS_CRIDEX_VMEM_PATH` is set in the environment; skipped, not failed,
when unset (mirrors this repo's existing `pytest.importorskip("evtx")`
pattern for an optional real-artifact dependency).

## Docker image build (real, not assumed)

`docker/Dockerfile.plaso-worker` was rebuilt with `volatility3==2.28.0` added
to the shared builder-stage `pip install` and
`docker/volatility/kronos-volatility-worker.py` added to the final stage's
`COPY` list (mirroring `docker/plaso/kronos-plaso-worker.py`'s own COPY —
and explicitly *not* repeating roadmap E4's left-over gap, where
`docker/yara/kronos-yarax-worker.py` was never `COPY`'d into this same
Dockerfile). Built for real as `kronos-poc-volatility-worker:test`; verified
inside the built image (not assumed) that:

- `vol --help` runs and reports `Volatility 3 Framework 2.28.0`.
- `/app/volatility-worker/kronos-volatility-worker.py` exists at the exact
  path `VOLATILITY_WORKER_PATH` points to.

See this PoC's own captured build/verify commands in the main task report
for the exact commands and output.

## Gaps / honestly out of scope this pass

- **Full HTTP upload -> validate -> parse -> Postgres pipeline was not
  driven end-to-end** for this item — `run_poc.py` stops at
  `VolatilityModule.extract_artifacts()` producing real, in-memory
  `StructuredArtifact` objects (step 5). Wiring through
  `ArtifactIngestService`/Postgres/the Celery `q.parse.plaso` queue for real
  is the natural next verification step, not attempted here due to time
  budget — an honestly-scoped fallback per the roadmap brief's own explicit
  permission to stop short of full pipeline integration.
- **`.dmp` (Microsoft crash dump) and `.lime` magic bytes were not verified**
  against a real sample of either format — only `cridex.vmem` (a plain raw
  `.vmem`) was downloaded and inspected. Extension-only detection covers
  both regardless, so this is a documentation gap, not a functional one.
- **Timeline-shaped plugins (`timeliner`, `pslist`/CreateTime,
  `windows.netscan`) are not wired** — `VolatilityModule.parse()` is a
  documented no-op; only `extract_artifacts()` does real work this pass, per
  the roadmap item's own explicit scope boundary.
- **Only `windows.pstree`/`windows.psscan` were exercised** — `malfind`,
  `filescan`, `dlllist`, etc. are a natural, low-risk follow-on once this
  wrapping mechanism is proven (which it now is), not attempted here.
- **Only a Windows XP sample was used** (`cridex.vmem` is XP-only) — Linux/
  macOS memory samples are out of scope for this item per the roadmap
  brief.
