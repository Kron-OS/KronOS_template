# PoC: real windows.dumpfiles byte extraction mechanism

**Version pinned**: `volatility3==2.28.0` (`docker/Dockerfile.plaso-worker`).
Run for real inside the live `docker-celery-worker-plaso-1` container.

## What this verifies (Milestone EEEEE, plan Stage 3.6 item 3 -- the
highest-risk item in the approved plan)

1. That `windows.dumpfiles` genuinely extracts real bytes via volatility3's
   real `FileHandlerInterface` (`close()` receives the accumulated bytes) --
   confirmed, not assumed.
2. Which real CLI targeting parameter (`--pid`, `--virtaddr`, `--physaddr`)
   is the right fit for a scoped, single-click "Extract this file" analyst
   action driven from a real `filescan` row -- resolved empirically, not
   guessed, after an initial wrong assumption was caught and corrected
   within this same PoC.
3. Real measured file sizes, to resolve the plan's open bytes-transport
   question (temp-file vs. base64-in-JSON).

## Real sample

The same real 1.6 GB user-uploaded Windows 7 image already used in
`poc/volatility_multiplugin/` (`Challenge.raw`, real user-owned
investigative data on this org's live MinIO, not redistributed).

## Real, captured results (`output.txt`)

- **`--pid 2080`** (firefox.exe): real, working extraction -- 239 real
  files captured, several **over 1 MB** (`ole32.dll.img` 2,063,872 bytes,
  `kernel32.dll.img` 1,132,032 bytes). Confirms the mechanism works, but
  process-scoped targeting is far too broad for a single UI action.
- **First `--virtaddr` attempt**: 0 rows -- but this reused an `Offset`
  value captured from a *separate*, earlier scan invocation. Real, honest
  negative result, but not yet conclusive on its own (see below).
- **`run_poc_targeted.py`** (the corrected, decisive test): gets fresh
  `filescan` rows and immediately tries both `--virtaddr` and `--physaddr`
  against the *same* offset, in the *same* automagic-resolved context, to
  eliminate any staleness. Real result: `--virtaddr` still 0 rows;
  **`--physaddr` succeeds**, extracting a real 49,152-byte Firefox cache
  file (`.../cache2/entries/F3A2A55211EE66D36F43F15EFF501E9546680661`).

**Conclusion, verified not guessed**: `windows.filescan`'s own `Offset`
column is a **physical** address (real, consistent with pool-tag scanning
operating on physical memory, not a virtual-address walk) -- the real
mechanism for a scoped "Extract this file" action is
`plugins.DumpFiles.physaddr = [offset]` against a `filescan` row's own
`Offset`, not `virtaddr`.

## Resolving the plan's open bytes-transport question

Real measured sizes (49 KB for one targeted file; up to 2 MB+ per file seen
in the broader `--pid` sweep) confirm base64-in-JSON is the wrong choice
for the worker's stdout contract -- a single multi-MB file would bloat
~33% larger as base64 plus real JSON-parse overhead for what could be tens
of MB across a batch. **Decision: the worker writes extracted bytes to a
real temp file (mirroring `PoCFileHandler`'s own `close()` -> real
`open(path, "wb")` pattern proven here), emits the temp path + real
`sha256`/`size_bytes` in the JSON envelope, and the launcher (already-
trusted `celery-worker-plaso` process, not the sandboxed subprocess) reads
that temp file and uploads to MinIO, then deletes it** -- symmetric to how
`VolatilityLauncher._run_volatility` already writes the *evidence itself*
to a `NamedTemporaryFile` before invoking the worker; no new sandboxing
weakness.

## Status

**PASS.** Real mechanism, real targeting parameter, and the bytes-transport
design are all resolved with real evidence. Proceeding to
`DerivedArtifactStorage` (PoC 5) and the worker/launcher/route
implementation using `--physaddr` targeting from a real `filescan` row's
`Offset`.

## Re-verification against the real, shipped worker script (Milestone EEEEE)

`docker/volatility/kronos-volatility-worker.py` was extended with a real
`--dumpfiles-physaddr OFFSET --dumpfiles-output-dir DIR` mode (the
`_run_dumpfiles()` function, using the exact `_KronosFileHandler`
mechanism this PoC proved). Run for real inside
`docker-celery-worker-plaso-1` against the same real `Challenge.raw`,
physaddr `0x53f3770` (88029040 decimal):

```
{"status": "ok", "error": null, "dumped_files": [{"filename":
"file.0x53f3770.0xfa80030456c0.DataSectionObject.F3A2A55211EE66D36F43F15EFF501E9546680661.dat",
"path": "/tmp/dumpfiles_out/file.0x53f3770.0xfa80030456c0.DataSectionObject.F3A2A55211EE66D36F43F15EFF501E9546680661.dat",
"sha256": "5c9d7a1952a6294ac6d631d8f564e0e50c939defecc347ff1f5fbdbc310f1f2c",
"size_bytes": 49152}]}
```

`size_bytes: 49152` matches this PoC's own decisive finding exactly. The
worker mode is now the real implementation `VolatilityLauncher` calls, not
just this scratch PoC script.
