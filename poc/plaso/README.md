# PoC: real Plaso parse of a real forensic artifact

## Versions (pinned, read from this repo — not assumed)
- Plaso: `20260512`, exactly as pinned in `docker/plaso/Dockerfile`
  (`pip install plaso==20260512`).
- Built into a real image: `kronos-poc-plaso:20260512`, built from the
  actual `docker/plaso/Dockerfile` in this repo (multi-stage, Chainguard
  Python base, same as production `docker/Dockerfile.plaso-worker`).
- Sample artifact: `tests/fixtures/samples/real/CMD.EXE-087B4001.pf` — a
  real Windows Prefetch file from Plaso's own test corpus (see
  `tests/fixtures/samples/real/NOTICE.md`), not a hand-crafted fixture.

## What this actually does
`run_poc.sh` runs the **real** `docker/plaso/kronos-plaso-worker.py` — the
exact script `FirecrackerLauncher` execs in production — as the container's
`ENTRYPOINT`, against the real sample file, and captures its JSONL stdout.

```
./poc/plaso/run_poc.sh
```

## Real findings — two confirmed bugs that made Plaso parsing a silent no-op

Before any fix, this PoC's first run produced only the worker's own
"honest placeholder" event, never real Plaso output. Root-caused by running
the actual pinned tools directly inside the actual image, not by reading code:

1. **`log2timeline.py` / `psort.py` are not the real binary names.**
   `plaso==20260512` installs unsuffixed `setuptools` console_scripts
   (`log2timeline`, `psort` — confirmed via
   `importlib.metadata.distribution("plaso").entry_points` and `ls
   /opt/plaso-venv/bin` inside the built image). `_find_tool()` searched for
   the legacy `.py`-suffixed names, always got `None`, and the worker always
   silently emitted the placeholder event — meaning **every prior "Plaso
   parsing" in this repo, however tested, never actually invoked Plaso.**
   **Fixed:** `docker/plaso/kronos-plaso-worker.py` now tries the unsuffixed
   name first, `.py` as a fallback.

2. **`psort -w <path>` refuses to write to a file that already exists.**
   The worker deliberately pre-creates `json_path` via `tempfile.mkstemp()`
   for TOCTOU safety (its own comment cites "EVID-11"), but psort's real CLI
   behavior (confirmed by direct invocation — see console capture below) is
   `ERROR: Output file already exists` and a non-zero exit when the target
   is already present — the opposite of log2timeline, which happily
   overwrites its pre-created storage file. **Fixed:** worker still reserves
   a unique unpredictable name via `mkstemp` (keeping the actual EVID-11
   guarantee), then `os.unlink()`s it immediately before invoking psort.

3. **Timestamps were silently replaced with wall-clock "now" for every
   record.** psort's `json_line` output for this pinned version carries the
   real event time as a plain int (`"timestamp": 1362910309281250`,
   *microseconds since 1970-01-01* — confirmed by manual conversion,
   `1362910309281250 / 1e6` ≈ 2013-03-10, a plausible date for this Plaso
   test-corpus sample), not the ISO-8601 string
   `src/external/sandbox/firecracker.py`'s `_stream_records()` assumed
   (`isinstance(ts_raw, str)` was the only branch handled; everything else
   fell back to `ingest_ts` = `datetime.now(UTC)`). This is confirmed in
   `poc/plaso_opensearch/output.txt`: before the fix, every record would have
   carried today's date instead of the artifact's real forensic timestamp —
   silently defeating the entire purpose of a *timeline* tool. **Fixed:**
   `_stream_records()` now also handles the int/float microsecond-epoch case.

## After the fixes: 5 real events extracted

```
INFO Plaso parse complete: 5 events
```

First record (see `output.jsonl` for all 5): a real
`windows:prefetch:execution` event — `executable: CMD.EXE`, `run_count: 2`,
`mapped_files` listing real DLL paths, `timestamp: 1362910309281250` (µs
epoch ≈ 2013-03-10T10:11:49Z), and Plaso's own generated human-readable
`message` field. See `output.jsonl` for the full raw captured output and
`console_output.txt` for the full run transcript (including the pre-fix
placeholder-only run at the top, for contrast).

