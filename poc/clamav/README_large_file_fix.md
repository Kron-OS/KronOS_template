# Fix: large forensic files (e.g. real .E01 images) failing intake with `intake_failed:BrokenPipeError`

**Reported by the user**: uploading a real 239.3 MB `forensic2.E01` landed
on `ERROR` with `errorReason: "intake_failed:BrokenPipeError"`, and every
retry (including via `retry-intake`) failed identically.

## Root cause, confirmed against the real running ClamAV container

`docker exec docker-clamav-1 clamconf` showed the real, compiled-in default:

```
StreamMaxLength = "104857600"   # 100 MB
MaxFileSize     = "104857600"   # 100 MB
```

KronOS's own upload ceiling (`src/config.py Settings.max_upload_bytes`) was
1 GB — 10x higher than clamd's real stream-scanning limit. `clamd`'s
`INSTREAM` protocol closes the TCP connection the instant a stream exceeds
`StreamMaxLength`; `ClamAVScanner.scan_stream()`
(`src/application/scanning.py`) had no size check and no handling for an
early-closed connection, so it just kept writing chunks from the async
generator until the OS raised a raw `BrokenPipeError` on a write to the
now-dead socket.

Confirmed via `run_poc_large_file_before_fix.py` (`output_large_file_before_fix.txt`,
5/5 checks): a real 239 MB clean stream against the real, then-unmodified
`docker-clamav-1` reproduces the *exact* reported error type
(`BrokenPipeError: [Errno 32] Broken pipe`), deterministically on a second
identical attempt — explaining why the user's own retry also failed instead
of "just working."

## The fix

1. **`src/config.py`**: `max_upload_bytes` default raised from 1 GB to
   **5 GiB** (`5_368_709_120`), documented as needing to stay `<=` clamd's
   real configured limit.
2. **`docker/docker-compose.dev.yml`**:
   - `MAX_UPLOAD_BYTES` added to `kronos-backend`/`celery-worker` (the two
     services that run `EvidenceIntakeService`/`process_intake`).
   - `CLAMD_CONF_StreamMaxLength`/`CLAMD_CONF_MaxFileSize`/
     `CLAMD_CONF_MaxScanSize` added to the `clamav` service — the real
     `clamav/clamav:stable` image's own `/init` entrypoint reads any
     `CLAMD_CONF_<Setting>` env var and rewrites the matching `clamd.conf`
     directive (verified by reading `/init` inside the real container, then
     confirmed end-to-end against a real throwaway container).
   - All three driven by one shared `${KRONOS_MAX_UPLOAD_BYTES:-5368709120}`
     so the two limits can't drift apart again, and the ceiling is
     configurable via a single env var without editing the compose file.
3. **`src/application/scanning.py`**: `ClamAVScanner.scan_stream()` now
   catches `BrokenPipeError`/`ConnectionResetError` during the write loop
   and raises a clear `StorageError` ("clamd closed the connection while
   streaming — the file likely exceeds clamd's configured
   StreamMaxLength/MaxFileSize") instead of letting a raw, opaque exception
   propagate — defense-in-depth if the two limits ever drift apart again
   (e.g. someone overrides `MAX_UPLOAD_BYTES` without also updating the
   `clamav` service's env vars).

## Verified, for real

- **Unit**: 2 new tests in `test_scanning_clamav.py` covering the
  `BrokenPipeError`/`ConnectionResetError` → `StorageError` handling
  (mocked socket). Full suite: 622/622 unit tests pass, no regressions.
- **Isolated scanner, real clamd** (`run_poc_large_file_after_fix.py`,
  `output_large_file_after_fix.txt`, 6/6): confirmed the real, rebuilt
  `docker-clamav-1` now reports `StreamMaxLength`/`MaxFileSize`/
  `MaxScanSize` = `5368709120`; the exact previously-failing 239 MB stream
  now scans clean, twice (deterministic); a 1.5 GB stream (realistic large
  forensic image size) also scans clean.
- **Full end-to-end through the real API**
  (`run_poc_e01_e2e_after_fix.py`, `output_e01_e2e_after_fix.txt`, 7/7):
  real PKCE login, real case, a real 239.3 MB file (exact reported size,
  `250,923,489` bytes) with a real EWF magic header, real PUT to MinIO, real
  finalize — evidence reaches `PARSING` with `errorReason: None`, not
  `ERROR/intake_failed:BrokenPipeError`.

## Not yet done / out of scope

- `docker-compose.prod.yml` was not touched — the user's instruction scoped
  this to dev env variables specifically. Production deployments need the
  equivalent `MAX_UPLOAD_BYTES`/`CLAMD_CONF_*` wiring before this fix
  applies there too.
- Helm chart (`charts/kronos/`) likewise has no equivalent wiring — same
  pre-existing gap already flagged for `CLAMD_HOST` in
  `poc/evidence_intake_async/README.md`.
