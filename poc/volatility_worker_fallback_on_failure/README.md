# PoC: real user report -- "the volatility analysis result is not available"

## Versions (pinned, read from this repo/host)

- volatility3: `2.28.0` (`docker/Dockerfile.plaso-worker`)
- Real sample: `ch2.dmp`, a real 512MiB (536870912 bytes) memory image
  uploaded by a user through the live dev stack, case `43097ab0-aae3-4968-915b-8f0229ac3865`,
  evidence `19ddd4ea-d81c-4148-8a82-ddc54fcbd1d5`.
- `docker-celery-worker-plaso-1` (built from `docker/Dockerfile.plaso-worker`).

## The real report and the real investigation trail

A user reported the Artifacts tab showed nothing for this case. Evidence
`19ddd4ea-...` was genuinely `state=COMPLETE`, so it wasn't a stuck
pipeline. `docker exec docker-postgres-1 psql ... structured_artifacts`
confirmed zero rows. `docker logs docker-celery-worker-plaso-1` (real,
live container) showed `parse_artefact_heavy` "succeeded" with
`record_count: 0` and a `volatility_scan_failed` WARNING immediately
before it -- confirming `VolatilityModule._run_volatility()` caught a real
`VolatilityScanError` and degraded silently (per its own documented "one
bad thing doesn't sink the evidence" contract), but the `extra={...}`
fields on that log line aren't rendered by this container's plain-text
logging config, so the *reason* wasn't visible from `docker logs` alone.

Downloaded the real file from MinIO (`kronos-evidence-kronos-dev` bucket,
via `boto3`, `http://minio:9000`) and ran `VolatilityLauncher.run()`
directly, exactly as `_run_volatility()` does (same `Settings()`-resolved
`worker_path`), to get the real exception text:

```
FAILED VolatilityScanError Volatility worker exited with code 2:
/opt/venv/bin/python3: can't open file
'/app/docker/volatility/kronos-volatility-worker.py': [Errno 2] No such
file or directory
```

That was a **testing artifact**, not the real bug: my manual script had
omitted `worker_path=`, so `VolatilityLauncher` fell back to its own
source-repo-relative default instead of the real, correctly-set
`VOLATILITY_WORKER_PATH=/app/volatility-worker/kronos-volatility-worker.py`
env var (confirmed present and pointing at a real, existing file via
`docker exec ... python3 -c "import os; print(os.environ...)"`). Redone
with the real `Settings()`-resolved path, the real error was:

```
FAILED VolatilityScanError windows.pstree exited 1: Volatility 3 Framework 2.28.0
Unable to validate the plugin requirements: ['plugins.PsTree.kernel.layer_name', 'plugins.PsTree.kernel.symbol_table_name']
```

Ran the real `vol` CLI directly with `-vv` for full diagnostics
(`docker exec docker-celery-worker-plaso-1 /opt/venv/bin/vol -f /tmp/ch2.dmp -vv windows.info`):

```
DEBUG    volatility3.framework.automagic.windows: WindowsIntelStacker hits: []
DEBUG    volatility3.framework.automagic.windows: Found 4 valid pointers
DEBUG    volatility3.framework.automagic.windows: DTB 185000 contains less than 12 valid pointers, ignoring
INFO     volatility3.framework.automagic.pdbscan: No suitable kernels found during pdbscan
Unable to validate the plugin requirements: ['plugins.Info.kernel.layer_name', 'plugins.Info.kernel.symbol_table_name']
```

Confirmed empirically that the fallback plugin (`windows.psscan`) fails
**identically** against this same file (`vol -q -r json -f /tmp/ch2.dmp
windows.psscan`, real exit code 1, same "Unsatisfied requirement" text) --
both plugins share the same automagic kernel/DTB construction, so this is
a genuine, framework-level "volatility3 cannot identify this image's
OS/kernel structures at all" outcome for this specific sample, not a
plugin-specific quirk. **This part is a real, honest tool limitation for
this sample** -- not something this PoC claims to fix.

## The real, fixable bug found along the way

`docker/volatility/kronos-volatility-worker.py`'s fallback branch was
gated on `if not rows and args.fallback_plugin:` -- reached only when the
primary plugin exited **0** with an empty JSON result. A non-zero primary
exit (line `if returncode != 0: ... _emit(scan_error); sys.exit(0)`)
returned immediately, **never attempting the fallback plugin at all** --
even though a plugin-specific requirement failure doesn't guarantee every
other plugin fails the same way (the whole reason a fallback exists per
this same file's own "cridex.vmem" precedent). Confirmed via `git diff`/
reading the pre-fix source that this bug existed since the fallback logic
was first written (Milestone AAAAA).

## The fix

`docker/volatility/kronos-volatility-worker.py`: a non-zero primary exit
now records the error and falls through to the same fallback-attempt path
an empty-rows result already took, instead of returning immediately. Only
emits `scan_error` after the fallback has also genuinely been tried (and
failed, or wasn't configured) -- the emitted `error` string notes whether
the fallback ran and also failed, for a strictly more informative
diagnostic than before.

## Real, live verification (after rebuilding+redeploying `celery-worker-plaso`)

```
$ docker exec docker-celery-worker-plaso-1 python3 -c "...VolatilityLauncher().run(evidence_path='/tmp/ch2.dmp', plugin='windows.pstree', fallback_plugin='windows.psscan')..."
SCAN ERROR (now with a real, informative message): windows.pstree exited 1: Volatility 3 Framework 2.28.0
Unable to validate the plugin requirements: ['plugins.PsTree.kernel.layer_name', 'plugins.PsTree.kernel.symbol_table_name']
 (fallback windows.psscan also failed)
```

Confirms: (1) the fallback is now genuinely attempted (previously it
never ran at all for this file), (2) for this specific real sample both
plugins really do fail, so the end-user-visible outcome (no artifacts) is
unchanged for `ch2.dmp` -- but a real Windows image where only the primary
plugin's own requirement chain has a problem will now correctly recover
via the fallback instead of silently reporting nothing.

Full backend unit suite re-run after the fix: `tests/unit/parsers/test_volatility.py`
(37 passed, 1 skipped) and `tests/unit/test_volatility_launcher.py` --
unaffected, since these mock at the `VolatilityLauncher`/subprocess
boundary, not the real worker script (consistent with
`kronos-plaso-worker.py`/`kronos-yarax-worker.py`'s existing precedent of
being real subprocess scripts verified live, not unit-tested directly).

## The second, UX-layer fix this same investigation motivated

Independent of the worker fallback fix: `frontend/src/pages/CaseDetailPage.tsx`'s
`ArtifactsTab` showed a generic "No forensic artifacts yet. Upload a
memory dump..." empty state even when a real memory dump WAS uploaded,
finished processing (`state=COMPLETE`), and genuinely produced zero
artifacts -- exactly what happened here, and precisely what triggered the
original user report ("the volatility analysis result is not available").
Fixed to distinguish three real, honestly-different cases using the
already-fetched evidence list: no memory-dump evidence at all (unchanged
generic message), memory-dump evidence still processing ("still in
progress"), and memory-dump evidence that's `COMPLETE` with no artifacts
(names the file(s), says analysis found nothing usable, points at the
Audit tab for the real underlying error). See
`docs/GAP_AUDIT_2026-09-02_MILESTONE_BBBBB.md` for this fix folded into
the same cycle's write-up (it was found and fixed alongside the Detections
work, not a separate milestone).
