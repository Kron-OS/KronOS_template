# PoC: curated on-demand Volatility plugin picker — Phase-1 vetting

**Version pinned:** `volatility3==2.28.0` (`docker/Dockerfile.plaso-worker`).
**Real sample:** `Challenge.raw`, a real 1.6 GB Windows 7 SP1 x64 memory
image the project owner uploaded to a real case on this dev stack (case
`43097ab0-aae3-4968-915b-8f0229ac3865`, evidence
`e9f3287f-3858-4018-bcee-42a4bcbb0bc3`) — pointed to explicitly for this
verification. Pulled fresh via a direct `boto3` call against the real
`kronos-evidence-kronos-dev` MinIO bucket into `/tmp/challenge.raw` inside
`celery-worker-plaso`; not redistributed/committed, same convention as
every other PoC using real evidence.

**Mechanism**: reuses `poc/volatility_multiplugin/run_poc.py`'s exact
shared-context harness unmodified (already proven correct for the eager
7-plugin set, Milestone CCCCC) — just points it at new candidate plugin
names. Real captured output: `output.txt`.

## Real, decisive findings (not guessed)

The original research doc (`reviews/Volatility_Missing_Modules_MemLabs6.md`)
reasoned costs *by analogy* to already-measured plugins, explicitly
flagging that as unverified. This PoC replaces that guessing with real
numbers, and **the reasoning behind several placements changed as a
result**:

| Plugin | Rows | Construct | Render | Verdict |
|---|---|---|---|---|
| `windows.envars.Envars` | 1590 | 0.34s | 0.53s | Fast — confirms prior reasoning |
| `windows.privileges.Privs` | 1855 | 0.16s | 0.36s | Fast |
| `windows.getsids.GetSIDs` | 705 | 0.17s | 1.32s | Fast |
| `windows.sessions.Sessions` | 53 | 0.29s | 0.33s | Fast — **corrects** the doc's exclusion (it runs fine despite declaring a `timeliner` requirement; no extra plumbing needed) |
| `windows.windows.Windows` | 0 | 0.15s | 9.5s | Moderate; 0 rows on this image is an honest negative result, not a bug |
| `windows.svcscan.SvcScan` | 863 | 0.27s | 9.1s | Moderate — **corrects** the doc's speed-based exclusion; fine for an explicit on-demand click |
| `windows.handles.Handles` | 13276 | 0.18s | 16.3s | Slower than reasoned ("similar to cmdline" was wrong) but tolerable on-demand |
| `windows.vadinfo.VadInfo` | 7324 | 0.31s | 34.6s | Slowest tested; `dump` requirement confirmed `default=False, optional=True` — safe, won't write files unless explicitly configured (nothing in this pipeline sets it) |
| `windows.consoles.Consoles` | — | 0.29s | 0.85s | **Real functional failure**: `NotImplementedError: This version of Windows is not supported: 6.1 15.7601!` — this plugin does not support Windows 7 SP1 at all in this volatility3 version. Every real sample in this exact case (`ch2.dmp`, `contact_me.*`, `Challenge.raw`) is Windows 7-era — a **real, confirmed incompatibility with this platform's actual current samples**, not a speed problem. |

**Key reframe this PoC produced**: the original doc's exclusion criteria
conflated "slow" with "unsafe for on-demand." Since every curated-list
plugin is analyst-initiated on-demand (never part of the eager per-parse
path), a 9–35 second wait for an explicit click is entirely acceptable —
the existing on-demand timeout is 300s. The real bar for exclusion is
*functional failure* or *needing bespoke non-generic parameters*, not raw
speed. This is why `svcscan`/`handles`/`vadinfo`/`sessions`/`windows.windows`
all move from "excluded" to "included" after real measurement, while
`consoles` moves to "excluded" for a different, more decisive reason (real
incompatibility with this platform's actual sample population) than
originally guessed.

## Final Phase-1 curated list (shipped)

`windows.envars.Envars`, `windows.privileges.Privs`, `windows.getsids.GetSIDs`,
`windows.sessions.Sessions`, `windows.windows.Windows`,
`windows.svcscan.SvcScan`, `windows.handles.Handles`, `windows.vadinfo.VadInfo`.

**Still excluded, with real reasons**: `windows.consoles.Consoles` (real
incompatibility with Windows 7, this platform's actual sample OS family),
`windows.dumpfiles`/`windows.registry.printkey` (already shipped as their
own bespoke-UI on-demand actions — need a target picked from a prior
result row, not a generic "just run it" call), `windows.strings` (needs a
separate pre-computed strings-file input — a two-phase pipeline).

## How to reproduce

```
docker cp poc/volatility_multiplugin/run_poc.py docker-celery-worker-plaso-1:/tmp/poc_multiplugin_run_poc.py
docker cp poc/volatility_ondemand_picker/run_poc.py docker-celery-worker-plaso-1:/tmp/poc_ondemand_picker.py
docker exec docker-celery-worker-plaso-1 python3 -c "
import sys, importlib.util
spec = importlib.util.spec_from_file_location('run_poc', '/tmp/poc_multiplugin_run_poc.py')
mod = importlib.util.module_from_spec(spec); sys.modules['run_poc'] = mod; spec.loader.exec_module(mod)
spec2 = importlib.util.spec_from_file_location('picker_poc', '/tmp/poc_ondemand_picker.py')
mod2 = importlib.util.module_from_spec(spec2); spec2.loader.exec_module(mod2); mod2.main()
"
```
(Requires `/tmp/challenge.raw` inside the container — real evidence, not
committed; pull fresh from MinIO as shown in this file's own header, or
substitute the small public `cridex.vmem` sample for a structural check
against a different/smaller real image.)
