# PoC: does `linux.boottime.Boottime` + per-process offset actually give Linux dual-emit a real `CreateTime`?

**Investigates the "what's still needed" item in
`reviews/Volatility_Linux_Plugin_Research.md`** ("A real Linux timeline
source would need combining `linux.boottime.Boottime` with a process's
boot-relative start offset") before writing any `src/` code, per
`CLAUDE.md` §F/§G.5. Answer: **currently blocked, not just unbuilt** — real
finding below, not a guess.

## Version pinned

`volatility3==2.28.0`, same real self-generated Linux sample and ISF as
`poc/volatility_linux_module/` (Ubuntu 22.04, `5.15.0-191-generic`, LiME
capture, `btf2json`-built ISF), reused directly (both the `.lime` dump and
the installed ISF were still present in the live `docker-celery-worker-plaso-1`
container from that earlier session).

## Method — real, step by step

1. Ran `linux.boottime.Boottime` for real against the real sample using
   the exact same shared-context/automagic harness
   `docker/volatility/kronos-volatility-worker.py` uses (`framework.
   import_files` → `automagic.choose_automagic` → `plugins.construct_plugin`
   → `grid.populate`).
2. Inspected `linux.pstree.PsTree`/`linux.psscan.PsScan`'s real, rendered
   `TreeGrid` columns directly (`grid.columns`, before any renderer
   filtering) to confirm no timestamp field is hidden by the JSON
   renderer's `ignored_columns()`.
3. Tried reading `task.start_time` directly from the object layer
   (`pslist.PsList.list_tasks()`, bypassing the `boottime` plugin
   entirely) to see whether the underlying data is even present in this
   ISF, independent of the plugin's own wall-clock-conversion logic.

## Real results

- **`linux.boottime.Boottime` fails outright** against this real ISF:
  ```
  AttributeError: Unable to find timekeeper for type <class 'volatility3.framework.objects.Void'>
  ```
  raised from `symbols/linux/extensions/__init__.py`'s `_get_boottime_raw()`
  → `tk_core.timekeeper`. This is the **same category of failure** already
  documented for `linux.malware.hidden_modules.Hidden_modules`
  (`poc/volatility_linux_module/README.md`): a real ISF-metadata field that
  `btf2json`'s output doesn't populate the way `dwarf2json`'s does. Not a
  bug in the plugin or this module — a real tool-compatibility gap.
- **`linux.pstree.PsTree`'s real rendered columns are exactly**
  `['OFFSET (V)', 'PID', 'TID', 'PPID', 'COMM']`; **`linux.psscan.PsScan`'s**
  are `['OFFSET (P)', 'PID', 'TID', 'PPID', 'COMM', 'EXIT_STATE']`. Confirmed
  directly from `grid.columns` (not the JSON-rendered output, so nothing is
  hidden by a renderer filter either) — neither plugin surfaces any
  timestamp-shaped field as a CLI-level column, in either mode.
- **`task.start_time` IS real and readable directly from the object layer**,
  independent of the broken `boottime` plugin (confirmed for PIDs 1-6):
  a boot-relative monotonic nanosecond count (e.g. `111154639` ≈ 0.11s
  after boot for PID 1, plausible for an early-boot process). So the
  underlying kernel data this fix would need genuinely exists in this
  ISF — the specific thing that's broken is only the wall-clock **boot
  anchor** (`timekeeper`), which is what `boottime.Boottime` needs to
  convert a monotonic offset into a real UTC timestamp.

## Conclusion: this is a real, verified blocker, not an oversight

Combining `linux.boottime.Boottime` with per-process `start_time` to
produce a dual-emitted `CreateTime` is **not implementable against this
exact real sample/ISF combination today** — not because the idea is wrong
(the raw data needed is confirmed present), but because the one real tool
this approach depends on (`boottime.Boottime`'s wall-clock conversion)
fails on a BTF-derived ISF the same way `hidden_modules` does. Two real
options for a future session, neither attempted here (out of scope for
this investigation, which was to confirm feasibility before committing to
an implementation):

1. Get a `dwarf2json`-built ISF for a Linux sample (needs a kernel with
   available `dwarf2json`-compatible debug info, e.g. a distro kernel with
   a `-dbg` package, or one already in volatility3's remote ISF repo) and
   re-verify `boottime` against that — if `timekeeper` resolves there, the
   original plan works unmodified.
2. Write a from-scratch, `timekeeper`-independent wall-clock anchor (e.g.
   deriving the image's real acquisition wall-clock time from another,
   working source and computing `boot_wall_time = acquisition_time -
   max(process uptimes)` as an approximation) — a real, separate piece of
   work with its own accuracy caveats, not a small addition to the
   existing plan.

Until one of those lands, Linux memory images correctly continue to
produce zero `TimelineRecord`s from `parse()` (artifacts only) — this
PoC does not change that; it only replaces "not yet built" with "verified
blocked, two named ways forward" in `STATUS.md`/the research doc.
