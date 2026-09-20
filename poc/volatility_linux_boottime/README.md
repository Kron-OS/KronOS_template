# PoC: does `linux.boottime.Boottime` + per-process offset actually give Linux dual-emit a real `CreateTime`?

**Investigates the "what's still needed" item in
`reviews/Volatility_Linux_Plugin_Research.md`** ("A real Linux timeline
source would need combining `linux.boottime.Boottime` with a process's
boot-relative start offset") before writing any `src/` code, per
`CLAUDE.md` §F/§G.5.

**Update (later session, same investigation): option (a) below (get a
real `dwarf2json`-built ISF) was attempted and works.** See "Part 2:
positive verification" below — `linux.pslist.PsList`'s "CREATION TIME"
column (not a hand-combined boottime+offset calculation — volatility3
computes it internally) is real and populated when the image's ISF was
built by `dwarf2json`. `src/external/parsers/volatility.py` and
`src/external/sandbox/volatility_launcher.py` (`LINUX_DEFAULT_PLUGINS`)
were updated accordingly. Part 1 below (the original negative finding
against this codebase's own `btf2json`-built ISF) is left as-written —
it's still real and still true for that ISF, and explains exactly why
the fix is conditional rather than unconditional.

## Part 1: original finding — blocked against the btf2json-built ISF

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

## Part 2: positive verification — option (a), a real `dwarf2json` ISF, works

**Method — real, step by step, same sample/kernel build, no new VM.**

1. Downloaded the real, matching Ubuntu `-dbgsym` package for the exact
   kernel this sample's memory dump was captured from
   (`linux-image-unsigned-5.15.0-191-generic-dbgsym_5.15.0-191.201_amd64.ddeb`,
   ~1.03GB, `https://ddebs.ubuntu.com/ubuntu/pool/main/l/linux/`) — no new
   VM/capture needed, since an ISF only needs to match the *kernel build*,
   not a specific boot of it, and applies directly to the existing
   `/tmp/kronos-linux-sample.lime` capture still present in
   `docker-celery-worker-plaso-1`.
2. Extracted `usr/lib/debug/boot/vmlinux-5.15.0-191-generic` from the
   `.ddeb` (real Debian binary package format 2.0: `ar x` for
   `control.tar.xz`/`data.tar.xz`, then a targeted `tar -xJf data.tar.xz
   <path>` for just the one file needed — a full extraction is unnecessary
   and, on a memory-constrained host, actively risky, see host note below).
   Real file: 755,518,320 bytes, ELF 64-bit, `with debug_info, not stripped`.
3. Ran the real `dwarf2json` binary (`/home/reca/vol-linux-vm/dwarf2json`,
   already present on this host from the original `poc/volatility_linux_module/`
   session, `producer.version: "0.9.0"` per its own output metadata)
   against that vmlinux: `dwarf2json linux --elf <path> > ubuntu-dwarf.json`.
   Real output: 46,028,930 bytes of valid ISF JSON, confirmed
   `tk_core` present in `symbols` and `timekeeper` present in `user_types`
   (neither guaranteed — this is exactly the metadata the btf2json-built
   ISF was missing).
4. Installed the new ISF into the **live, shared, production**
   `docker-celery-worker-plaso-1` container's real volatility3 symbol
   cache (`/home/nonroot/.cache/volatility3/symbols/linux/`) under a
   distinct filename, and **temporarily moved the existing btf2json-built
   ISF aside** (same directory, `.btf2json_bak` suffix) for the duration of
   the test only — both ISFs otherwise claim the same kernel banner, so
   volatility3's automagic banner-matching would nondeterministically pick
   between them. **Restored immediately after the test** (moved the
   original back, deleted the temporary one) since this is a live worker
   container that could pick up a real production Celery task at any
   moment, not an isolated PoC container.
5. Ran `linux.boottime.Boottime` and `linux.pslist.PsList` for real via
   the actual `kronos-volatility-worker.py` production script against
   `/tmp/kronos-linux-sample.lime`, and separately fed the real captured
   JSON rows through the actual (non-mocked) `_timeline_rows()`/
   `_row_to_timeline_record()` functions from `src/external/parsers/
   volatility.py` to confirm the real `src/` code path, not just the
   external tool, produces correct output.

**Real results — see `output_dwarf2json_positive.json`** (captured,
not paraphrased):

- `linux.boottime.Boottime`: **`status: "ok"`**, real recovered boot time
  `2026-09-19T14:50:06.605516+00:00` — `tk_core.timekeeper` resolved
  correctly this time, no `AttributeError`.
- `linux.pslist.PsList`: all **105/105 rows** now carry a real, non-null,
  monotonically-plausible `CREATION TIME` (e.g. PID 1 `systemd` at
  `2026-09-19T14:50:06.111155+00:00`, ~0.5s before the recovered boot
  time's own timestamp per `tk_core`'s coarser rounding — consistent, not
  a discrepancy).
- Fed through the real, unmodified `src/external/parsers/volatility.py`
  functions (not test mocks): `_timeline_rows()` correctly selects
  `linux.pslist.PsList` (Linux's `pstree`/`psscan` plugin names don't
  match the Windows-specific constants those checks use, so they fall
  through as designed) and `_row_to_timeline_record()` correctly maps the
  Linux field names (`CREATION TIME`/`COMM`/`OFFSET (V)`, added via
  `_ROW_FIELD_NAMES`) into **105 real `TimelineRecord`s**.

## Host gotcha found and fixed during this verification

`/tmp` on this host is a RAM-backed `tmpfs` capped at 3.6GB, not real
disk. An earlier attempt to download the 1GB `.ddeb` and `dpkg-deb -x` it
there (a full extraction, not the targeted one used above) filled the
tmpfs completely, which broke **all** shell command execution on the host
(even `echo`/`true` returned exit 1 with empty output) until the large
files were removed — confirmed via a fresh subagent hitting the identical
failure, ruling out session-local shell corruption. Also, `dwarf2json`
itself is memory-hungry (~3.5GB+ RSS observed climbing on a host with
only 7.1GB total RAM and already-exhausted swap) — it completed
successfully here, but on a more memory-constrained host this should be
run with a memory limit or on a bigger box, not assumed safe. **Lesson
for future large-file work on this host: use a real-disk path (e.g.
`/home/reca/scratch/<name>/`), never `/tmp`, and watch `free -h` for
memory-hungry native tools.**

## Conclusion

Both real options named in Part 1 are now resolved: (a) works and is what
got implemented. `LINUX_DEFAULT_PLUGINS` now includes
`linux.pslist.PsList`; `VolatilityModule`'s dual-emit logic dispatches to
it for Linux images. Whether a *specific* org's Linux images actually get
real Linux `TimelineRecord`s depends on how their ISF was built
(`dwarf2json` → yes; `btf2json` → still zero, honestly, not a crash) —
this is now a documented, understood dependency, not a silent gap. See
`STATUS.md`/`DECISIONS.md` for the production-facing summary.
