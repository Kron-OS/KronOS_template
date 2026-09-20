# Volatility3 Linux plugin research (real, pinned-version introspection)

**Status:** requirements research complete AND real-sample-verified.
Requirements introspected live against the pinned `volatility3==2.28.0`
inside `celery-worker-plaso` (not read off documentation). The curated set
below has now been run for real against a real, self-generated Linux
memory sample (`poc/volatility_linux_module/`, closing task #14) — 8 of 9
plugins ran cleanly with real, plausible row output; one
(`hidden_modules`) surfaced a real ISF-tool-compatibility caveat, and one
real bug in this doc's own original plugin-path guess
(`linux.malware.lsmod.Lsmod` → `linux.lsmod.Lsmod`) was found and
corrected by that run. See `poc/volatility_linux_module/README.md` for
the full real methodology and results table. Task #15 (OS-family
detection + dispatch implementation) is **done** — see `STATUS.md` and
`DECISIONS.md`'s Volatility section. The dual-emit timeline gap this left
open (§"What's still needed" item 3 below, superseded) was investigated
for real in `poc/volatility_linux_boottime/README.md`: **verified
blocked** on the same real ISF-tool-compatibility gap as `hidden_modules`,
not just unbuilt — see that PoC for the two named ways forward.

## Method

```python
# run inside celery-worker-plaso (the real image that carries volatility3)
import pkgutil, importlib, inspect
from volatility3.framework import interfaces
import volatility3.plugins.linux as linux_pkg

for finder, name, ispkg in pkgutil.walk_packages(linux_pkg.__path__, prefix="volatility3.plugins.linux."):
    mod = importlib.import_module(name)
    for attr_name, obj in vars(mod).items():
        if inspect.isclass(obj) and issubclass(obj, interfaces.plugins.PluginInterface) and obj.__module__ == name:
            print(name, attr_name, obj.get_requirements())
```

Confirmed live: `importlib.metadata.version("volatility3")` → `2.28.0`,
matching `docker/Dockerfile.plaso-worker`'s pin exactly. **60 real plugin
classes** exist under `volatility3.plugins.linux.*` in this exact version.

## Real finding: duplicate classes under two namespaces

Exactly like this codebase's own already-handled `windows.malfind.Malfind`
→ `windows.malware.malfind.Malfind` move (`_PLUGIN_KIND_OVERRIDES` in
`src/external/parsers/volatility.py`), volatility3 2.28.0 carries the
**same plugin twice**, under both `linux.*` and `linux.malware.*`, for:
`check_afinfo`, `check_creds`, `check_idt`, `check_modules`,
`check_syscall`, `hidden_modules`, `keyboard_notifiers`, `modxview`,
`netfilter`, `tty_check`. Any future eager/on-demand list must pick
**one** canonical path per pair (the `linux.malware.*` one, matching the
`windows.malware.*` precedent already established for Windows) and add
the other to `_PLUGIN_KIND_OVERRIDES` so a kind name never silently
depends on which namespace happened to run.

## Classification: no required user-supplied target parameter

Same criterion this codebase already uses for the Windows eager set
(`DEFAULT_PLUGINS`, `src/external/sandbox/volatility_launcher.py`): a
plugin qualifies if every one of its `get_requirements()` entries is
either `kernel`/`primary` (`ModuleRequirement`/`TranslationLayerRequirement`,
auto-resolved by volatility3's own automagic — not something a caller
supplies), a `VersionRequirement` (framework-internal cross-plugin
dependency, also auto-resolved), or genuinely `optional` (schema marks it
`?` — has a working default with no value supplied). **57 of the 60**
plugins qualify. Three do not:

| Plugin | Blocking requirement | Why it can't be eager |
|---|---|---|
| `linux.module_extract.ModuleExtract` | `base: IntRequirement` (required) | Needs a specific kernel module's base address — a targeted, on-demand action, same shape as the existing `windows.dumpfiles`/`windows.registry.printkey` on-demand pair. |
| `linux.vmaregexscan.VmaRegExScan` | `pattern: StringRequirement` (required) | Needs an analyst-supplied regex — inherently on-demand. |
| `linux.vmayarascan.VmaYaraScan` | `yara_string`/`yara_file`/`yara_compiled_file` (all optional in schema, but the plugin does nothing useful with none supplied) | Schema-optional but practically requires a YARA rule to be worth running — same "optional in schema, required in practice" shape as `windows.vmayarascan`'s own equivalent; excluded from the eager set for the same reason. |

## Curated eager set (candidate, mirrors the 7-plugin Windows `DEFAULT_PLUGINS`)

Windows' own eager set covers: process tree/scan, DLLs, command lines,
injected memory, files-in-memory, registry hives. The Linux analog below
maps each real Windows eager plugin to its closest Linux equivalent, plus
two Linux-native additions with no direct Windows-eager counterpart today
(flagged as bonus coverage, not parity gaps):

| # | Plugin (canonical path) | Windows analog | Real DFIR value |
|---|---|---|---|
| 1 | `linux.pstree.PsTree` | `windows.pstree.PsTree` | Process tree via task_struct linked-list walk — the primary process-timeline source (mirrors the existing dual-emit `CreateTime` logic). |
| 2 | `linux.psscan.PsScan` | `windows.psscan.PsScan` | Pool/hash-scan fallback that recovers exited/hidden processes `pstree`'s linked-list walk can miss — same fallback role as Windows' pair. |
| 3 | `linux.psaux.PsAux` | `windows.cmdline.CmdLine` | Full argv per process (the direct `cmdline` analog — confirmed same command-line-recovery value as the plugin that found the RAR password in the Windows MemLabs writeup). |
| 4 | `linux.bash.Bash` | *(no Windows-eager analog — `windows.consoles` was excluded, see below)* | Recovers **bash command history directly from each bash process's own in-memory history buffer** — no full-image scan needed (bounded per-process walk, same cost class as `cmdline`/`psaux`, not `windows.consoles`'s `bytes_scanner`-based full scan that got excluded on Windows for being too slow). Genuinely high-value, low-cost — the single strongest "add coverage Windows doesn't have" candidate here. |
| 5 | `linux.malware.malfind.Malfind` | `windows.malware.malfind.Malfind` | Injected/suspicious executable memory regions — direct analog, same plugin family. |
| 6 | `linux.library_list.LibraryList` | `windows.dlllist.DllList` | Shared libraries (`.so`) mapped per process — direct `dlllist` analog. |
| 7 | `linux.lsof.Lsof` | `windows.filescan.FileScan` | Open file descriptors per process — Linux's `lsof` is process-scoped (not a full pool scan like `filescan`), so cheaper in principle; also the closest thing to covering sockets-as-files, a real Linux idiom Windows doesn't share. |
| 8 (bonus) | `linux.lsmod.Lsmod` | *(no Windows-eager analog)* | Loaded kernel modules — a real rootkit/persistence indicator with no Windows-eager equivalent today (Windows eager set has no "drivers" plugin at all). **Correction (real run, `poc/volatility_linux_module/`):** originally listed here as `linux.malware.lsmod.Lsmod` by incorrect analogy with the other real `.malware.`-namespace duplicates — `lsmod` is **not** actually duplicated; only `linux.lsmod.Lsmod` exists. Confirmed live (`not found (not registered/importable)` on the wrong path, 43 real rows on the correct one). |
| 9 (bonus, needs a timing check before eager) | `linux.malware.hidden_modules.Hidden_modules` | *(no Windows-eager analog)* | Detects kernel modules hidden from `lsmod` (unlinked from the module list but still present in memory) — the single highest-signal Linux rootkit-detection plugin available. Flagged separately (not folded into the core 7) because its requirements alone don't reveal whether it does a full memory scan internally; needs the same real-timing discipline `windows.consoles` got before any eager placement. |

**Deliberately excluded** (real reasons, not oversights):
- `linux.malware.netfilter.Netfilter` / `linux.ip.Addr` / `linux.ip.Link` —
  network-facing plugins have no analog in the current Windows eager set
  either (`windows.netscan` was never added there); adding Linux-only
  network coverage without the Windows equivalent existing would be an
  inconsistent asymmetry, not a genuine platform gap — worth a *separate*,
  explicit product decision (add `netscan` to both OS families together),
  not smuggled in here.
- Everything under "check_*"/"tracing.*"/"kallsyms"/"ebpf"/"iomem"/"kmsg" —
  real, valid rootkit/integrity checks, but niche/anti-forensic-specific
  rather than "most useful for a general CERT-analyst first pass" — same
  curation bar Windows' own eager set already applies (Windows doesn't
  eagerly run `hashdump`/`lsadump` either, despite being real and useful,
  for an analogous "not everyone needs this every time" reason).
- `linux.pagecache.*` (Files/InodePages/RecoverFs) — real and valuable
  (page-cache file recovery) but structurally closer to `windows.dumpfiles`
  in shape (an extraction action with its own target/output semantics),
  not a "just run it and get rows" plugin like the 7+2 above.

## What's still needed before this is real (not guessed)

1. **A real Linux memory sample — real, honest dead end so far, tracked
   here so the next session doesn't repeat the same search.** None exists
   locally (checked `poc/`, `tests/fixtures/samples/`). Checked, in order,
   all real dead ends:
   - Official `volatility3` docs' own Linux tutorial names a real sample
     (Insomni'hack teaser 2020 "getdents" CTF, Ubuntu 4.15.0-72-generic) —
     confirmed via a real HTTP request that its Google Cloud Storage
     download link 404s (a time-limited CTF-event link, long expired).
   - The classic `volatility/wiki/Memory-Samples` page's Linux entries
     (DFRWS 2008, Honeynet 2011, "Second Look"/Pikeworks) — the Pikeworks
     domain (`secondlookforensics.com`) now 301-redirects to an unrelated,
     unrecognized site (domain squatted/repurposed — not followed, per
     this repo's own untrusted-content policy); DFRWS/Honeynet links are
     from 2008–2011 and were not verified further given the domain-squat
     finding already cast doubt on this page's overall freshness, and
     both use kernels old enough to likely need a hand-built ISF anyway.
   - `pinesol93/MemoryForensicSamples` (a curated links repo) — checked
     directly: Windows and macOS samples only, zero Linux entries.

   **Next real option, not yet attempted (verified technically feasible
   on this host: `/dev/kvm` present, CPU reports VT-x):** self-generate a
   real, modern-kernel sample with a disposable QEMU/KVM guest VM (fully
   isolated from this shared host's own kernel — LiME requires loading a
   kernel module, which must never touch the actual shared host) + LiME
   (`github.com/504ensicsLabs/LiME`) compiled against that guest's own
   kernel, dumped, then copied out. This also has a real advantage over a
   found CTF sample: the guest's own bash history/processes can be
   seeded deliberately, directly validating the curated `linux.bash`/
   `linux.psaux`/`linux.malware.malfind` picks above against known,
   planted content rather than an opaque unknown-content sample. Real
   setup work (qemu-system-x86_64 is not currently installed), scoped as
   its own step for the next session rather than rushed here.
2. **Real timing + row-output measurement** against that sample, mirroring
   `poc/volatility_multiplugin/`'s methodology exactly (shared automagic
   context, per-plugin construct/render timing) — this is what turns the
   "candidate eager set" above into a verified `LINUX_DEFAULT_PLUGINS`
   constant.
3. ~~**OS-family detection**~~ **Done** (`VolatilityLauncher.detect_os_family()`,
   real `banners.Banners`-based, verified against both a real Windows and
   a real Linux sample) — see `STATUS.md`/`DECISIONS.md`.
4. **Linux dual-emit `TimelineRecord`s (the `boottime` + per-process-offset
   plan) — investigated for real, verified blocked, not just unbuilt.**
   `poc/volatility_linux_boottime/README.md`: `linux.boottime.Boottime`
   fails against this codebase's own real, self-generated ISF
   (`AttributeError: Unable to find timekeeper`) — the same
   `btf2json`-vs-`dwarf2json` ISF-metadata gap already documented for
   `hidden_modules`. The underlying per-process boot-relative offset
   (`task.start_time`, nanoseconds since boot) IS real and readable
   directly from the object layer even with `boottime` broken — confirmed
   live for real PIDs — so the *data* this plan needs exists; only the
   wall-clock boot anchor `boottime.Boottime` would supply is missing.
   Two named ways forward, neither attempted yet: (a) get a
   `dwarf2json`-built ISF for a Linux sample and re-verify `boottime`
   against it, or (b) write a `timekeeper`-independent wall-clock anchor
   from scratch (its own real work, with real accuracy caveats, not a
   small addition to this plan).

See `TaskList` tasks #13 (this doc) → #14 (real sample + measurement) →
#15 (implementation, done) → #16 (Linux dual-emit timeline, blocked, see
above) for the tracked sequence.
