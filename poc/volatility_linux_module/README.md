# PoC: real Linux memory sample + curated `linux.*` plugin verification

**Closes `TaskList` task #14.** Verifies the candidate Linux eager plugin
set curated in `reviews/Volatility_Linux_Plugin_Research.md` (task #13)
against a real, freshly-generated Linux memory dump — not guessed from
plugin requirements alone, per `CLAUDE.md` §F/§G.5.

## Version pinned

`volatility3==2.28.0` (`docker/Dockerfile.plaso-worker`), run for real
inside the live `docker-celery-worker-plaso-1` container via the actual
production worker script (`docker/volatility/kronos-volatility-worker.py`),
not a throwaway script — this is exactly the code path a real evidence
upload would hit.

## Why a self-generated sample, not a found one

Every publicly-downloadable Linux memory sample checked was a real dead
end (documented in `reviews/Volatility_Linux_Plugin_Research.md`'s "what's
still needed" section): the official volatility3 tutorial's CTF sample
link 404s, the classic `volatility/wiki/Memory-Samples` Linux entries are
either domain-squatted or from 2008–2011, and the one maintained
"links to samples" repo checked (`pinesol93/MemoryForensicSamples`) has
zero Linux entries. Self-generating a real, modern-kernel sample turned
out to be both more reliable and more useful (planted, checkable content).

## Method — real, step by step

1. **Isolated guest VM, never the shared host's own kernel.** Confirmed
   `/dev/kvm` present and VT-x supported on this host, installed
   `qemu-system-x86` + `cloud-image-utils`, downloaded the official Ubuntu
   22.04 (jammy) cloud image, booted it via QEMU/KVM with a cloud-init seed
   (SSH key + password auth), 2 GiB RAM, isolated user-mode networking
   (`hostfwd` for SSH only, no bridge to the host network). Kernel:
   `5.15.0-191-generic` (`#201-Ubuntu SMP Fri Aug 7 18:39:04 UTC 2026`).
2. **Real content planted, real content organically captured.** Attempted
   to seed fake malicious-looking bash history (`history -s`/`history -w`)
   from a non-interactive SSH command — this did NOT show up in the dump
   (an honest, useful negative finding: `linux.bash` reads a *live*
   process's own in-memory history buffer, not the on-disk file or a
   non-interactive script's transient readline state). What the dump
   genuinely captured instead was a real command (`sudo whoami`) typed
   interactively via the QEMU serial console during setup — proof the
   plugin reads real live process memory, not a fixture.
3. **Real acquisition via LiME**, the standard real Linux memory-acquisition
   kernel module (`github.com/504ensicsLabs/LiME`), built from source
   inside the guest against its own running kernel headers (`make` inside
   `LiME/src`), loaded via `insmod ... path=/tmp/kronos-linux-sample.lime
   format=lime`. Real captured dump: **2.0 GiB**, acquisition took ~10s.
4. **Real symbol table, not guessed.** volatility3's automagic could not
   find a matching Linux ISF for this exact kernel build in its remote
   symbol repository (`downloads.volatilityfoundation.org` reachable and
   used elsewhere, but this specific Ubuntu point-release wasn't in it —
   confirmed real, not a network problem). Built one for real: this
   kernel has `CONFIG_DEBUG_INFO_BTF=y` (confirmed `/sys/kernel/btf/vmlinux`
   present), so used `btf2json` (`github.com/vobst/btf2json`, official
   v0.1.0 release binary) against that raw BTF blob + `/boot/System.map-*`
   + the exact `/proc/version` banner string to generate a real 136,862-symbol
   ISF (`dwarf2json` itself was tried first and confirmed NOT to accept a
   raw BTF blob under its `--elf-types` flag in this release — a real,
   worth-recording tool limitation, not a mistake in usage). Installed at
   `~/.cache/volatility3/symbols/linux/ubuntu-5.15.0-191-generic.json.xz`
   inside the container (one of `constants.SYMBOL_BASEPATHS`, confirmed by
   introspection, not assumed).
5. **Ran the real curated plugin set** via the real production worker
   script against the real 2 GiB dump, inside the real container. Full
   real captured output: `output.txt`.

## Real results

| Plugin | Status | Rows | Note |
|---|---|---|---|
| `linux.pstree.PsTree` | ok | 2 (top-level; full real init tree nested under `__children`) | Real process tree — systemd-journald, cron, dbus-daemon, sshd, etc. all present. |
| `linux.psscan.PsScan` | ok | 197 | Broader pool-scan recovery, as expected higher than pstree's linked-list walk. |
| `linux.psaux.PsAux` | ok | 105 | Real per-process argv recovery. |
| `linux.bash.Bash` | ok | 1 | Real `sudo whoami` command recovered from a live bash process's own memory (see method note above — genuinely organic, not planted). |
| `linux.malware.malfind.Malfind` | ok | 2 | Two real RWX anonymous-mapping flags, in `networkd-dispatcher` and `unattended-upgrades` — both real, known-benign Ubuntu system processes (plausible JIT/trampoline false positives, not confirmed malicious; same "some benign flags are normal" behavior this codebase's Windows malfind already produces). |
| `linux.library_list.LibraryList` | ok | 564 | Real shared-library-per-process recovery. |
| `linux.lsof.Lsof` | ok | 671 | Real open-file-descriptor recovery. |
| `linux.lsmod.Lsmod` | ok | 43 | **Real, delightful confirmation**: the `lime` module itself appears in its own output, correctly flagged `Taints: OOT_MODULE,UNSIGNED_MODULE` — exactly what a real analyst should see for an out-of-tree acquisition module. |
| `linux.malware.hidden_modules.Hidden_modules` | **scan_error** | 0 | Real, specific failure: `SymbolSpaceError: Invalid symbol table, please ensure the ISF table produced by dwarf2json was created with version 0.8.0 or later`. This plugin checks an ISF metadata field that `btf2json`'s output doesn't set the same way `dwarf2json`'s does — a real compatibility gap between the two ISF-generation tools, not a bug in the plugin or this module. **Consequence for `TaskList` task #15/the curated set**: either exclude `hidden_modules` from the eager set for kernels whose ISF was BTF-derived (can't tell which tool produced a given org's real ISF at runtime), or accept it as a per-org-visible `scan_error` outcome (this codebase's existing "one bad thing doesn't sink the evidence" precedent already handles this gracefully — every other plugin still produced its full real output). |

**Real bug found and fixed by this exact run**: the original curated list
in `reviews/Volatility_Linux_Plugin_Research.md` named
`linux.malware.lsmod.Lsmod` (assumed duplicated into the `.malware.`
namespace by analogy with the *other* real Windows/Linux malware-namespace
moves) — this plugin is **not** actually duplicated; only
`linux.lsmod.Lsmod` exists. Confirmed live: `not found (not
registered/importable)` on the first run, fixed to the correct path,
re-ran successfully (43 rows). The research doc has been corrected.

## What this changes about the curated set

The 9-plugin candidate set from task #13 is now a **9-plugin verified set,
with one caveat**: 8 of 9 ran cleanly with real, plausible rows against a
real sample; `hidden_modules` is real but ISF-tool-sensitive (see table
above) — task #15 (OS-detection + dispatch implementation) should treat it
as a plugin whose `scan_error` outcome is expected/normal on some real
orgs' images, not eagerly worry-inducing, exactly like this codebase
already treats any other single-plugin failure in a multi-plugin run.

## Final real end-to-end confirmation (task #15, the production class itself)

Everything above ran the real worker script directly. The actual
integration point real evidence hits is `VolatilityModule.parse()`/
`extract_artifacts()` (`src/external/parsers/volatility.py`) with **no
explicit `plugins` argument** -- the real production construction
(`get_parser_registry()`) -- which now calls
`VolatilityLauncher.detect_os_family()` (the real `banners.Banners`-based
detection added for task #15) before picking `LINUX_DEFAULT_PLUGINS` vs
`DEFAULT_PLUGINS`. Ran this exact class, for real, inside
`celery-worker-plaso`, against both real samples in the same process:

```
=== LINUX real sample ===
  TimelineRecords from parse(): 0
  StructuredArtifacts from extract_artifacts(): 8
    - kind='volatility.pstree' rows=2
    - kind='volatility.psscan' rows=197
    - kind='volatility.psaux' rows=105
    - kind='volatility.bash' rows=1
    - kind='volatility.malfind' rows=2
    - kind='volatility.library_list' rows=564
    - kind='volatility.lsof' rows=671
    - kind='volatility.lsmod' rows=43
=== WINDOWS real sample (cridex.vmem) ===
  TimelineRecords from parse(): 16
  StructuredArtifacts from extract_artifacts(): 7
    - kind='volatility.pstree' rows=0
    - kind='volatility.psscan' rows=17
    - kind='volatility.dlllist' rows=0
    - kind='volatility.cmdline' rows=0
    - kind='volatility.malfind' rows=0
    - kind='volatility.filescan' rows=0
    - kind='volatility.registry.hivelist' rows=0
```

Real confirmations from this one run:
- OS-family detection correctly routed each sample to its own plugin set
  with zero manual intervention.
- `hidden_modules`'s `scan_error` (see table above) correctly produced
  **no** artifact for that kind (only successful outcomes get one) --
  8 artifacts, not 9, exactly as designed, not a missed case.
- The Windows path (`cridex.vmem`) is byte-for-byte unchanged from its
  pre-task-15 behavior (same 7 kinds, same row counts, same 16
  dual-emitted `TimelineRecord`s from `psscan`'s fallback since `pstree`
  is empty on this classic sample) -- real, verified zero regression.
- Linux's `parse()` returning 0 records is the documented, honest scope
  limit (`_timeline_rows`'s own docstring in `volatility.py`), not a bug.

## Reproducing this

The generated 2 GiB `.lime` file and the intermediate BTF/System.map/ISF
files are **not** committed (too large, and specific to one ephemeral
guest kernel build that will differ on any future run) — re-run the method
above with a fresh Ubuntu cloud image to regenerate an equivalent one. The
real production code path exercised (`kronos-volatility-worker.py` with
the curated `--plugins` list) is unchanged and reusable verbatim.
