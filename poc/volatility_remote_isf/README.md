# PoC: wiring up real remote ISF lookup for volatility3

**Closes the gap diagnosed live against a real user-uploaded evidence file**
(`memory.vmem`, case `c3a60d51-84df-433e-9ee7-f376030c34fb`, Ubuntu
`6.5.0-41-generic`): every plugin failed with `UnsatisfiedException` despite
correct OS-family detection, because this codebase's worker never attempts
remote symbol-table (ISF) lookup at all. Per `CLAUDE.md` §F/§G.5, verified
this for real against the real file before touching `src/`.

## Version pinned

`volatility3==2.28.0` (`docker/Dockerfile.plaso-worker`), same real
`docker-celery-worker-plaso-1` container as every other Volatility PoC in
this repo.

## Real root cause, traced through volatility3's own source (not guessed)

1. `banners.Banners` (pure byte-pattern scan, no symbol resolution) correctly
   found `Linux version 6.5.0-41-generic ... Ubuntu 6.5.0-41.41~22.04.2` in
   the real uploaded file.
2. Every other plugin (`pstree`, `psaux`, `bash`, etc.) needs automagic to
   resolve a real `SymbolTableRequirement` first. Caught the exact
   unsatisfied requirement directly:
   ```
   unsatisfied: {'plugins.PsTree.kernel.layer_name': <TranslationLayerRequirement>,
                 'plugins.PsTree.kernel.symbol_table_name': <SymbolTableRequirement>}
   ```
3. Read `volatility3/framework/automagic/symbol_cache.py`'s real source:
   remote ISF lookup only ever runs when
   `not constants.OFFLINE and constants.REMOTE_ISF_URL` -- and
   `constants.REMOTE_ISF_URL` defaults to `None`, only ever set by
   volatility3's own CLI (`vol.py`) when a user passes `--remote-isf-url`.
   This codebase's worker (`docker/volatility/kronos-volatility-worker.py`)
   calls the framework API directly, never the CLI, so that constant was
   never set -- confirmed live: `constants.REMOTE_ISF_URL` is `None` in this
   worker's real runtime, and only one manually-installed ISF (from an
   earlier PoC, a *different* kernel) exists in the local symbol cache.

## Real docs used (not guessed, not the open-web page treated as instructions)

- `volatility3` project's own official GitHub repo, PR #1316 ("Enable Remote
  ISF server for Linux testcases", `volatilityfoundation/volatility3`) --
  the project's own CI workflow diff sets:
  ```
  REMOTE_ISF_URL: https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/banners/banners.json
  ```
  This is the value the volatility3 maintainers' own test suite uses, not a
  third-party guess. Fetched via GitHub's public REST API
  (`api.github.com/repos/.../pulls/1316`, `patch-diff.githubusercontent.com/.../1316.diff`)
  -- read as technical content only, no instructions from page text followed.
- Confirmed this URL is real and live: `curl` returned HTTP 200, a valid
  `{"version": 1, "linux": {...11123 entries...}, "mac": {...303 entries...}}`
  document matching `RemoteIdentifierFormat.process_v1`'s exact expected
  shape (read directly from volatility3's own installed source).
- Confirmed the *exact* real kernel from the user's file is covered:
  searching the fetched index for `6.5.0-41-generic` found one real,
  base64-decodable match pointing at
  `.../Ubuntu/amd64/6.5.0/41/generic/Ubuntu_6.5.0-41-generic_6.5.0-41.41~22.04.2_amd64.json.xz`
  -- confirmed that URL itself is live (`curl -I` -> HTTP 200, 2.7MB).
- The official `volatility3-symbols` repo (the name suggested by
  `constants.py`'s own naming convention) was checked and found genuinely
  empty (`api.github.com/.../volatility3-symbols` -> `"size": 0"`) -- not
  used, ruled out for real rather than assumed working.

## Real run, before and after

**Before** (already captured live against the real uploaded file, see the
conversation this PoC is from): all 10 curated Linux plugins ->
`scan_error`, `UnsatisfiedException: ` (empty message), 0 usable rows,
matching exactly what the analyst-facing diagnostic artifact showed.

**After** -- ran the real worker module's own `_run_all_plugins()` function
directly (imported via `importlib`, not reimplemented) against the same
real 4GB file, after setting
`constants.REMOTE_ISF_URL = "https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/banners/banners.json"`.
Full captured output: `output.txt`. Result:

| Plugin | Before | After |
|---|---|---|
| `linux.pstree.PsTree` | `scan_error` (UnsatisfiedException) | `ok`, 0 rows |
| `linux.psscan.PsScan` | `scan_error` (UnsatisfiedException) | **`ok`, 1493 rows** |
| `linux.pslist.PsList` | `scan_error` (UnsatisfiedException) | `ok`, 0 rows |
| `linux.psaux.PsAux` | `scan_error` (UnsatisfiedException) | `ok`, 0 rows |
| `linux.bash.Bash` | `scan_error` (UnsatisfiedException) | `ok`, 0 rows |
| `linux.malware.malfind.Malfind` | `scan_error` (UnsatisfiedException) | `ok`, 0 rows |
| `linux.library_list.LibraryList` | `scan_error` (UnsatisfiedException) | `ok`, 0 rows |
| `linux.lsof.Lsof` | `scan_error` (UnsatisfiedException) | `ok`, 0 rows |
| `linux.lsmod.Lsmod` | `scan_error` (UnsatisfiedException) | `ok`, 0 rows |
| `linux.malware.hidden_modules.Hidden_modules` | `scan_error` (UnsatisfiedException) | `scan_error` (different, real error -- see below) |

Automagic now genuinely resolves the kernel for every plugin (no more
`UnsatisfiedException` anywhere) -- the fix works as intended and is not
guessed: `linux.psscan.PsScan` recovered 1493 real process-scan rows from a
file that previously produced nothing usable at all.

## Real, separate finding this PoC surfaces (not fixed here, not silently hidden)

Most plugins that need to *walk* from a resolved kernel structure
(`pstree`/`pslist`/`psaux`/`bash`/`malfind`/`library_list`/`lsof`/`lsmod`)
returned real `ok` status but zero rows, while `psscan` (a pool/pattern
*scan*, not a linked-list walk) recovered real data. Since `psscan` also
needs the same resolved symbol table to interpret memory as `task_struct`,
this is not a second symbol-resolution failure -- both plugin classes now
have working symbols. The likely real cause: this file is a bare `.vmem`
with no paired `.vmss`/`.vmsn` snapshot metadata (volatility3 itself warned
about this live: `"No metadata file found alongside VMEM file. A VMSS or
VMSN file may be required to correctly process a VMEM file"`), which can
affect KASLR/DTB-shift calculation used by the walk-based plugins
specifically. Not investigated further in this PoC -- out of scope for the
"wire up remote ISF lookup" fix this PoC verifies; tracked as a distinct,
separate, real gap in `STATUS.md`.

`linux.malware.hidden_modules.Hidden_modules`'s post-fix error is also
distinct and real, not related to ISF resolution: `PagedInvalidAddressException:
Page Fault at entry 0x117a3a001 in table page map layer 4` -- a genuine
page-table walk hitting an unmapped/invalid page for this specific image,
a different failure class from the pre-fix symbol-resolution error.

## What changed in `src/`

- `src/config.py`: new `Settings.volatility_remote_isf_url`, defaulting to
  the real URL verified above; empty string disables (reproduces the exact
  pre-fix, fully-offline behavior).
- `docker/volatility/kronos-volatility-worker.py`: new `--remote-isf-url`
  CLI flag (same name/semantics as volatility3's own CLI flag), sets
  `constants.REMOTE_ISF_URL` in `main()` before any automagic runs.
- `src/external/sandbox/volatility_launcher.py`: `VolatilityLauncher.__init__`
  takes `remote_isf_url`, threads it into the multi-plugin/OS-detection
  subprocess command (`_run_sync`) -- not the on-demand Windows-only
  dumpfiles/registry-printkey paths, which target an already-identified
  kernel and have no Linux equivalent today.
- `src/external/parsers/volatility.py` / `volatility_on_demand.py` /
  `celery_runtime.py`: thread `settings.volatility_remote_isf_url` through
  to both the eager multi-plugin `VolatilityLauncher` and the on-demand
  curated-plugin-picker `VolatilityLauncher`.

## Real, disclosed tradeoff (not a silent decision)

The sandboxed Volatility worker subprocess now makes real outbound HTTPS
requests to GitHub/raw.githubusercontent.com to fetch the banner index and,
when a match is found, the specific matched ISF file. No evidence content
or evidence-derived data is ever sent -- the index is a one-time
(cache-period-bounded) download of a public document, and the only
information that reaches GitHub is which specific kernel build's ISF URL
gets requested (visible in GitHub's own access logs), not any evidence
bytes. This is consistent with this component's existing trust tier
(`CLAUDE.md` §G.3: "first-party module wrapping a real external tool",
sandboxed at the container level, not the stricter no-network Track D
tier) -- explicitly requested by the project owner over the alternative
(manually building a per-kernel ISF, ruled out as not viable regardless of
kernel version for this use case).
