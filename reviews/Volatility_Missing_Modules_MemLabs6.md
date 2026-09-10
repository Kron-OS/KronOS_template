# Volatility module gaps, found via MemLabs Lab6

**Status update:** the mechanism below is now **built and shipped** — not
as individual eager-plugin additions to `DEFAULT_PLUGINS` as originally
sketched, but as a single generic **curated on-demand plugin picker**
(the project owner's own redirect: "put the list of possibilities, let the
user require modules" rather than us hand-picking eager plugins one at a
time). See `poc/volatility_ondemand_picker/` for the real timing/safety
PoC that replaced this doc's original reasoned-not-measured guesses with
real numbers (several placements below turned out wrong once measured —
see that PoC's own README for the corrections), and
`src/external/parsers/volatility_on_demand.py`'s `CURATED_ON_DEMAND_PLUGINS`
for the real, live catalog: `windows.envars`, `windows.privileges`,
`windows.getsids`, `windows.sessions`, `windows.windows`, `windows.svcscan`,
`windows.handles`, `windows.vadinfo`. Real end-to-end verified against the
actual `Challenge.raw` case referenced below
(`frontend/e2e/case-artifacts-volatility-picker.spec.ts`). The original
research below is kept for its own real value (the writeup analysis,
the plugin-requirement findings) — read the corrections in the PoC README
before trusting any placement claim made before that PoC ran.

**Trigger:** the project owner worked through
[MemLabs Lab6](https://n1ght-w0lf.github.io/ctf%20writeups/memlabs-lab6/)
(a real memory-forensics CTF exercise) against KronOS and could only
recover the `.rar` file — everything else the writeup's own solve path
needed is currently missing from `VolatilityModule`
(`src/external/parsers/volatility.py`).

## What the real writeup actually used (verified by fetching it)

| Step | Volatility (v2) command | What it recovered |
|---|---|---|
| 1 | `imageinfo` | Windows 7 SP1 x64 profile |
| 2 | `pslist` | WinRAR.exe process, touching `flag.rar` |
| 3 | `cmdline` | Confirmed the exact file path |
| 4 | `filescan` + `dumpfiles` | Extracted `flag.rar` |
| 5 | `consoles` | Console history hinting at an env-var trick |
| 6 | `envars` | The real RAR password, sitting in WinRAR's own environment block |
| 7 | (external `unrar`) | `flag2.png` (half the flag) |
| 8 | `chromehistory` | A Pastebin link |
| 9 | `screenshot` | A Gmail window showing a Mega decryption key |
| 10 | (external `strings` on the raw image) | The full Mega key text |

## What KronOS already has (confirmed by reading `volatility_launcher.py`/`volatility.py`)

- **Eager** (`DEFAULT_PLUGINS`, run automatically on every memory-dump
  parse): `windows.pstree`/`psscan` (→ step 2), `windows.cmdline` (→ step
  3), `windows.filescan` (→ step 4's discovery half), `windows.dlllist`,
  `windows.malware.malfind`, `windows.registry.hivelist`.
- **On-demand** (Celery-triggered, analyst clicks "Extract"):
  `windows.dumpfiles` (→ step 4's extraction half),
  `windows.registry.printkey`.
- So steps 2/3/4 are already fully covered. **Steps 5, 6, 8, 9, 10 are
  the real gap** — there is no `consoles`, `envars`, `chromehistory`, or
  `screenshot` equivalent anywhere in the module, and no memory-wide
  string search.

## Missing modules, with a real (not guessed) eager/on-demand call

Checked live against the actual pinned `volatility3==2.28.0` inside
`celery-worker-plaso` (`get_requirements()` on each real plugin class,
not read off documentation) — no real memory sample was available on this
host to re-run this cycle's own `poc/volatility_multiplugin/` timing
methodology, so costs below are reasoned from each plugin's *own
requirements* against the already-measured plugins from that PoC
(`windows.cmdline`: 0.15s construct/0.12s render: per-process, no memory
scan; `windows.malfind`/`filescan`: 11–24s render: full pool scan) —
flagged per-row as measured vs. reasoned. **A real timing PoC against a
real sample (the missing step) is the first thing the next cycle should
do before trusting these placements in production**, per this repo's own
`CLAUDE.md` §F/§G.5.

| Plugin | Real class | Requirements (live-checked) | Recommended placement | Basis |
|---|---|---|---|---|
| `windows.envars.Envars` | confirmed importable | `pslist`, `hivelist`, optional `pid` filter | **Eager** | Per-process PEB walk, same shape as `cmdline` (already eager, measured fast) — no full-memory scan. This is literally the plugin that found the RAR password; burying it behind a click undercuts the platform's existing proactive-detection posture (same reasoning Milestone CCCCC used for malfind/filescan). |
| `windows.consoles.Consoles` | confirmed importable | `pslist`, `verinfo`, `info`, `hivelist`, **`bytes_scanner`** | **On-demand** (tentative — needs a real timing PoC) | `bytes_scanner` is the same cost class as `malfind`/`filescan`'s pool scanning (11–24s measured on a 1.6GB image) — a full-memory byte-pattern scan, not a bounded per-process walk. Real, valuable (console/shell history), but likely too slow to run unconditionally on every parse. **Do not place this without a real measurement** — it could turn out cheap enough to be eager; don't guess. |
| `windows.strings.Strings` | confirmed importable | `pslist`, `pid`, **`strings_file` (URIRequirement)** | **On-demand, and inherently two-phase** | This plugin does NOT run `strings` itself — it correlates a pre-computed strings dump (real external `strings -t d <image>`) back to owning processes. The real external `strings` pass alone can be GB-scale text for a large image. This is the concrete case that justifies the user's own instinct ("call on demand instead of storing everything in memory") — never eager, and the raw strings output itself should stream to scratch/MinIO like `dumpfiles` already does, not sit in a Celery task's memory. |
| `windows.windows.Windows` (GUI window/desktop enumeration) | confirmed importable | `windowstations` only | **Eager candidate** (needs confirmation, likely cheap) | Structurally a bounded desktop/window-station object walk, not a memory scan — closest real v3-native answer to the writeup's "screenshot" step (recovers window **titles**, e.g. would have surfaced "Gmail" as an open window, though not actual pixels). Cheap-looking from requirements alone; still wants a real timing check before being added to `DEFAULT_PLUGINS`. |
| Chrome history from memory | n/a — not a Volatility plugin | — | **New idea, on-demand, reuses existing code** | volatility3 has no chrome-history plugin at all (confirmed: no such module in the installed package). The writeup's real technique was extracting `History` (SQLite) from memory via `filescan`+`dumpfiles`, then reading it separately. KronOS **already has** `ChromeHistoryParser` (`src/external/parsers/chrome_history.py`) for a standalone uploaded History file. The real, valuable gap: once a `windows.dumpfiles` extraction lands in `DerivedArtifactStorage` (Milestone EEEEE), **nothing re-dispatches it through the parser registry** — confirmed by grep, no such wiring exists. A `History` SQLite file recovered from memory currently just sits as an opaque downloadable blob. |
| Pixel screenshot (vol2 community `screenshot` plugin) | **no v3 equivalent exists** | — | **Real, honest gap — do not build around it** | Confirmed via a real package walk of `volatility3.plugins.windows.*`: no screenshot/GDI-buffer-rendering plugin ships in core v3 (this was always a third-party community plugin in v2, never ported to core v3). Adding it would mean pulling in unvetted third-party plugin code, which conflicts with this repo's own Track-D/untrusted-code gating (`CLAUDE.md` §G.3) unless that specific plugin is individually vetted — a real decision point, not a silent workaround. |

## A genuinely good side-finding, unrelated to "missing," worth noting

`windows.hashdump`/`lsadump`/`cachedump` (credential-hash extraction,
deliberately deferred at Milestone CCCCC because `pycryptodome` was
missing, and the sensitivity of real password-hash material warranted an
explicit go-ahead rather than silent inclusion) **now import cleanly** —
confirmed live: `docker exec celery-worker-plaso-1 python3 -c "from
Crypto.Cipher import AES"` succeeds (Milestone GGGGG's Dockerfile fix is
real and working; earlier testing this cycle mistakenly checked the
`Cryptodome` namespace instead of the `Crypto` namespace pycryptodome
actually installs under, which is why that first check looked like a
regression and wasn't one). The CCCCC-era blocker is gone; the
sensitivity-based "needs an explicit go-ahead" gate from that milestone
still stands and is unchanged by this finding.

## Recommended next cycle (status per item)

1. ~~Get a real memory sample back onto this host~~ **Done** — the project
   owner pointed directly at the real, already-uploaded `Challenge.raw`
   evidence on this dev stack (case `43097ab0-aae3-4968-915b-8f0229ac3865`,
   evidence `e9f3287f-3858-4018-bcee-42a4bcbb0bc3`); re-ran the CCCCC-style
   shared-context timing methodology against it for real
   (`poc/volatility_ondemand_picker/`).
2. ~~Add `windows.envars` to `DEFAULT_PLUGINS` (eager)~~ **Superseded** —
   shipped instead as part of the curated *on-demand* picker (the project
   owner's own redirect away from more eager-plugin hand-picking). Real
   measured cost (0.87s) would have supported eager placement too; on-demand
   was chosen for mechanism consistency with the other 7 curated plugins,
   not because envars itself needed it.
3. `windows.consoles`/`windows.windows` eager-vs-on-demand decided from
   real numbers, not reasoning: **`consoles` excluded entirely** (real,
   confirmed incompatibility with Windows 7 SP1 in this volatility3
   version — a functional gap, not a cost one, and the exact OS family
   every real sample on this platform is); **`windows.windows` shipped
   on-demand** (9.5s real-measured, tolerable for an explicit click, 0 rows
   on this particular image — an honest negative result).
4. `windows.strings` — **still not built.** Real requirements confirmed it
   needs a separate pre-computed strings-file input (a genuine two-phase
   pipeline, not a single plugin call) — doesn't fit the generic on-demand
   mechanism the other 8 plugins share. Would need its own bespoke route
   (mirrors `dump-file`/`registry-key`'s own bespoke-target reasoning),
   not a catalog entry.
5. The dumped-file re-dispatch idea (extracted `History`/similar files
   matching a known parser's magic bytes auto-run through
   `get_parser_registry()`) — **still not built**, still the highest-
   leverage single follow-up named in this doc.
6. `hashdump`/`lsadump`/`cachedump` — **still gated**, unchanged: real
   credential-hash material, needs an explicit go-ahead before any
   inclusion, not blocked by any remaining technical gap (pycryptodome
   import confirmed working, see below).
