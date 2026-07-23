# KAPE Artifact Coverage Analysis

**Purpose:** map the forensic-artifact surface covered by
[KAPE](https://github.com/EricZimmerman/KapeFiles) (Kroll Artifact Parser
and Extractor) against what KronOS's ingestion pipeline handles today, so
the parser roadmap is grounded in the de-facto DFIR triage standard rather
than guesswork.

**Status:** reference / gap analysis (2026-07-09). Not a spec change.

**Sources:**
[KapeFiles repo](https://github.com/EricZimmerman/KapeFiles) ·
[Modules/README](https://github.com/EricZimmerman/KapeFiles/blob/master/Modules/README.md) ·
[!EZParser.mkape](https://github.com/EricZimmerman/KapeFiles/blob/master/Modules/Compound/!EZParser.mkape) ·
[Awesome-KAPE](https://github.com/AndrewRathbun/Awesome-KAPE) ·
[KAPE notes (qazeer)](https://notes.qazeer.io/dfir/tools/kape)

---

## 1. How KAPE is structured

KAPE splits triage into two stages, and the distinction matters for us
because **KronOS is a "Module"-equivalent, not a "Target"-equivalent**:

| Stage | KAPE term | File ext | What it does | KronOS analogue |
|---|---|---|---|---|
| **Collect** | **Target** | `.tkape` | Locate + copy raw artifact files off a live/imaged system (respecting locks, VSS, `$MFT`-based file extraction). No parsing. | **Out of scope** — KronOS receives already-collected files via upload. The client/examiner runs KAPE (or similar) to produce the files, then uploads them. |
| **Parse** | **Module** | `.mkape` | Run a parser (mostly Eric Zimmerman "EZ Tools") over collected artifacts → normalized CSV/JSON timeline rows. | **This is what KronOS does** — `ForensicParser` implementations turn raw artifact bytes into `TimelineRecord`s indexed into OpenSearch. |

A "Target" answers *"which files do I grab"*; a "Module" answers *"what do
those files mean."* KronOS's parser registry is the Module layer. Below,
"do we handle X" always means *"can we parse an uploaded X into timeline
records,"* never *"can we collect X off a host."*

---

## 2. KAPE Target catalogue (what a full triage collection contains)

These are the artifact families a standard KAPE triage
(`KapeTriage` / `!SANS_Triage` compound targets) pulls off a Windows host.
This is the **universe of files an examiner could plausibly upload to
KronOS** after running a triage collection.

### 2.1 Windows OS / execution artifacts

| Artifact | Underlying format | Forensic value |
|---|---|---|
| **Event Logs** (`*.evtx`) | EVTX (binary XML) | Logons, service installs, PowerShell, Defender, RDP, etc. |
| **Registry hives** (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat) | REGF | Config, autoruns, user activity, mounted devices |
| **Amcache.hve** | REGF | Program execution + SHA1 of executables |
| **Prefetch** (`*.pf`) | SCCA (often MAM-compressed) | Program execution, run count, first/last run, referenced files |
| **SRUM** (`SRUDB.dat`) | ESE database | Per-app network + resource usage over ~30 days |
| **ShimCache / AppCompatCache** | inside SYSTEM hive | Program presence (not necessarily execution) |
| **BAM/DAM** | inside SYSTEM hive | Background activity moderator — execution + timestamps |
| **UserAssist**, **RunMRU**, **ShellBags** | inside NTUSER/UsrClass hives | GUI program launches, typed commands, folder access |
| **RecentFileCache.bcf** | proprietary binary | Program execution |

### 2.2 File-system artifacts

| Artifact | Format | Forensic value |
|---|---|---|
| **`$MFT`** | NTFS Master File Table | Every file's timestamps (Std Info + FileName), size, parent |
| **`$J` (UsnJrnl)** | NTFS change journal | File create/delete/rename history |
| **`$LogFile`, `$Boot`, `$SDS`** | NTFS metadata | Transaction log, boot, security descriptors |

### 2.3 User-activity / shell artifacts

| Artifact | Format | Forensic value |
|---|---|---|
| **LNK files** | Shell link binary | Files opened, source volume/host, timestamps |
| **JumpLists** (`*.automaticDestinations-ms`, `*.customDestinations-ms`) | OLE/custom | Recently accessed per-app items |
| **Windows Timeline** (`ActivitiesCache.db`) | SQLite | App/document usage timeline |
| **Recycle Bin** (`$I*` info files) | binary | Deleted-file name, size, deletion time |
| **Thumbcache** (`thumbcache_*.db`) | proprietary | Thumbnails of viewed images/folders |
| **Windows Search** (`Windows.edb`) | ESE database | Indexed file/email content |

### 2.4 Network / remote / cloud / app artifacts

| Artifact | Format | Forensic value |
|---|---|---|
| **Web browsers** (Chrome/Edge `History`, `Cookies`, `Web Data`; Firefox `places.sqlite`; IE/legacy `WebCacheV01.dat`) | SQLite + ESE | Browsing, downloads, search terms, autofill |
| **SUM** (Server User Access Logging) | ESE | Per-user access to a Windows Server over time |
| **Scheduled Tasks** (`*.job`, Task XML) | XML/binary | Persistence, execution schedule |
| **WBEM / WMI repository** (`OBJECTS.DATA`) | proprietary | WMI persistence |
| **BITS** (`qmgr.db`) | ESE/SQLite | Background transfers (often malware download) |
| **WER** (Windows Error Reporting) | text/`.wer` | Crash reports — process paths, module lists |
| **Remote access** (RDP bitmap cache, TeamViewer/AnyDesk logs) | mixed | Lateral movement, remote sessions |
| **Cloud storage metadata** (OneDrive/Dropbox/GDrive logs) | mixed | Synced-file provenance |
| **Messaging/FTP clients** | mixed | Comms + transfers |
| **PowerShell console history** (`ConsoleHost_history.txt`) | text | Attacker commands |

### 2.5 Non-Windows / non-KAPE sources KronOS also cares about

KronOS's spec (`Project_Specifications.md`) targets **cloud + web-server +
Linux** evidence too, which sits *outside* KAPE's Windows-endpoint scope:

- **AWS CloudTrail**, Azure activity, GCP audit logs (cloud control-plane)
- **nginx / Apache access logs** (web-server)
- **Linux `journald`**, syslog, auth.log (Linux endpoint)

---

## 3. KAPE Module catalogue (the parsers that produce the output)

The parsing tools KAPE Modules wrap — mostly EZ Tools — and the artifact →
output mapping. This is the concrete "output information" list requested.

| KAPE Module / tool | Consumes | Produces |
|---|---|---|
| **EvtxECmd** | `*.evtx` | Normalized event CSV/JSON (one schema across all channels) |
| **MFTECmd** | `$MFT`, `$J`, `$LogFile`, `$Boot`, `$SDS` | File-system timeline (CSV / bodyfile) |
| **RECmd** | Registry hives (batch-driven) | Extracted key/value rows (CSV) |
| **PECmd** | Prefetch `*.pf` | Execution timeline + referenced-file list |
| **AmcacheParser** | `Amcache.hve` | Program-execution + SHA1 CSV |
| **AppCompatCacheParser** | SYSTEM hive | ShimCache CSV |
| **SrumECmd** | `SRUDB.dat` + SOFTWARE | Per-app network/resource CSV |
| **SumECmd** | SUM ESE DBs | User-access CSV |
| **JLECmd** | JumpLists | Recent-items CSV |
| **LECmd** | LNK files | Target/volume/timestamp CSV |
| **RBCmd** | Recycle Bin `$I` | Deleted-file CSV |
| **SBECmd** | ShellBags (NTUSER/UsrClass) | Folder-access CSV |
| **SQLECmd** | Arbitrary SQLite (map-driven) | Table rows → CSV per "map" |
| **WxTCmd** | `ActivitiesCache.db` | Windows Timeline CSV |
| **RecentFileCacheParser** | `RecentFileCache.bcf` | Execution CSV |
| **bstrings / hindsight / bulk_extractor** (community) | strings / browser / carving | Strings, browser timeline, carved artifacts |
| **Timeline output** | any of the above | mactime/bodyfile, super-timeline, Timeline Explorer TLE |

The `!EZParser` compound module chains: EvtxECmd, JLECmd, LECmd, MFTECmd,
PECmd, RBCmd, RecentFileCacheParser, RECmd (DFIR batch), SBECmd, SQLECmd —
i.e. the "run everything" DFIR default.

---

## 4. What KronOS handles **today**

Registry: `src/external/dependencies.py::get_parser_registry()`.
Detection: magic-byte / extension in each parser's `supports()`, over the
first 8 KB (`_HEADER_BYTES`). Parsers run first-match-wins in registration
order.

| # | Parser | Class | Detection | Artifact | Queue | KAPE equivalent |
|---|---|---|---|---|---|---|
| 1 | CloudTrail | `CloudTrailParser` | `.json`/`.jsonl` + `"Records"` or `"CloudTrailEvent"` | AWS CloudTrail (wrapped + Lake/S3 NDJSON) | fast | — (cloud, non-KAPE) |
| 2 | Nginx | `NginxParser` | `.log`/`.txt` + combined/common-log header | nginx/Apache access logs (+ vhost-prefixed) | fast | — (web server, non-KAPE) |
| 3 | EVTX | `FastEvtxParser` | `ElfFile\x00` magic | Windows Event Logs | fast | **EvtxECmd** |
| 4 | Plaso | `PlasoParser` | see below | multiple (delegates to Plaso) | heavy | multiple EZ Tools |

**PlasoParser routing** (`supports()`) — what actually reaches Plaso:

| Trigger | Artifact | KAPE equivalent |
|---|---|---|
| `regf` magic | Registry hives (SYSTEM/SOFTWARE/NTUSER/Amcache) | RECmd, AmcacheParser, AppCompatCacheParser, SBECmd (via Plaso winreg plugins) |
| `MAM\x04` or `SCCA` @ off 4 | Prefetch | PECmd |
| `SQLite format 3` magic | SQLite DBs (browser history, Windows Timeline, some SRUM/BITS) | SQLECmd, WxTCmd, hindsight |
| journald magic (`\xbe\xb9\xb0\xd9…`) | Linux systemd journal | — (Linux, non-KAPE) |
| ext `.dat/.db/.sqlite/.sqlite3/.hve/.hiv` | SRUM/Amcache/Shimcache/registry by name | SrumECmd, etc. |

> **Caveat on the Plaso path:** Plaso *itself* can parse far more than the
> five triggers above route to it (MFT, LNK, JumpLists, Recycle Bin, ESE,
> etc.). KronOS only *dispatches* a file to Plaso when `supports()` matches
> — so an uploaded `$MFT` or `.lnk` is **not** handled today even though the
> Plaso engine underneath could parse it. Coverage is gated by our
> detection, not by Plaso's capability. Also note the current Plaso worker
> is a dev subprocess stub (`docker/plaso/kronos-plaso-worker.py`) whose
> real event extraction is not yet verified end-to-end (see prior review
> notes).

### 4.1 Accepted-at-intake but **no parser** (silent dead-ends)

`src/application/validation.py` accepts more formats at upload than any
parser can consume. These pass intake, then fail at parse with
`ParsingError: No parser found` (which now cleanly transitions evidence →
ERROR after the 2026-07 fix, rather than hanging):

| Accepted magic/ext | Parser exists? | Note |
|---|---|---|
| `PK\x03\x04` **ZIP** | ✅ (2026-07) | `ZipArchiveParser` (`src/external/parsers/archive.py`) recursively re-dispatches every member through `ParserRegistry`, stamping `kronos.source_path`/`file.path` + `kronos.container_sha256`. Verified end-to-end against a real KAPE-shaped zip (`poc/kape_ingestion_test/`). |
| `\x1f\x8b` **GZIP** | ❌ | Still no decompression — `.gz` logs / journald exports dead-end. Not addressed this pass (scope was ZIP + disk images, matching the explicit ask). |
| `%PDF` **PDF** | ❌ | Accepted (spec lists as "reports") but no parser. |
| `.csv` | ❌ | Accepted as text; no CSV parser. |
| `.xml` | ❌ | Accepted as text; no XML parser (Scheduled Tasks, etc.). |

---

## 5. Coverage matrix (KAPE artifact → KronOS status)

Legend: ✅ handled · 🟡 partial / only via generic Plaso routing ·
❌ not handled · ➖ out of KronOS scope (collection-side).

| KAPE artifact family | KronOS status | Notes |
|---|---|---|
| Event Logs (EVTX) | ✅ | `FastEvtxParser`, dedicated fast path |
| Registry hives (raw REGF upload) | 🟡 | Routed to Plaso by `regf` magic; per-plugin output unverified |
| Amcache | 🟡 | REGF → Plaso; not a dedicated parser |
| ShimCache / BAM / UserAssist / ShellBags | 🟡 | Live inside hives → Plaso winreg plugins; not explicitly surfaced |
| Prefetch | ✅ | `PlasoParser` (MAM **and** SCCA), heavy queue |
| SRUM (`SRUDB.dat`, ESE) | 🟡 | `.dat` ext routes to Plaso; ESE parsing unverified |
| SUM (ESE) | ❌ | No ESE routing by magic; only `.dat`/`.db` ext |
| Windows Search (`Windows.edb`, ESE) | ❌ | Not routed |
| `$MFT` / `$J` / `$LogFile` | ❌ | No detection → not dispatched to Plaso |
| LNK files | ❌ | No `.lnk`/shell-link-magic routing |
| JumpLists | ❌ | Not routed |
| Windows Timeline (`ActivitiesCache.db`) | 🟡 | SQLite magic → Plaso |
| Browser history/cookies (SQLite) | 🟡 | SQLite magic → Plaso |
| Browser cache / IE `WebCacheV01.dat` (ESE) | ❌ | Not routed |
| Recycle Bin (`$I`) | ❌ | Not routed |
| Thumbcache | ❌ | Not routed |
| Scheduled Tasks (XML) | ❌ | `.xml` accepted, no parser |
| WBEM/WMI, BITS, WER, Remote-access, Cloud-storage-meta | ❌ | Not routed |
| PowerShell console history (text) | ❌ | No plain-text/history parser |
| **AWS CloudTrail** | ✅ | `CloudTrailParser` (non-KAPE) |
| **nginx/Apache access logs** | ✅ | `NginxParser` (non-KAPE) |
| **Linux journald** | 🟡 | Magic routes to Plaso |
| ZIP containers | ✅ (2026-07) | `ZipArchiveParser` recursive re-dispatch (§4.1) |
| GZIP containers | ❌ | Still accepted at intake, no extraction (§4.1) |
| Disk images (**E01/Ex01**) | ✅ (2026-07) | EWF magic routes the whole image to `PlasoParser` -> `log2timeline`'s dfVFS auto-detection walks every partition/filesystem directly; verified against a real E01 (388 real `windows:evtx:record` + 1 `windows:prefetch:execution` + more, each with real in-image `source_path`) |
| Disk images (raw/dd, VHDX, VMDK, QCOW) | ❌ | Not yet given a magic-byte trigger in `PlasoParser.supports()` (only EWF added this pass) or the validator's `_MAGIC_TABLE` -- same whole-image-to-Plaso mechanism would likely work, unverified |

---

## 6. Highest-value gaps (suggested priority)

Ranked by DFIR triage impact vs. implementation effort. Not a commitment —
input for roadmap planning.

1. ~~**Container extraction (ZIP).**~~ **DONE (2026-07)** — `ZipArchiveParser`
   (`src/external/parsers/archive.py`) recursively re-dispatches every
   member through the registry, with a real depth/count/byte budget +
   zip-slip guard (`tests/unit/parsers/test_archive.py`). **GZIP is still
   open** (not addressed this pass). E01/Ex01 disk images are also now
   handled (see the coverage matrix above) via `PlasoParser`'s
   whole-image dfVFS routing — raw/VHDX/VMDK/QCOW are not yet triggered.
2. **`$MFT` parsing.** The single richest Windows timeline artifact;
   universally collected. Plaso can already do it — mainly needs a
   `supports()` trigger (`FILE0`/`BAAD` signature or `$MFT` filename) to
   route it, plus output verification.
3. **Verify the Plaso path end-to-end.** Much "🟡 partial" coverage above
   is theoretical until the dev subprocess worker is confirmed to emit real
   events for registry / SQLite / prefetch (per §4 caveat). This validates
   a large swath of the matrix without new parsers.
4. **LNK + JumpLists.** Cheap, high-signal, Plaso-supported — needs
   routing.
5. **ESE database routing (SRUM/SUM/`Windows.edb`/BITS).** Distinct from
   SQLite; needs ESE magic (`\xef\xcd\xab\x89` at offset 4) detection.
6. **CSV parser.** Lets pre-parsed EZ Tools output (already CSV) be
   re-ingested, and covers office365/audit CSV exports the spec mentions.

---

## 7. One-line summary

KronOS today robustly parses **EVTX + AWS CloudTrail + web-server access
logs**, plus **prefetch, registry hives, SQLite and journald via Plaso**,
**and now (2026-07) a real KAPE `.zip` (recursive re-dispatch,
`ZipArchiveParser`) or `.E01` image (whole-image Plaso routing)** — covering
the *execution*, *cloud/web*, and *container* slices, but still **missing
the file-system (`$MFT`), shell (LNK/JumpLists), ESE-database, and GZIP
artifact classes** that make up the rest of a standard KAPE triage. See
`poc/kape_ingestion_test/` for the real end-to-end verification (zip + E01,
631 real records, correct `source_path`/`file.path` provenance on every
one).
