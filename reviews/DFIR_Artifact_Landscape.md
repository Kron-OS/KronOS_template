# DFIR Artifact Landscape — Beyond KAPE

**Purpose:** catalogue the forensic data-source categories KronOS should
eventually be able to ingest beyond its current baseline, so the module
roadmap (`reviews/Data_Source_Module_System.md`) is grounded in the real
DFIR tooling landscape rather than guesswork. Companion to
`reviews/KAPE_Coverage_Analysis.md` (Windows/KAPE-specific) and
`reviews/Data_Source_Module_System.md` (the architecture this catalogue feeds).

**Status:** living catalogue (2026-07-24). Research-grounded (real tool
names, real output formats, versions cited where confirmable) — see
Sources at the bottom. Not a commitment to build all of this; a map for
prioritization.

---

## 0. The core problem this document exists to name

KronOS today has exactly one output shape: `TimelineRecord` — a flat,
chronological, single-timestamp event (`@timestamp`, `message`, ECS
`event.*`/`host.*`/`user.*`/`process.*`, `kronos.*` provenance). Every parser
written so far (EVTX, CloudTrail, nginx, Prefetch, registry, Chrome History,
the KAPE zip/E01 routing) produces exclusively this shape, because every
artifact chosen so far happens to *be* a timeline: a sequence of discrete,
independently-timestamped occurrences.

That assumption breaks the moment KronOS tries to ingest a **process tree**,
a **network connection graph**, a **memory map**, or a **static configuration
snapshot**. These are real, common, high-value DFIR artifacts. None of them
is "a list of timestamped events" — forcing one into `TimelineRecord` either
destroys the information that makes it useful (a `pstree` flattened to rows
loses every parent→child edge) or requires fabricating a timestamp that
doesn't meaningfully exist (a `.plist` config file has no "occurred at").

This is not a parser-writing problem (add another `ForensicParser`
subclass); it's a **data-model problem**: KronOS's domain layer currently has
no concept of "a piece of forensic evidence that isn't an event." Section 3
of `reviews/Data_Source_Module_System.md` names and solves this gap
(`StructuredArtifact`, a new sibling to `TimelineRecord`). This document's
job is only to catalogue *what* falls on each side of that line, and *how
much of it there is*, so the solution is scoped to the real problem instead
of one example (`pstree`).

---

## 1. Linux endpoint forensics

| Source | Real format | Timeline? | OSS tooling |
|---|---|---|---|
| `auditd` (`/var/log/audit/audit.log`) | Multi-line text, `type=`/`msg=audit(epoch:serial)`; one syscall event spans several correlated lines | ✅ Yes, but needs reassembly first (group by `audit(...)` id) | `ausearch`, `laurel` (auditd → one JSON object per event — ideal pre-normalizer) |
| `journald` binary journals | Indexed binary; `_PID`, `_COMM`, `_SYSTEMD_UNIT`, `MESSAGE`, `_BOOT_ID` | ✅ Yes — already routed to Plaso by magic bytes (`\xbe\xb9\xb0\xd9...`), coverage past detection unverified | `journalctl -o json`, Plaso's `journal` parser |
| bash/zsh history | Plain text; timestamps only if `HISTTIMEFORMAT`/`extended_history` set (often absent) | 🟡 Partial — ordered, frequently timestamp-less | Plaso `bash_history`/`zsh_extended_history` |
| cron (crontab) | `/etc/crontab`, `/var/spool/cron/*` | ❌ Static schedule, a listing | stdlib text |
| cron exec log (`/var/log/cron`) | syslog text | ✅ Yes | stdlib/regex |
| systemd unit state | `.service`/`.timer` files + `systemctl list-units` | ❌ Static config/state snapshot | stdlib INI parse |
| `/proc` captures | Snapshot of `/proc/<pid>/{cmdline,maps,fd,status}` | ❌ Point-in-time process/memory snapshot | stdlib |
| package manager history | `/var/log/dpkg.log`, `apt/history.log` (text); `dnf`/`yum` `history.sqlite` | ✅ Yes — install/remove/update are timestamped | stdlib text; `sqlite3` for dnf |
| SSH auth logs | `/var/log/auth.log`, `secure` (syslog text) | ✅ Yes | stdlib/regex; Plaso syslog parser |

**Collection tools (the "KAPE of Linux/multi-OS" — container-explosion candidates):**
- **UAC** (`tclahr/uac`, actively maintained, 2.x) — shell script; output is a `.tar.gz` preserving original paths, optionally a **bodyfile** (`mactime`, already timeline-shaped). Supports AIX/BSD/ESXi/Linux/macOS/Solaris/NetScaler. Structurally identical to the KAPE `.zip` case KronOS already solved: explode + re-dispatch each member.
- **CyLR** — live collector, outputs a `.zip` preserving directory structure.
- **Velociraptor** (Rapid7, ~v0.74) — VQL artifact collections export as a `.zip` of **JSONL result sets**, one JSON object per row per artifact. Very ingest-friendly, minimal normalization work.
- **GRR Rapid Response** — agent-based; typed protobuf/YAML flow results.
- **Loki / Fenrir / THOR-lite** (Nextron) — IOC scanners; alert/match rows (CSV/log), scan-time not event-time.

---

## 2. Memory forensics — Volatility 3

**`pip install volatility3`, current ~2.28.x.** The most important
non-timeline category — every plugin renders a tabular `TreeGrid`, and
whether that's a *timeline* depends entirely on the plugin.

> **Status (2026-07-24): scoped, not yet built.** A `VolatilityModule` PoC
> was attempted but the build agent was killed by an account-level spend
> limit before writing any code — no partial/broken state exists, this is a
> clean not-started. Real research already done so resumption needs zero
> re-investigation:
> - **Version to pin: `volatility3==2.28.0`** (confirmed current on PyPI).
> - **Real sample source found:** the classic `cridex.vmem` (Windows XP,
>   Cridex/Feodo banking trojan) — the smallest well-known real, legitimately
>   redistributable memory sample. Original host
>   (`files.sempersecurus.org/dumps/cridex_memdump.zip`, linked from
>   Volatility Foundation's own
>   [Memory-Samples wiki](https://github.com/volatilityfoundation/volatility/wiki/Memory-Samples))
>   now 403s, but a working Wayback Machine snapshot exists:
>   `https://web.archive.org/web/20210304131300/http://files.sempersecurus.org/dumps/cridex_memdump.zip`
>   (verified reachable, `Content-Length: 40352364` — ~40 MB compressed).
>   **Do not commit this to git** — 40 MB is an order of magnitude larger
>   than every other fixture in this repo (the KAPE E01 was deliberately
>   shrunk from 33 MB to 47 KB for exactly this reason). Download it to a
>   local scratch path for verification, document the URL + sha256 in the
>   PoC's `README.md`/`NOTICE.md` instead of committing the binary, and gate
>   any automated unit test on the file's local presence (skip, don't fail,
>   when absent — mirrors the existing `pytest.importorskip("evtx")`
>   pattern for an optional real-artifact dependency).
> - **Volatility3's own CI** (`volatilityfoundation/volatility3`
>   `.github/workflows/test.yaml`) downloads real samples from its own
>   official `volatilityfoundation/volatility3-test-data` GitHub Releases
>   (tag `v0.0.1`) — a Linux sample (`linux-sample-1.bin.gz`, ~137 MB),
>   a Windows XP image (`win-xp-laptop-2005-06-25.img.gz`, ~172 MB), and a
>   Windows 10 dump (`win-10_19041-2025_03.dmp.gz`, ~661 MB). All larger
>   than `cridex.vmem`; noted here as the authoritative upstream source if
>   a *different* profile/plugin coverage is needed later (e.g. real Linux
>   `pslist`/`pstree` coverage, which `cridex.vmem` — Windows XP — can't
>   exercise).
> - **Detection is a real open question, not yet resolved**: raw physical
>   memory dumps have no standard magic bytes. Real, verified alternatives
>   worth checking before falling back to extension-only detection
>   (`.vmem`/`.mem`/`.raw`/`.dmp`/`.lime`): Microsoft crash dumps have a
>   real `PAGEDU64`/`PAGEDUMP` magic; LiME format has a real magic too —
>   neither was verified against a real sample before this PoC was paused.

> **Status (2026-08-02): BUILT and real-verified — `VolatilityModule` +
> `VolatilityLauncher` land as roadmap E5.** See
> `docs/NEXTGEN_SOC_ROADMAP.md`'s E5 entry for the full account;
> highlights specific to this section's own open questions:
> - **Detection question resolved, for real, against the real sample above:**
>   `cridex.vmem`'s own first 4 KiB carry **no** `PAGEDUMP`/`PAGEDU64` and
>   **no** LiME magic — just raw kernel bytes, no header at all. Extension-
>   only detection (`.vmem`/`.mem`/`.raw`/`.dmp`/`.lime`) is therefore the
>   honest, now-implemented answer (`src/application/validation.py`'s
>   `_MEMORY_DUMP_EXTENSIONS`, `VolatilityModule.supports()`). The
>   `PAGEDUMP`/`PAGEDU64`/LiME magics remain real per public documentation
>   but still **not independently verified** — no real crash-dump/LiME
>   sample was downloaded this pass either, only `cridex.vmem`.
> - **`pstree` (the case this section names explicitly) has a real,
>   reproduced wrinkle**: `windows.pstree`/`windows.pslist` (the
>   `PsActiveProcessHead` linked-list walk) return zero rows against this
>   exact sample + `volatility3==2.28.0` — confirmed via `-vvv`
>   (no exception, just an empty walk) and cross-checked with `--pid`
>   filters against PIDs `windows.psscan` confirms exist. Root cause not
>   fully chased down (XP-era volatility3 support has known rough edges —
>   see `poc/volatility_memory_module/README.md` for the GitHub-issue
>   search) but conclusively shown to be a real tool/sample interaction, not
>   a wrapper bug: reproduced with the bare `vol` CLI directly, zero KronOS
>   code involved. `windows.psscan` (pool-tag scan, not a linked-list walk)
>   recovers the real, full 17-process census from the same bytes — the
>   shipped module runs `pstree` first and automatically falls back to
>   `psscan` when the primary result is empty, emitting a `StructuredArtifact`
>   for each (`volatility.pstree`, `volatility.psscan`).
> - `linux-sample-1.bin.gz`/`win-xp-laptop-2005-06-25.img.gz`/
>   `win-10_19041-2025_03.dmp.gz` (the official `volatility3-test-data`
>   releases) were **not** downloaded this pass — `cridex.vmem` alone was
>   judged sufficient for this item's own gate (Windows XP `pstree`/`psscan`
>   coverage); real Linux `pslist`/`pstree` coverage remains a follow-up.

**Timeline-shaped (map directly to `TimelineRecord`):**
- `timeliner` — Volatility's own timeline plugin; aggregates timestamps
  (process create, thread, handle, registry) across other plugins into
  `(timestamp, description)` rows.
- `windows.pslist` / `linux.pslist` — each row carries a process
  **CreateTime** → one creation event per process.
- `windows.netscan` — connections carry a Created time on modern Windows.

**Fundamentally non-timeline (the `pstree` case the platform brief names explicitly):**
- **`pstree`** — parent/child **process tree** keyed by PID/PPID + tree
  depth. A flat row destroys the structure that makes it useful.
- `pslist`/`psscan` as **listings** — state at capture time.
- `cmdline`, `dlllist`, `handles`, `ldrmodules`, `envars` — per-process
  attribute listings.
- `malfind` — injected-memory **regions** (address ranges + hexdump/disasm).
- `netscan`/`netstat` as a **connection table/matrix**.
- `filescan`, `dumpfiles` — file objects resident in memory (a listing/hash set).
- `vadinfo`, `memmap` — virtual address-space maps.
- `svcscan`, `modules`, `driverscan`, `callbacks`, `ssdt` — state inventories.

**Takeaway:** most Volatility output is a *structured snapshot object*, not
a timeline row. Only `timeliner` and CreateTime-bearing plugins belong in
`TimelineRecord`; everything else is the canonical `StructuredArtifact` use
case.

---

## 3. Mobile forensics

| Source | Format | Timeline? | OSS tooling |
|---|---|---|---|
| iOS iTunes/Finder backup (unencrypted) | Directory of SHA1-named blobs + `Manifest.db` (SQLite) + plists; underlying artifacts are SQLite/plist | Container of mixed artifacts — inner DBs (SMS, calls, Safari) are timeline-able once mapped | **iLEAPP** (`abrignoni/iLEAPP`, Python, active) — outputs HTML + TSV + a **SQLite timeline** + KML |
| Android ADB backup / `adb bugreport` / FS extraction | `.ab` (custom tar-ish), bugreport text bundle, or tar/zip of SQLite+XML | Mixed; app DBs timeline-able | **ALEAPP** (`abrignoni/ALEAPP`, Python) — same output shape as iLEAPP |
| Cellebrite UFED | `.ufd`/`.ufdr` package (XML + binary + media), semi-proprietary | Report bundle; parts timeline-able | Treat as an archive to explode (recursive re-dispatch, KAPE-zip pattern) |
| GrayKey / GrayShift | Full filesystem extraction (folder/image) | Same as iOS FS | Feed to iLEAPP |

**Key point:** iLEAPP/ALEAPP already emit a SQLite "timeline" table KronOS
could re-ingest directly (same pattern as §9's pre-parsed CSV case). Most
*message-level* mobile data is timeline-friendly; the *extraction
container* needs the same recursive-explosion treatment as a KAPE zip.

---

## 4. Network forensics

| Source | Format | Timeline? | OSS tooling |
|---|---|---|---|
| PCAP/PCAPng | Binary packet capture | Packets: yes (each timestamped); flows/sessions: graph | `scapy`, `pyshark`/`tshark`, `dpkt` |
| Zeek (v7/v8) | Per-protocol logs (`conn.log`, `dns.log`, `http.log`, ...) — TSV or JSON, `ts` + `uid` + Community-ID per row | ✅ Yes — explicitly timestamped event rows, excellent fit | stdlib JSON/TSV |
| Suricata (v8) `eve.json` | JSONL, one object per event: `timestamp`, `event_type`, 5-tuple, `community_id` | ✅ Yes — near-perfect `TimelineRecord` fit | stdlib JSONL |
| NetFlow/IPFIX/sFlow | Binary flow records (router-exported) | 🟡 Borderline — flows have start/end times, but the analytical value is the **connection graph/matrix** | `nfdump`/`nfcapd`, `python-netflow` |

**Nuance:** individual Zeek/Suricata/NetFlow records ARE timestamped events
(ingest fine as `TimelineRecord`). But the forensically interesting
*product* — "who talked to whom, how much" — is a connection
graph/adjacency matrix a flat timeline can't express. Both representations
are worth keeping in mind for future modules.

---

## 5. Cloud beyond AWS

All timeline-native (audit logs = event streams) → strong `TimelineRecord`
fit; the work is field-mapping (mirrors the existing `CloudTrailParser`
pattern), not a shape mismatch. **Highest ROI category.**

| Source | Format |
|---|---|
| Azure Activity Log | JSON events (REST/`az monitor`) |
| Entra ID (Azure AD) sign-in & audit logs | JSON or CSV export; sign-ins include risk/conditional-access detail |
| Microsoft 365 Unified Audit Log | Rows with an `AuditData` JSON column; CSV export or Purview Audit Search Graph API |
| GCP Cloud Audit Logs | JSONL, `protoPayload` (Admin Activity / Data Access / System Event) |
| Okta System Log | JSON via System Log API; `eventType`/`actor`/`client`/`outcome`/`published` |
| GitHub/GitLab audit logs | JSON/JSONL via audit-log API |

---

## 6. Container / Kubernetes forensics

| Source | Format | Timeline? |
|---|---|---|
| K8s audit logs | JSONL, one event per line (`verb`, `user`, `objectRef`, `requestReceivedTimestamp`) | ✅ Yes |
| Container runtime logs | JSON-file driver (`{"log","stream","time"}` per line) or journald | ✅ Yes |
| Falco (CNCF) alerts | JSON alert events | ✅ Yes (alert-time) |
| Sysdig capture (`.scap`) | Binary syscall capture (PCAP-for-syscalls) | Events: yes, but low-level |
| Image layer diffs | Filesystem diff between layers | ❌ A state delta/file listing, not chronology |

Mostly timeline-friendly; image-layer diffs are the non-timeline outlier.

---

## 7. macOS-specific

| Source | Format | Timeline? | OSS tooling |
|---|---|---|---|
| Unified Logs (`.tracev3`+`uuidtext`, `.logarchive`) | Proprietary binary | ✅ Yes — huge, high-volume event stream | **mac_apt** (Python), Mandiant `macos-UnifiedLogs` (Rust CLI) → CSV/JSON |
| FSEvents (`/.fseventsd/*`) | Proprietary binary, gzip'd | 🟡 Weak — logs *that* a path changed + change-type, no per-event timestamp/user, ordering only | **FSEventsParser** (Nicole Ibrahim, Python), mac_apt |
| Spotlight (`store.db`) | Binary metadata index | ❌ Metadata catalog/snapshot | `spotlight_parser`, mac_apt |
| `.plist` | XML or binary property lists | ❌ Mostly static config snapshot (occasional embedded timestamps) | stdlib `plistlib`, `ccl_bplist` |

**Bundled collector:** **mac_apt** parses most of the above into
SQLite/CSV — same "pre-parsed structured output" re-ingestion pattern as §9.

---

## 8. Email

| Format | Shape | Timeline? | OSS tooling |
|---|---|---|---|
| PST/OST | Proprietary binary mailbox container | Messages: yes (Date header); container: hierarchical folder tree | **`pypff`** (libyal — same family as `libewf`/`pyewf` already used via dfVFS for E01) |
| MBOX | Concatenated RFC 822 messages | ✅ Yes | stdlib `mailbox` |
| EML | Single RFC 822 MIME message | ✅ Yes | stdlib `email` |

Each message → one `TimelineRecord` works well; full email forensics also
cares about thread/reply graphs and folder hierarchy (non-timeline).
`pypff` aligns directly with KronOS's existing libyal/dfVFS stack.

---

## 9. Generic structured forensic tool output (pre-parsed re-ingestion)

A distinct case: the upstream tool already did the parsing — KronOS just
normalizes rows, no raw-artifact re-parsing needed.

- **EZ Tools** (`MFTECmd`, `RECmd`, `PECmd`, `LECmd`, `AmcacheParser`,
  `SBECmd`, ...) — CSV output, most rows timestamped → direct
  `TimelineRecord` mapping.
- **KAPE Modules output** — a KAPE package can contain *both* raw targets
  (already handled by `ZipArchiveParser`) and pre-parsed EZ Tools CSVs in
  `Module output/` — worth detecting and ingesting directly rather than
  re-parsing the raw artifact Plaso already covers.
- **Hayabusa** (Rust, v2.18+) — Sigma-based EVTX → CSV/JSON/JSONL timeline,
  includes MITRE ATT&CK rule-match metadata. Excellent fit.
- **Chainsaw** (WithSecure, Rust) — EVTX+Sigma → CSV/JSON detection rows.
- **Timesketch**-compatible JSONL (Plaso's own interchange format).
- **STIX 2.1 / MISP** — threat-intel **objects and relationship graphs**
  (JSON). **Non-timeline** — an indicator/relationship graph
  (`stix2`/`PyMISP` Python libs), used for enrichment/correlation.

---

## 10. Explicit "non-timeline artifact" catalogue

Concrete artifact types a flat `TimelineRecord` would misrepresent, with why
and a **plausible future** presentation (noted only — not designed now, per
explicit product direction: solve capture/storage first, presentation later).

| Artifact | Why not a timeline | Plausible future presentation |
|---|---|---|
| Process tree (Volatility `pstree`, `/proc` snapshot) | Parent/child structure, not chronology | Interactive collapsible tree/graph |
| Network connection matrix (NetFlow, Zeek aggregate, `netscan`) | "Who↔whom / volume" is an adjacency graph | Force-directed graph / heatmap matrix |
| Memory maps & injected regions (`malfind`, `vadinfo`, `memmap`) | Address-space layout at one instant | Memory-region map / hexdump viewer |
| File-hash sets (`filescan`, MFT listings, NSRL, image-layer diff) | A set/inventory for membership+dedup, no chronology | Searchable/diffable table, hash-lookup |
| Static config snapshots (`.plist`, systemd units, crontab, K8s manifests) | Declared state, not events | Config diff / structured key-value viewer |
| Permission/ACL & privilege listings (`/etc/passwd`, ACLs, `svcscan`) | A state inventory | Permission matrix / entitlement table |
| Spotlight/metadata catalogs | A searchable index, not an event log | Faceted metadata browser |
| STIX/MISP threat-intel objects | Indicator-and-relationship graph | Graph/link-analysis canvas + correlation overlay |
| Email folder & thread trees (PST hierarchy, reply chains) | Hierarchy/conversation structure | Folder tree + thread view |
| FSEvents change records | Records *that* a path changed, no reliable per-event timestamp/user | Path-change table (ordered, not time-plotted) |

This list is the concrete input to `StructuredArtifact.kind` values (see
`reviews/Data_Source_Module_System.md` §3) — each row here is a real,
named `kind` a future module will emit, deliberately stored opaquely for
now (no per-kind schema/UI decided yet).

---

## 11. Prioritization (impact vs. effort, not a commitment)

1. **Immediate, pure-timeline wins** (reuse the existing NDJSON/CSV
   field-mapping pattern from `CloudTrailParser`): Zeek logs, Suricata
   `eve.json`, all §5 cloud audit logs, K8s audit logs, Hayabusa/Chainsaw
   CSV, EZ Tools/KAPE-Module CSV re-ingestion, macOS Unified Logs.
2. **Container-explosion pattern** (reuse `ZipArchiveParser`'s recursive
   re-dispatch, zero new orchestration): UAC `.tar.gz`, Velociraptor `.zip`
   (JSONL), CyLR, iLEAPP/ALEAPP extractions, PST (`pypff`), Cellebrite UFDR.
3. **Needs the new `StructuredArtifact` model + eventual dedicated UI**
   (do NOT force into `TimelineRecord`): Volatility `pstree`/`malfind`/
   `netscan`, NetFlow graphs, STIX/MISP, everything in §10.

**Python-native tooling already aligned with KronOS's existing stack**
(stdlib, or the same libyal/dfVFS family already used for E01, or a
subprocess-CLI pattern matching `PlasoParser`/`FirecrackerLauncher`):
`volatility3` (pip), `iLEAPP`/`ALEAPP` (pip), `pypff` (libyal, same family
as `libewf`/`pyewf`), `plistlib`/`ccl_bplist`, `scapy`/`pyshark`, `laurel`
(auditd→JSON), Mandiant `macos-UnifiedLogs` (Rust CLI, subprocess),
Hayabusa/Chainsaw (Rust CLI, subprocess).

---

## Sources

[Volatility3 plugin docs](https://volatility3.readthedocs.io/en/latest/volatility3.plugins.html) ·
[UAC (tclahr)](https://github.com/tclahr/uac) ·
[Velociraptor releases](https://github.com/velocidex/velociraptor/releases) ·
[Plaso parsers](https://plaso.readthedocs.io/en/latest/sources/user/Parsers-and-plugins.html) ·
[Book of Zeek log formats](https://docs.zeek.org/en/master/log-formats.html) ·
[Suricata EVE JSON](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html) ·
[iLEAPP](https://github.com/abrignoni/iLEAPP) ·
[M365/Entra log export](https://learn.microsoft.com/en-us/purview/audit-log-export-records) ·
[macOS Unified Logs](https://cloud.google.com/blog/topics/threat-intelligence/reviewing-macos-unified-logs/) ·
[K8s audit logs & Falco](https://sysdig.com/learn-cloud-native/kubernetes-security/kubernetes-audit-log/) ·
[Hayabusa](https://github.com/Yamato-Security/hayabusa)

Version numbers cited from current (2026) official docs where confirmable;
where a specific point release wasn't confirmable (e.g. exact UAC/
Velociraptor patch version), the line is noted without inventing one — pin
the real version at PoC/implementation time per CLAUDE.md §F.2 step 1.
