# PoC: cross-source log normalization alignment

**Real question from the project owner**: "does win and lin signin produce
logs where signin is the logtype" — checked more broadly against logs from
custom containers and variable web sources too.

## Scope (defined via a research-only subagent, then independently verified)

1. **Fields to compare**: `TimelineRecord`'s ECS event fields
   (`src/domain/timeline.py`) — `event_kind` (`event.kind`), `event_category`
   (`event.category`, list), `event_type` (`event.type`, list),
   `event_outcome` (`event.outcome`). No ECS spec version is pinned anywhere
   in this repo.
2. **Source pairs and their real ingestion paths**:
   - Windows signin → `.evtx` routes to **PlasoParser** in the real, live
     registry (`FastEvtxParser` was deliberately deregistered, Gap Audit
     Milestone VVVV — see `src/external/dependencies.py`'s own comment).
   - Linux signin → a plain-text auth log has no magic-byte/extension match
     anywhere in the real registry.
   - "Custom container" logs → no fixed parser applies by design; the real
     generic path is `StreamNormalizationService`/`StreamSourceNormalizerRegistry`
     (`src/application/stream_normalization.py`,
     `src/application/stream_source_registry.py`), which only has Zeek/
     Wazuh/Defender normalizers registered.
   - "Variable web sources" → `NginxParser` already handles both nginx's
     own format and Apache combined-log-format (confirmed by its own code
     comment and this PoC's own real run).
3. **Samples location**: `poc/cross_source_log_alignment/samples/` (this
   PoC's own scratch evidence) — copied into
   `tests/fixtures/samples/real/` (see that dir's `NOTICE.md`) for the real,
   committed, repeatable test (`tests/unit/parsers/test_cross_source_log_alignment.py`).
4. **"Aligned" means**: both sides produce `event_category` containing
   `"authentication"` and a real, shared `event_type` value, with
   `event_outcome` distinguishing success/failure. "Not aligned" means
   either divergent vocabulary, or (as found here) no classification field
   populated at all on one or both sides.

## Real samples collected (via a subagent, real provenance recorded per-sample)

| File | Real source |
|---|---|
| `windows_security.evtx` | `omerbenamram/evtx` (the real upstream project for the pinned `evtx`/pyevtx-rs Python package), `samples/Security_short_selected.evtx`, verified via a real parse to contain a genuine EventID 4625 (failed logon, LogonType 10/RDP, source IP `23.94.153.202`) |
| `linux_auth.log` | This host's own real `/var/log/auth.log.1` — a genuine local PAM `session opened`/`session closed` login sequence |
| `custom_container.log` | Real `docker logs` output from a briefly-run `redis:7-alpine` container (removed afterward) |
| `nginx.log` / `apache_access.log` | Pre-existing real fixtures already in this repo |

## Real, captured run (`output.json`, inside `docker-celery-worker-plaso-1`)

Ran the REAL, live `get_parser_registry()` (the exact selection
`execute_parse()` uses in production) against each real sample's real
header bytes, then ran the winning parser's real `parse()` against the
real full file, for every sample.

- **`windows_security.evtx`** → claimed by `plaso`. Produces 14 real
  `TimelineRecord`s (Plaso's own real de-duplication artifact, not a PoC
  bug), including the genuine EventID 4625 record
  (`message` contains `"[4625 / 0x1211] ... An account failed to log
  on. ... Logon Type: 10 ... Administrator ... Status: 0xc000006d"`).
  **Every single record's `event_kind`/`event_category`/`event_type`/
  `event_outcome` is `null`/`[]`.** Root cause confirmed by reading
  `FirecrackerLauncher._stream_records` (`src/external/sandbox/firecracker.py`):
  it constructs every Plaso-derived `TimelineRecord` with only
  `@timestamp`/`message`/`event_original`/`extra`/`kronos` — no ECS
  classification fields are ever set for anything routed through Plaso.
- **`linux_auth.log`** → `claimed_by_parser: null`. Never becomes a
  `TimelineRecord` at all — no registered parser accepts a plain-text
  auth log.
- **`custom_container.log`** → `claimed_by_parser: null`. Same outcome —
  KronOS's evidence-upload parser registry has no generic fallback for an
  arbitrary custom container's own log format. Independently confirmed via
  `StreamSourceNormalizerRegistry.for_source("some-custom-container-source")`
  → `None` on the generic streaming path too.
- **`nginx.log`** and **`apache_access.log`** (positive control) → both
  claimed by `NginxParser`, both produce `event_kind="event"`,
  `event_category=["web"]`, `event_type=["access"]` on every record — real,
  consistent alignment, proving the mechanism works whenever a shared
  parser actually exists for both sides.

## The real, decisive answer

Not "Windows and Linux signin events diverge from each other" — it's
**"neither side is classified as a signin/authentication event at all
today,"** for two different real reasons: Windows-EVTX-via-Plaso records
parse but carry zero ECS classification; Linux auth-log records never even
get ingested. The positive control (nginx vs. apache) shows the
normalization *mechanism* itself is sound — the gap is specific to (a) the
Plaso path never setting ECS fields on any record it produces, regardless
of source format, and (b) plain-text syslog-style auth logs and arbitrary
custom-container logs having no ingestion path at all yet.

## Status

**PASS as a verification exercise** (the real question is now answered
with real, captured evidence) — but the underlying platform capability
itself is a **real, confirmed gap**, now locked in as an explicit,
documented regression check:
`tests/unit/parsers/test_cross_source_log_alignment.py` (6 tests run
unconditionally on any host; a 7th, requiring real Plaso, run and
confirmed passing inside `docker-celery-worker-plaso-1`). See
`docs/GAP_AUDIT_2026-09-08_MILESTONE_HHHHH.md` for the milestone summary
and recommended follow-up (not built this cycle — scope was "build the
test," not "fix the gap," per the project owner's own request).
