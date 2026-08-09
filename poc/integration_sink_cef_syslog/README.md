# PoC: Generic CEF-over-syslog sink connector (roadmap R3, `docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md`)

**Objective (roadmap R3, verbatim):** "Real CEF-formatted message over real
syslog transport, against a real local syslog receiver — proves the ABC's
second, non-HTTP, no-ack transport shape."

## Design decision: reuse `SyslogIntegrationSink` (R1) unchanged — no sibling sink class

The roadmap brief for this item explicitly asked for a justified choice
between building a sibling `IntegrationSink` (as R2 did for Splunk HEC) or
reusing an existing one. **R3 lands on the opposite answer from R2, for a
specific, verifiable reason:** CEF-over-syslog's real wire shape (verified
against the sources below) is an ordinary RFC 3164 BSD-syslog line whose
message body happens to start with the literal token `CEF:0|...` —

```
<PRI>Mmm dd hh:mm:ss host CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
```

`SyslogIntegrationSink.push_events()` (`src/adapter/integration_sink/syslog_sink.py`,
R1, **unmodified this pass**) already does exactly one thing: write
whatever `MappedSinkEvent.raw_text` string it is given, as one line over a
real TCP connection or one real UDP datagram — it never inspects, reshapes,
or adds anything to that string. Nothing about a CEF line needs different
*socket* behavior from any other line this sink already sends; the entire
CEF-specific requirement (RFC 3164 header, `CEF:0` marker, header-vs-
extension escaping rules) is about the **string contents**, which
`MappedSinkEvent`'s own docstring already assigns to the mapper's job
("only the mapper knows the target's own field dictionary, so formatting
happens here, never in the transport"). Building a sibling sink class here
would duplicate R1's real TCP/UDP-write-and-honest-`UNACKNOWLEDGED` logic
for zero behavioral gain — this is the mirror image of R2's own conclusion
that a sibling class *was* justified there (Splunk HEC's concatenated-JSON
batch body and whole-batch `{"text","code"}` ack are structurally
different from the generic `HttpJsonIntegrationSink` envelope; nothing
about CEF-over-syslog is structurally different from a plain syslog line).

New this pass: `src/application/cef_detection_mapper.py`
(`CefDetectionMapper(DetectionEventMapper)`) — maps one `Detection` into a
fully RFC 3164-framed, properly escaped CEF line as `MappedSinkEvent.raw_text`,
which the real, unmodified `SyslogIntegrationSink` then writes as-is.

## What was actually researched and verified this pass (not from memory)

1. **Real CEF wire shape and escaping rules** — Micro Focus/OpenText's own
   "Implementing ArcSight Common Event Format (CEF)" guide (the CEF spec's
   maintaining vendor), corroborated word-for-word on the escaping rules by
   Micro Focus's "What is CEF?" doc page and the community.opentext.com CEF
   White Paper, and independently cross-checked against Microsoft
   Sentinel's own CEF-via-AMA connector docs
   (`learn.microsoft.com/en-us/azure/sentinel/connect-cef-syslog-ama`):
   - Header/"prefix" zone (the 7 pipe-delimited fields `Version` through
     `Severity`): a literal `|` MUST become `\|`; a literal `\` MUST become
     `\\`. Equals signs are left untouched.
   - Extension zone (space-separated `key=value` pairs): a literal `=`
     MUST become `\=`; a literal `\` MUST become `\\`. Pipes are left
     untouched.
   - Backslash-escaping is applied FIRST in both zones, before the
     zone-specific delimiter escaping — otherwise a backslash just
     inserted to escape a `|`/`=` would itself get re-escaped.
   - **This exact algorithm was independently re-verified by the round-trip
     parser in `run_poc.py` (`parse_cef_syslog_line`/`_split_escape_aware`/
     `_unescape`), deliberately NOT importing `cef_detection_mapper.py`'s
     own private escaping helpers** — the round-trip proof is a genuine
     independent re-derivation of the spec, not "the same code checking
     itself."
2. **RFC 3164 (BSD syslog), not RFC 5424** — every real CEF worked example
   in the official Micro Focus/OpenText docs, and every named-vendor
   CEF-over-syslog configuration guide found (Palo Alto Networks, Centrify,
   Microsoft Sentinel's own CEF-via-AMA connector), uses the plain
   `Mmm dd hh:mm:ss host CEF:0|...` BSD-style prefix, never RFC 5424's
   structured-data form. `facility=local4` (RFC 3164 facility code 20) is
   used as the default PRI facility, matching Microsoft's own CEF-via-AMA
   connector docs ("the syslog agent sets the facility to local4 for CEF
   forwarding" by default).
3. **CEF Severity mapping** — the real spec's own worked guidance bands
   (0-3 Low, 4-6 Medium, 7-8 High, 9-10 Very High) mapped deterministically
   onto KronOS's existing Sigma severity vocabulary
   (`informational→0, low→3, medium→5, high→8, critical→10`), ascending to
   match `SIGMA_SEVERITY_LEVELS`'s own ordering.
4. **`SyslogIntegrationSink` re-read, unmodified** — confirmed it has
   exactly one `return` statement in `push_events()` (always
   `SinkAck(status=SinkAckStatus.UNACKNOWLEDGED, ...)`), i.e. it is
   *structurally* incapable of ever returning `ACKNOWLEDGED` — the honesty
   property this whole R1/R2/R3 line requires, re-confirmed by direct code
   reading, not assumed to still hold after R2's changes to sibling files.

## The real receivers used

Per roadmap §1 invariant 9 (no live third-party SaaS, ever), this PoC
stands up two real local receivers on `127.0.0.1` — a real `asyncio` TCP
server and a real `asyncio` UDP listener — standing in for a real
CEF-over-syslog SIEM ingestion endpoint (e.g. QRadar's syslog+LEEF/CEF
receiver, or a generic rsyslog/syslog-ng CEF collector). No realistic
free/self-hostable "real CEF SIEM" image exists that would add anything a
protocol-accurate local stand-in doesn't already prove for this specific
transport (unlike R2's Splunk, syslog itself has no vendor-specific
ingestion logic to validate against — the wire format IS the entire
contract). The real, live dev-stack Postgres 16 (`docker-postgres-1`,
already running for this whole initiative, not created/torn down by this
script) is used for the Scenario 5 audit-hash-chain proof — never an
InMemory double.

## Pinned versions

- Python stdlib `asyncio` (TCP `start_server`/UDP `create_datagram_endpoint`)
  for both the real production transport (`SyslogIntegrationSink`) and the
  PoC's own receivers — no version pinning needed, same runtime as every
  other `asyncio`-based module in this repo.
- `postgres:16-alpine` (`docker/docker-compose.dev.yml`) — the same live
  `docker-postgres-1` container prior PoCs in this initiative used.
- `sqlalchemy[asyncio]`/`asyncpg` at the versions pinned in `pyproject.toml`
  — the real async engine used for the audit-trail scenario.

## Scenarios covered (see `output.txt` for the full, unedited captured run)

1. **Clean push over real TCP** — `CefDetectionMapper` + the real,
   unmodified `SyslogIntegrationSink` push one ordinary `Detection`; the
   real bytes received by the real local TCP listener are parsed back
   apart field-by-field (RFC 3164 prefix, 7 CEF header fields, extension
   `key=value` pairs) by an independently-written parser, and every
   recovered value is compared against the source `Detection`'s own real
   attributes.
2. **Same over real UDP** — same round-trip proof, different transport.
3. **Escaping edge case** (the roadmap's own required deliberate case) — a
   `Detection` whose `detector_name`/`rule_name`/`finding_id` deliberately
   contain a literal `|`, `\`, and `=`, pushed over real TCP. The real
   received bytes are parsed back the same field-by-field way, with every
   recovered value asserted to EXACTLY equal the original raw field, PLUS
   direct wire-level assertions on the escaped bytes themselves (not just
   the recovered values) to prove the escaping rules were actually applied,
   not merely that round-trip recovery happens to work:
   - `malware\|scanner\\v2` on the wire for header field `detector_name`
     containing `malware|scanner\v2` (both `|` and `\` escaped).
   - `Blocked C2 (proto=tcp\|udp)` on the wire for header field `rule_name`
     containing `Blocked C2 (proto=tcp|udp)` — the `|` is escaped (header
     zone), the `=` is left untouched (header zone doesn't escape `=`).
   - `case\=1234|alert\=5678` on the wire inside the extension `msg` value
     for `finding_id` containing `case=1234|alert=5678` — the `=` is
     escaped (extension zone), the `|` is left untouched (extension zone
     doesn't escape `|`).
4. **Honesty property re-confirmed for CEF specifically** — both the clean
   and edge-case pushes report `SinkAckStatus.UNACKNOWLEDGED`, never
   `ACKNOWLEDGED`.
5. **Real failure path** — a real `ConnectionRefusedError` against a real
   closed TCP port still raises `IntegrationSinkError` through the
   unmodified `SyslogIntegrationSink` (mirrors R1's own failure scenario;
   `CefDetectionMapper` does not change this contract at all).
6. **`DetectionSinkPushService` full orchestration + real Postgres audit
   trail** — a real CEF push through the real service produces real
   `SINK_PUSH_ATTEMPTED`/`SINK_PUSH_EXECUTED` audit rows, independently
   re-read from a fresh Postgres connection and hash-chain-verified
   end-to-end (mirrors the roadmap's own hard invariant: "audit every
   mutation — reuse `DetectionSinkPushService`'s own idiom, don't
   reinvent").

**35/35 checks passed** (see `output.txt` for the full, unedited captured
run from the final PoC version — every line is real stdout, not
paraphrased).

## Bug this PoC run actually found (the whole point of Section F)

The first real run of `run_poc.py` surfaced a **real bug in the PoC
script's own Scenario 3 wire-level assertion**, not in production code: it
asserted the literal substring `"Blocked C2 (proto=tcp|udp)"` (fully
unescaped) appears in the raw wire bytes, but `rule_name` is itself a
**header-zone** field and contains its own `|` — which the mapper
correctly escapes to `\|` per the real spec's own rule (only extension-zone
pipes are left unescaped). The wire bytes are actually
`Blocked C2 (proto=tcp\|udp)` — correct per spec — and the assertion was
checking for the wrong (over-simplified) string. Fixed by asserting the
correctly-escaped substring `"Blocked C2 (proto=tcp\\|udp)"`, with the
assertion label updated to explain why: "the rule_name's OWN `|` is
correctly escaped since it's also in the header zone." The round-trip
recovery check (which already correctly recovered the original unescaped
`rule_name`) was passing the whole time — only the direct wire-format
assertion had the bug, confirming the escaping implementation itself was
correct from the first real run; only the PoC's own test authoring needed
a fix. This was caught only because the PoC was actually executed and its
FAIL output actually read, not because the code "looked plausible."

## How to run

```bash
# 1. Ensure the real dev-stack Postgres is up (already running for this initiative):
docker ps --filter name=docker-postgres-1

# 2. Run the PoC (starts/stops its own real local TCP+UDP receivers; no
#    other container is touched or required):
~/venv/bin/python3 poc/integration_sink_cef_syslog/run_poc.py
```

Nothing this script starts (the local TCP/UDP receivers) is left listening
afterward — `TcpSyslogReceiver.stop()`/`UdpSyslogReceiver.close()` are
called unconditionally at the end of `main()`, independently confirmed via
`ss -tlnp` after the run.
