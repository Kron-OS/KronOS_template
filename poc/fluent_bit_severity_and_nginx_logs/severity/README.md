# PoC: fluent-bit `Syslog_Severity_Key` real fix (Gap Audit P1-5)

**Objective.** Prove, against the real `fluent/fluent-bit:3.1` container (the
exact tag pinned in `docker/fluent-bit/docker-compose.fluent-bit.yml:12`),
that `docker/fluent-bit/fluent-bit.conf`'s syslog `[OUTPUT]` block really did
send the wrong/default severity for KronOS's real structured-logger `level`
strings (P1-5's documented bug), and that the real fix (five `modify`
`[FILTER]`s + reading a new `severity_num` field) makes the correct RFC 5424
numeric severity land on the wire for every real level this repo's logger
emits.

## Versions pinned (real, this pass)

- `fluent/fluent-bit:3.1` -- already pinned in
  `docker/fluent-bit/docker-compose.fluent-bit.yml:12`. Real running version
  self-reported at boot: `v3.1.10`, commit `e28f447995` (same image already
  used by Q3's own `poc/integration_source_suricata_zeek/`).
- `structlog>=24.1` (`pyproject.toml`); real installed version in this
  worktree's venv: `26.1.0` (`~/venv/bin/python3 -c "import structlog;
  print(structlog.__version__)"`).

## Real level strings this repo's logger actually emits (verified, not assumed)

Two independent checks, cross-confirmed:

1. `structlog.stdlib.map_method_name`'s own real source
   (`~/venv/bin/python3 -c "import structlog, inspect; from
   structlog._log_levels import map_method_name; print(inspect.getsource(
   map_method_name))"`):
   ```python
   def map_method_name(method_name: str) -> str:
       # warn is just a deprecated alias in the stdlib.
       if method_name == "warn":
           return "warning"
       # Calling exception("") is the same as error("", exc_info=True)
       if method_name == "exception":
           return "error"
       return method_name
   ```
2. `grep -rhoE "logger\.(debug|info|warning|warn|error|critical|exception)\("
   src/` — real call-site counts: `info` (89), `warning` (58), `error` (20),
   `debug` (8), `critical` (3), `exception` (1). Zero raw `.warn(` call
   sites.

Combined: the real, complete set of `level` strings this repo's logger can
ever emit is exactly `{"debug", "info", "warning", "error", "critical"}` --
**never** `"warn"` (the brief's own framing assumed this; the deprecated
alias always normalizes to `"warning"` before `add_log_level` runs).

## RFC 5424 numeric severities used (verified against the RFC itself)

RFC 5424 §6.2.1's own table: `emerg=0, alert=1, crit=2, err=3, warning=4,
notice=5, info=6, debug=7`. KronOS's logger can only ever emit 5 of the 8
real levels (Python's `logging` module has no `emerg`/`alert`/`notice`), so
the real mapping needed is: `debug=7, info=6, warning=4, error=3,
critical=2`.

## Mechanism chosen: `modify` FILTER + `Condition Key_Value_Equals`

Verified directly against the real 3.1.10 binary (no shell/`cat` available
in the image -- confirmed via `docker run --rm --entrypoint sh
fluent/fluent-bit:3.1 -c "..."` producing no output; used `docker create` +
`docker cp` to inspect `/fluent-bit/etc/parsers.conf` instead): a config
with five `[FILTER] Name modify / Condition Key_Value_Equals level <value> /
Set severity_num <n>` blocks initializes with **zero** config errors, and a
real appended-live JSON line for each of the five levels produces the
correct `severity_num` in the real fluent-bit stdout output (see "Filter
mechanism smoke test" below). Chosen over a `lua` filter because
`fluent-bit.conf` is bind-mounted as a single file in
`docker-compose.fluent-bit.yml` (no script directory to also mount), and
over rewriting `level` in place because a new field (`severity_num`) is
non-destructive -- the existing OpenSearch `[OUTPUT]`s and the `parser`
`[FILTER]` upstream of them still see the original `level` string
unchanged.

## Filter mechanism smoke test (real, captured)

Real fluent-bit container, `smoketest.conf` (5 `modify` filters + `stdout`
OUTPUT only), real live-appended JSON lines:

```
[2026/08/14 13:59:59] [ info] [input:tail:tail.0] inotify_fs_add(): inode=1417027 watch_fd=1 name=/var/log/kronos-poc/app.log
[2026/08/14 13:59:59] [ info] [output:stdout:stdout.0] worker #0 started
```

(no config errors at boot for any of the 5 `modify`/`Condition` blocks)

After appending one real JSON line per level:

```
{"date":1786716041.367538,"level":"debug","service":"kronos-backend","event":"poc live debug","timestamp":"2026-08-14T00:00:05Z","severity_num":"7"}
{"date":1786716044.537738,"level":"info","service":"kronos-backend","event":"poc live info","timestamp":"2026-08-14T00:00:06Z","severity_num":"6"}
{"date":1786716045.63445,"level":"warning","service":"kronos-backend","event":"poc live warning","timestamp":"2026-08-14T00:00:07Z","severity_num":"4"}
{"date":1786716046.265073,"level":"error","service":"kronos-backend","event":"poc live error","timestamp":"2026-08-14T00:00:08Z","severity_num":"3"}
{"date":1786716046.489256,"level":"critical","service":"kronos-backend","event":"poc live critical","timestamp":"2026-08-14T00:00:09Z","severity_num":"2"}
```

Every `severity_num` matches the RFC 5424 table exactly.

## Real end-to-end run: BEFORE (bug reproduced) vs AFTER (fix verified)

Both runs use the identical real components: `fluent-bit-before.conf` /
`fluent-bit-after.conf` (this directory), a real `fluent/fluent-bit:3.1`
container run with `--network host` (so its `syslog` OUTPUT can reach
`127.0.0.1:5514` on the host), and `udp_syslog_receiver.py` -- a real
`asyncio.DatagramProtocol` UDP listener (structurally identical to
`poc/integration_sink_cef_syslog/run_poc.py`'s own real local TCP/UDP
receivers), run as a plain host process, that independently re-derives the
RFC 5424 PRI-header decode (facility/severity) rather than importing
anything from `docker/fluent-bit/` -- a genuine external check, not the
same mapping checking itself.

Five real JSON lines (one per level) were appended live to a tailed file
after each fluent-bit container was already running and watching it via
inotify.

### BEFORE (`fluent-bit-before.conf` -- the real, unfixed
`Syslog_Severity_Key level`)

Real fluent-bit container log -- **the real, documented bug, reproduced
exactly**:

```
[2026/08/14 14:01:33] [ info] [output:syslog:syslog.0] setup done for 127.0.0.1:5514 (TLS=off)
...
{"date":1786716100.266254,"level":"debug", ...}
{"date":1786716100.308765,"level":"info", ...}
{"date":1786716100.345328,"level":"warning", ...}
{"date":1786716100.476511,"level":"error", ...}
{"date":1786716100.737808,"level":"critical", ...}
[2026/08/14 14:01:41] [ warn] [output:syslog:syslog.0] invalid severity: 'debug'
[2026/08/14 14:01:41] [ warn] [output:syslog:syslog.0] invalid severity: 'info'
[2026/08/14 14:01:41] [ warn] [output:syslog:syslog.0] invalid severity: 'warning'
[2026/08/14 14:01:41] [ warn] [output:syslog:syslog.0] invalid severity: 'error'
[2026/08/14 14:01:41] [ warn] [output:syslog:syslog.0] invalid severity: 'critical'
```

Real UDP receiver output -- decoded PRI header per datagram:

```
=== real local UDP syslog receiver listening on 127.0.0.1:5514 ===
[RAW] '<15>1 2026-08-14T14:01:40.266254Z - kronos-backend - - -'
    -> PRI=15 facility=1 severity=7 (debug) ...
[RAW] '<14>1 2026-08-14T14:01:40.308765Z - kronos-backend - - -'
    -> PRI=14 facility=1 severity=6 (info) ...
[RAW] '<12>1 2026-08-14T14:01:40.345328Z - kronos-backend - - -'
    -> PRI=12 facility=1 severity=4 (warning) ...
[RAW] '<14>1 2026-08-14T14:01:40.476511Z - kronos-backend - - -'
    -> PRI=14 facility=1 severity=6 (info) ...
[RAW] '<14>1 2026-08-14T14:01:40.737807Z - kronos-backend - - -'
    -> PRI=14 facility=1 severity=6 (info) ...

[SUMMARY] real datagrams received: 5
```

**Real, more nuanced finding than the pre-existing (Milestone S) doc
comment assumed:** the old comment in `fluent-bit.conf` said the bug
"falls back to the plugin's own default severity 6/info" uniformly. The
real captured behavior is messier: `debug`→7, `info`→6, `warning`→4 all
land **correctly by coincidence** (fluent-bit's own fallback keyword table
happens to recognize the RFC 5424 severity *names* even while still
logging "invalid severity"), but `error`→6 and `critical`→6 are **silently
wrong** (RFC 5424's real keywords for those are the abbreviations `err`/
`crit`, which `"error"`/`"critical"` don't match). So under the old config,
a real ERROR or CRITICAL KronOS log line was mis-reported to any downstream
severity-based syslog routing as if it were merely INFO -- worse than the
old comment's own "same severity regardless of level" framing, since it
wasn't uniformly wrong, just wrong for exactly the two most operationally
important levels.

### AFTER (`fluent-bit-after.conf` -- the real fix, `Syslog_Severity_Key
severity_num`)

Real fluent-bit container log -- **zero `invalid severity` warnings**:

```
[2026/08/14 14:02:27] [ info] [output:syslog:syslog.0] setup done for 127.0.0.1:5514 (TLS=off)
...
{"date":1786716151.728769,"level":"debug", ..., "severity_num":"7"}
{"date":1786716151.784776,"level":"info", ..., "severity_num":"6"}
{"date":1786716151.816533,"level":"warning", ..., "severity_num":"4"}
{"date":1786716151.90095,"level":"error", ..., "severity_num":"3"}
{"date":1786716152.161459,"level":"critical", ..., "severity_num":"2"}
```

(no `[warn]`/`[error]` lines at all in the full container log after this
point)

Real UDP receiver output -- **every severity now correct**:

```
[RAW] '<15>1 2026-08-14T14:02:31.728768Z - kronos-backend - - -'
    -> PRI=15 facility=1 severity=7 (debug) ...
[RAW] '<14>1 2026-08-14T14:02:31.784775Z - kronos-backend - - -'
    -> PRI=14 facility=1 severity=6 (info) ...
[RAW] '<12>1 2026-08-14T14:02:31.816532Z - kronos-backend - - -'
    -> PRI=12 facility=1 severity=4 (warning) ...
[RAW] '<11>1 2026-08-14T14:02:31.900949Z - kronos-backend - - -'
    -> PRI=11 facility=1 severity=3 (err) ...
[RAW] '<10>1 2026-08-14T14:02:32.161458Z - kronos-backend - - -'
    -> PRI=10 facility=1 severity=2 (crit) ...

[SUMMARY] real datagrams received: 5
```

`debug=7, info=6, warning=4, error=3(err), critical=2(crit)` -- exactly the
real RFC 5424 table, for every real level KronOS's logger emits.

## Real containers created (all `kronos-poc-*`, torn down after each run)

- `kronos-poc-fb-smoketest` / `kronos-poc-fb-smoketest2` -- filter mechanism
  smoke tests.
- `kronos-poc-fb-severity-before` -- real end-to-end BEFORE run.
- `kronos-poc-fb-severity-after` -- real end-to-end AFTER run.

Confirmed via `docker ps -a | grep kronos-poc` (exit 1, no matches) after
teardown that none remain. No shared dev-stack container was touched (this
PoC's fluent-bit containers ran with `--network host`, entirely separate
from the running `docker-*` project containers).

## How to reproduce

```bash
rm -f /tmp/kronos-poc-severity/app.log && touch /tmp/kronos-poc-severity/app.log
python3 poc/fluent_bit_severity_and_nginx_logs/severity/udp_syslog_receiver.py 5514 18 &

docker run -d --name kronos-poc-fb-severity-before --network host \
  -v $(pwd)/poc/fluent_bit_severity_and_nginx_logs/severity/fluent-bit-before.conf:/fluent-bit/etc/fluent-bit.conf:ro \
  -v /tmp/kronos-poc-severity/app.log:/var/log/kronos-poc/app.log:ro \
  fluent/fluent-bit:3.1

# append one real JSON line per level (debug/info/warning/error/critical) to
# /tmp/kronos-poc-severity/app.log via `printf '...' >> ...` (live inotify
# tail), then inspect `docker logs kronos-poc-fb-severity-before` and the
# receiver's stdout.

docker rm -f kronos-poc-fb-severity-before
# repeat with fluent-bit-after.conf / kronos-poc-fb-severity-after
```

## What was NOT verified here

- **Only the syslog OUTPUT path.** The OpenSearch OUTPUTs
  (`kronos.backend`/`kronos.falco`) don't read `Syslog_Severity_Key` at all
  and are unaffected by this fix; not re-verified here (already covered by
  Milestone S's own real OpenSearch verification).
- **Real Wazuh manager as the receiver.** A real local UDP receiver
  (matching R1/R3's own established pattern) stands in for
  `wazuh-manager:514`; Wazuh's own severity interpretation of an inbound
  RFC 5424 message is a Wazuh-side concern, out of this fix's scope.
