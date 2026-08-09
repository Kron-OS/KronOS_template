# PoC: Suricata/Zeek live-tail source connector (roadmap Q3) -- L2

**Objective.** Prove a real log-shipper (fluent-bit, reusing this repo's own
existing `docker/fluent-bit/fluent-bit.conf` `tail`+`http` pattern) tailing a
real `eve.json` file and a real Zeek `conn.log` file forwards each newly
appended line, live, to KronOS's real `IntegrationSource` PUSH endpoints end
to end: real file append -> real fluent-bit `tail` input (inotify) -> real
`http` output -> real `POST /api/integrations/push/{suricata-eve,zeek-conn-log}`
-> real `StaticApiKeyInboundAuthenticator` -> real
`SuricataEvePushSource`/`ZeekJsonPushSource.parse_push_event` -> real
`IntegrationSourceIngestService.ingest_push` -> real dedup/backpressure ->
real `StreamIngestAdapter.produce` -> real audit event. Then, separately
(Phase 3), that the reused-ECS-mapping normalizers
(`SuricataEveStreamNormalizer` here, the pre-existing `ZeekConnLogNormalizer`)
resolve and normalize correctly via `StreamSourceNormalizerRegistry`.

**Stage reached (roadmap SS3): test-stage only**, matching Q1/Q2's own
precedent: no `docker-compose.dev.yml` service entry for a real dev-stack
fluent-bit-tailing-Suricata/Zeek deployment, no real
`StaticApiKeyProvisioning` wired into `startup.py` for a real customer's
sensors. The connector's logic is proven end-to-end below; its deployment
wiring is real follow-up work, not silently skipped.

## Versions pinned (real, this pass)

- `fluent/fluent-bit:3.1` -- the exact tag already pinned in this repo's own
  `docker/fluent-bit/docker-compose.fluent-bit.yml:12`, not assumed/"latest".
  Real pulled digest: `sha256:e72c08d2ec8d93999dfb74b17bd0ec8bcb07fedde0d53308f59e7aa0b5f293e1`
  (`fluent-bit` reports itself as `v3.1.10`, commit `e28f447995`, at boot).
- `kronos-backend:dev` -- this repo's own already-built dev image (Python/
  FastAPI/uvicorn/httpx runtime) for the receiver half, reused as-is with the
  current worktree's `src/`/`poc/` bind-mounted read-only over `/app` (its
  Python dependencies live in `/opt/venv`, confirmed by reading
  `docker/Dockerfile`, so the bind mount does not shadow anything installed).
- No real Suricata/Zeek binary was run -- see "What was NOT verified" below
  for why a real *log line* was still used, not fabricated freeform JSON.

## Real, previously-unverified gap found and fixed here (CLAUDE.md SS F)

This repo's own `docker/fluent-bit/fluent-bit.conf` (the dev-stack config,
used for KronOS's own application/Celery/Falco logs) sets `Parser json` on
every `tail` `[INPUT]` block but never sets `Parsers_File` anywhere in its
`[SERVICE]` block. Verified directly, not assumed: pointing a real
`fluent/fluent-bit:3.1` container at a config with `Parser json` and no
`Parsers_File` produces, at boot:

```
[error] [input:tail:tail.0] parser 'json' is not registered
```

fluent-bit does not fail to start -- it silently proceeds without ever
JSON-parsing that input, which for that repo file's own real production use
(structured KronOS/Celery/Falco JSON logs feeding OpenSearch/syslog outputs)
means the `Parser json` directive has almost certainly never actually taken
effect at runtime. Fixed **in this PoC's own `fluent-bit.conf`** by adding
`Parsers_File /fluent-bit/etc/parsers.conf` (the image's own bundled default,
which already defines a `json` parser) to `[SERVICE]` -- the error clears
immediately on the next boot (see `output.txt` Phase 1). **Not fixed in the
dormant `docker/fluent-bit/fluent-bit.conf` itself** -- that is a different
subsystem's own config, out of this connector module's scope (mirrors Q2's
own "report, don't silently fix outside scope" precedent for
`docker/wazuh/docker-compose.wazuh.yml`'s wrong version pin). Flagged for the
orchestrator to route to whoever owns that file.

## Real containers created (all `kronos-poc-*`, all torn down after each run)

Discovery phase (Phase 1, wire-format-only, torn down before the end-to-end
run):
- `kronos-poc-fluentbit-discovery`
- `kronos-poc-stub-receiver`

End-to-end phase (Phase 2):
- `kronos-poc-suricata-net` -- dedicated bridge network.
- `kronos-poc-suricatazeek-receiver` -- real KronOS FastAPI app + real
  `SuricataEvePushSource`/`ZeekJsonPushSource` (`run_poc_receiver.py`).
- `kronos-poc-suricatazeek-fluentbit` -- real fluent-bit 3.1, this dir's own
  `fluent-bit.conf`.

Confirmed via `docker ps -a`/`docker network ls` immediately after each
phase's teardown, and again independently re-checked at the start of this
verification pass (2026-08-09): no container or network from either phase
remains, and no container outside this PoC's own (the shared long-running
dev stack, `portainer_agent`, and unrelated concurrent-session containers)
was touched.

## Real mechanism confirmed

Neither Suricata nor Zeek exposes a push/webhook API of their own for
`eve.json`/JSON-log-writer output -- the documented, standard way to forward
either in real time is a log-shipper tailing the file, which is exactly what
this repo's own `docker/fluent-bit/fluent-bit.conf` already does for
KronOS's own logs. This PoC's `fluent-bit.conf` applies the identical
`tail` + `http` pattern to `/var/log/suricata/eve.json` and
`/var/log/zeek/conn.log` instead.

**Real, captured (not assumed from fluent-bit's docs, which do not clearly
specify this) wire format for `http` output `Format json_lines`:**
`Content-Type: application/x-ndjson`; body is one JSON object per originally
tailed line, newline-terminated; fluent-bit prepends its own ingestion-time
`date` field (float epoch, `json_date_key`'s default name) to each object,
leaving the original fields untouched; multiple lines that land within one
`Flush` window are concatenated as multiple NDJSON lines in a **single** POST
body -- not a JSON array, not separate requests. This directly informed
`_TailedNdjsonPushSource.parse_push_event`'s split-on-`\n` implementation in
`src/external/integration_sources/suricata_zeek.py`.

## How the real lines were produced

- **Suricata line:** copied byte-for-byte from this repo's own real,
  provenance-tracked fixture `tests/fixtures/samples/real/suricata/eve.json`
  line 2 (`alert`, `flow_id=1676750115612680`, `ET ATTACK_RESPONSE
  Win32/LeftHook Stealer` -- see that fixture directory's own `NOTICE.md`:
  real Suricata output traced to OISF's own userguide's documented real-pcap
  example). Appended live to an initially-empty `eve.json` while fluent-bit
  was already running and watching it via inotify -- a genuine live-tail
  event, not a pre-seeded backfill.
- **Zeek line:** hand-built (no equivalent real-captured `conn.log` fixture
  exists yet in this repo), with every field name/type/unit independently
  verified against Zeek's own source
  (`scripts/base/protocols/conn/main.zeek`'s `Conn::Info` record doc
  comments) -- the same rigor level `ZeekConnLogNormalizer`'s own tests and
  `poc/stream_normalization/run_poc.py` already established for Zeek
  elsewhere in this repo. See "What was NOT verified" below for why a full
  Zeek engine was not stood up to produce a fully organic line.

## How to reproduce

```bash
docker network create kronos-poc-suricata-net

mkdir -p /tmp/kronos-poc-suricata-zeek/logs2
touch /tmp/kronos-poc-suricata-zeek/logs2/eve.json
touch /tmp/kronos-poc-suricata-zeek/logs2/conn.log

docker run -d --name kronos-poc-suricatazeek-receiver --network kronos-poc-suricata-net \
  -v <repo-root>:/app:ro --entrypoint python3 \
  kronos-backend:dev /app/poc/integration_source_suricata_zeek/run_poc_receiver.py 90

docker run -d --name kronos-poc-suricatazeek-fluentbit --network kronos-poc-suricata-net \
  -v <this-dir>/fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf:ro \
  -v /tmp/kronos-poc-suricata-zeek/logs2:/var/log/suricata:ro \
  -v /tmp/kronos-poc-suricata-zeek/logs2:/var/log/zeek:ro \
  fluent/fluent-bit:3.1

# real trigger -- both files start empty, fluent-bit is already tailing:
sed -n '2p' tests/fixtures/samples/real/suricata/eve.json \
  >> /tmp/kronos-poc-suricata-zeek/logs2/eve.json
echo '<zeek-shaped JSON line>' >> /tmp/kronos-poc-suricata-zeek/logs2/conn.log

docker logs -f kronos-poc-suricatazeek-receiver   # observe the real pushes land

docker rm -f kronos-poc-suricatazeek-fluentbit kronos-poc-suricatazeek-receiver
docker network rm kronos-poc-suricata-net
```

## What `output.txt` actually captures (real, not reconstructed from memory)

1. **Phase 1 (wire-format discovery):** the real
   `parser 'json' is not registered` boot error with no `Parsers_File`, the
   real clean boot once fixed, one real captured request/response pair for a
   single record (`Content-Type: application/x-ndjson`, body content
   verbatim), then a second real captured request proving two lines
   appended back-to-back land as two NDJSON lines in one POST body.
2. **Phase 2 (real end-to-end run):** real image digests, real receiver boot
   log (uvicorn), real fluent-bit boot log (both `tail` inputs + both `http`
   outputs + `stdout` output all initializing cleanly), fluent-bit's own
   stdout showing both real forwarded records (Suricata alert + Zeek conn)
   with the real `date` field prepended, both real `HTTP status=202`
   forwards with real KronOS response bodies, and the real receiver-side
   stdout: two real inbound HTTP calls with full raw bodies, real
   `SuricataEvePushSource`/`ZeekJsonPushSource` validation passing, real
   `IntegrationSourceIngestService` outcomes (`accepted=True,
   duplicate=False`), real produced stream entries (`message_id=1-0`/`2-0`),
   two real `AuditEvent`s of type `integration_source.push_ingested`, and the
   final `REAL END-TO-END FLOW CONFIRMED FOR BOTH SOURCES` summary line.
3. **Cleanup confirmation:** `docker ps -a`/`docker network ls` output after
   teardown showing only the shared dev stack / `portainer_agent` /
   unrelated concurrent-session containers remaining.
4. **Phase 3 (unit-level, real fixture reuse):** a real Python REPL-style run
   splitting the full real 6-line Suricata fixture and normalizing every
   line via `SuricataEveStreamNormalizer` (all six real `event_type`s
   correctly mapped), plus the real-shaped Zeek line resolving through
   `StreamSourceNormalizerRegistry` to the pre-existing
   `ZeekConnLogNormalizer` with zero new normalizer code, plus two real
   negative cases (invalid JSON, missing `ts`) raising `ParsingError`.
5. **Phase 4 (automated tests):** the real `pytest` invocation for
   `test_suricata_zeek.py` alone (24 passed), plus a `git stash -u`
   before/after of the full suite as it stood *during that session*.
   **Superseded by this verification pass's own independent re-run below**
   (this repo has grown since that session — re-deriving the baseline live
   rather than trusting the number in this file, per this task's own
   instruction, is the correct thing to do every time this PoC is read).

## Independent re-verification performed this pass (2026-08-09)

Re-ran, without trusting any number already written above or in the roadmap
doc:

- `git stash -u` / re-run full suite / `git stash pop` / re-run full suite,
  using this worktree's own `~/venv`:
  - **Before (stashed):** `1647 passed, 1 skipped`
  - **After (popped):** `1671 passed, 1 skipped`
  - **Delta: +24**, exactly `test_suricata_zeek.py`'s own test count, zero
    regressions.
- `ruff check` on every touched file (`src/external/dependencies.py`,
  `src/external/integration_sources/suricata_zeek.py`,
  `tests/unit/integration_sources/test_suricata_zeek.py`,
  `poc/integration_source_suricata_zeek/run_poc_receiver.py`): found and
  fixed two real, this-pass-introduced issues (not pre-existing-baseline
  violations) -- an `E501` long line in `suricata_zeek.py`'s own module
  docstring, and an unsorted import block (`I001`) in
  `test_suricata_zeek.py` (fixed via `ruff check --fix`, then confirmed the
  resulting import grouping is still correct by inspection). Clean after.
- `black --check` on the same four files: clean, no changes needed.
- `mypy src`: **29 errors**, identical count to Q2's own documented
  baseline in `docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md`, **zero** of which
  are in `suricata_zeek.py` or the touched hunk of `dependencies.py`
  (grepped explicitly for both filenames in the output).
- Confirmed (again) via `docker ps -a` / `docker network ls` that no
  `kronos-poc-suricata*`/`kronos-poc-fluentbit*`/`kronos-poc-stub-receiver`
  container or network remains on the host from either phase.

## Honesty notes / what was NOT verified here

- **Only PUSH, never POLL** -- both Suricata's `eve.json` and Zeek's
  JSON-log-writer output are shipped by a tailing agent, not polled by
  KronOS; that shape is already proven generically by Q1's own
  `GenericPollSource` PoC.
- **In-memory stream/dedup/audit doubles inside the receiver**, not real
  Redis/Postgres -- identical, already-accepted PoC-tier bar
  `poc/integration_source_wazuh/run_poc_receiver.py`/
  `poc/integration_source_foundation/run_poc_push.py` established; those
  real backends are independently verified in `poc/stream_ingest_redis/`
  and their own repository tests.
- **No real Suricata or Zeek binary was run** -- fluent-bit was pointed at a
  plain file containing one real (Suricata) and one realistic-but-hand-built
  (Zeek) JSON line, not a live Suricata/Zeek process's own freshly-written
  log. This proves the log-shipper mechanism and the connector's parsing
  faithfully, but not that Suricata/Zeek's own file-writing behavior (e.g.
  partial-line writes mid-flush) behaves identically -- fluent-bit's `tail`
  input's own line-completeness handling is a fluent-bit concern, not this
  connector's, and is outside this PoC's scope.
- **Only one line per source forwarded live end-to-end.** The Suricata
  normalizer's handling of all six real `event_type`s in the full fixture
  (`fileinfo`/`alert`/`http`/`anomaly`/`flow`) is verified in Phase 3
  (direct calls) and in the real unit tests
  (`tests/unit/integration_sources/test_suricata_zeek.py`), not by pushing
  all six through the live fluent-bit pipeline.
- **`notice.log`/other Zeek log types not built.** Only `conn.log` has a
  `ZeekJsonPushSource`-equivalent registration
  (`source_type="zeek-conn-log"`) in this pass -- see
  `src/external/integration_sources/suricata_zeek.py`'s own module
  docstring. Adding another Zeek log type is a new `source_type` +
  `_validate_line` override on the same shared `_TailedNdjsonPushSource`
  base, not a new abstraction.
- **`docker/fluent-bit/fluent-bit.conf`'s own `Parsers_File` gap was not
  fixed** in that file -- flagged above, left for the orchestrator to route
  to whoever owns that config (out of this connector module's own scope,
  mirroring Q2's identical precedent for
  `docker/wazuh/docker-compose.wazuh.yml`).
- **No dev/prod-stage wiring (SS3)** -- no `docker-compose.dev.yml` service
  entry for a real dev-stack fluent-bit-tailing-Suricata/Zeek deployment, no
  real `StaticApiKeyProvisioning` wired into `startup.py`. Real follow-up
  work, matching Q1/Q2's own identical honesty note.
