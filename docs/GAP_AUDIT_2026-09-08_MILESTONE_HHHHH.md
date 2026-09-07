# Gap Audit — Milestone HHHHH (2026-09-08)

**Scope:** the project owner asked for a real test checking whether KronOS
normalizes semantically-equivalent log events consistently across
different real sources — their own example: "does win and lin signin
produce logs where signin is the logtype," checked more broadly against
"logs from custom containers" and "variable web sources" too. Explicit
process requested: a subagent to define scope, subagent(s) to collect real
samples into a directory, then a real test that ingests and compares
fields.

## The real issue / what changed

Followed the requested process exactly: a research-only Explore subagent
read KronOS's real parsers/registry/ECS schema and proposed a concrete
scope (source pairs, target fields, sample locations); its most decisive
claim — that Plaso-derived `TimelineRecord`s never get ECS event
classification — was independently re-verified by reading
`FirecrackerLauncher._stream_records` directly before being trusted. A
second subagent then collected real samples (a genuine Windows Security
EVTX with EventID 4625 from the real upstream `evtx`/pyevtx-rs project;
real `docker logs` output from a briefly-run `redis:7-alpine` container),
while a real excerpt of this host's own `/var/log/auth.log` was pulled
directly. All samples landed in `poc/cross_source_log_alignment/samples/`
per CLAUDE.md §F, then copied into `tests/fixtures/samples/real/` (with
`NOTICE.md` provenance) for a real, committed, repeatable test.

**Real, decisive finding**: neither a genuine Windows signin-failure event
nor a genuine Linux signin event is classified as an authentication event
by KronOS today — for two different reasons, confirmed by an actual run
of the real, live parser registry against real bytes, not by reading code
and guessing:

1. **Windows** (`windows_security.evtx`, real EventID 4625) routes to the
   real, live `PlasoParser` (the only registered EVTX handler since Gap
   Audit Milestone VVVV deregistered `FastEvtxParser`). It parses
   correctly — the real failure-reason/logon-type/account-name data is all
   present in the record's own `message` text — but
   `FirecrackerLauncher._stream_records` (`src/external/sandbox/firecracker.py`)
   only ever sets `@timestamp`/`message`/`event_original`/`extra`/`kronos`
   on every `TimelineRecord` it yields. `event_category`/`event_type`/
   `event_kind`/`event_outcome` are `[]`/`[]`/`None`/`None` on every single
   Plaso-derived record, regardless of source format — this is not
   specific to signin events, it's a total absence of ECS classification
   for the entire Plaso ingestion path.
2. **Linux** (`linux_auth.log`, a real PAM login-session sequence) fares
   *worse*: no parser in the real, live registry claims a plain-text auth
   log at all (no magic-byte match, `.log` extension not in any
   `_SUPPORTED_EXTENSIONS` set, and `NginxParser`'s own combined-log-format
   regex correctly does not false-positive-match it). It never becomes a
   `TimelineRecord` in the first place.
3. **"Custom container" logs** (real `redis:7-alpine` stdout) hit the same
   "no claiming parser" outcome on the evidence-upload path, and
   `StreamSourceNormalizerRegistry.for_source()` — the real generic
   streaming/collector path's own registry — also returns `None` for an
   arbitrary custom source_id (only Zeek/Wazuh/Defender normalizers are
   registered).
4. **Positive control** (`nginx.log` vs. real `apache_access.log`,
   pre-existing fixtures): both route to the same `NginxParser` and both
   produce identical, real `event_category=["web"]`/`event_type=["access"]`
   — proving the normalization *mechanism* itself works correctly whenever
   a shared parser exists. The gap is specific to the Plaso path (zero
   classification, any format) and to formats with no ingestion path at
   all yet (plain-text auth logs, arbitrary custom-container logs) — not a
   limitation of `TimelineRecord`'s own schema.

## What was built

- `poc/cross_source_log_alignment/` — full investigation, real samples,
  real captured `output.txt` from a live run inside
  `docker-celery-worker-plaso-1`.
- `tests/fixtures/samples/real/windows_security.evtx`,
  `linux_auth.log`, `custom_container.log` (+ `NOTICE.md` provenance
  update) — real, committed, reusable fixtures.
- `tests/unit/parsers/test_cross_source_log_alignment.py` — 7 real tests:
  6 run unconditionally on any host (real-live-registry detection for all
  5 samples, the stream-normalizer-registry check, and the nginx/apache
  positive control); 1 (`TestSigninEventClassificationGap`, the headline
  finding) is gated with `@pytest.mark.skipif` on real `plaso` being
  importable — it does not run on a host without Plaso, and does not skip
  the other 6 (a class-level skip, not the sibling test file's own
  module-level `pytest.importorskip` convention, which would have
  incorrectly skipped everything in this file).

**Deliberately not fixed this cycle** — the project owner's ask was to
build the test and answer the question, not to fix the underlying
normalization gap. `FirecrackerLauncher`/Plaso ECS-mapping and a
plain-text-syslog/generic-custom-source parser are real, separate,
larger pieces of work; flagged here for a future cycle, not attempted
unprompted.

## Real, live verification (commands + actual captured output)

- Subagent 1 (scope): read real code, cited real file:line references;
  its two most load-bearing claims (FastEvtxParser deregistration,
  Firecracker's non-setting of ECS fields) were independently re-confirmed
  by directly reading the same files before being trusted.
- Subagent 2 (samples): real `git clone --depth 1` of `omerbenamram/evtx`,
  real parse-based verification (not filename trust) of 6 real candidate
  EVTX files before selecting the smallest one containing a genuine
  4624/4625 record; real `docker pull`/`docker run`/`docker logs`/
  `docker stop`/`docker rm` of a distinctly-named `kronos-poc-*` container,
  confirmed no trace left and no pre-existing container touched.
- Real PoC run (`poc/cross_source_log_alignment/run_poc.py`) inside
  `docker-celery-worker-plaso-1` (has real Plaso installed): captured real
  JSON output for all 5 samples, saved as `output.txt`.
- Real pytest run of the new test file on the host venv (no plaso): `6
  passed, 1 skipped` — the gated class correctly skips, nothing else does.
- Real pytest run of the same file inside `docker-celery-worker-plaso-1`
  (pytest/pytest-asyncio installed ephemerally for the run, real `plaso`
  already present): **`7 passed`** — including the real, decisive
  `TestSigninEventClassificationGap` assertion against a real Plaso
  subprocess run.
- Full backend suite re-run after adding the new test file: `2000 passed,
  2 skipped`, 89.14% coverage, `ruff` clean — no regressions (additive
  only).

## Status

PASS. The real question is answered with real, captured, now-permanently-
regression-checked evidence, exactly per the requested process (subagent
scope → subagent sample collection → real test).

## Recommendation for the next cycle

If closing this gap is desired: (1) teach `FirecrackerLauncher`/`PlasoParser`
to map at least the common Plaso `source_name`/`event_identifier` shapes
(Windows EVTX auth-related event IDs, at minimum) onto real ECS
`event.category`/`event.type`/`event.outcome` values, mirroring how
`suricata.py`'s `_ECS_BY_EVENT_TYPE` table already does this for Suricata;
(2) add a real plain-text syslog/auth-log parser (Plaso itself has a real
syslog parser plugin — confirm the pinned `plaso==20260512` exposes it
before assuming); (3) decide whether "arbitrary custom container logs"
should get a real generic best-effort normalizer on the streaming path, or
whether that's explicitly out of scope (mirrors this repo's own "Track
D"/third-party-code gating precedent for open-ended untrusted input).
