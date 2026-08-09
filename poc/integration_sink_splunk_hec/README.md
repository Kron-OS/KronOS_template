# PoC: Splunk HEC sink connector (roadmap R2, `docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md`)

**Objective (roadmap R2, verbatim):** "Real HEC token + JSON envelope push
of a real `Detection`, against a real local Splunk instance if a real
free/dev-license image exists (research this — Splunk does ship a free
single-instance license tier), or a real local stand-in HEC-shaped receiver
per §1 invariant 9 otherwise, with the real envelope/batching/size-limit
behavior honestly verified either way."

## Judgment call: real Splunk WAS used this pass (research resolved)

The roadmap explicitly asked this item to research whether a real,
self-hostable Splunk image exists before falling back to a stand-in. It
does: **`splunk/splunk`** is Splunk Inc.'s own maintained Docker image
(`docker-splunk`, provisioned via the `splunk-ansible` project), ships a
60-day Enterprise trial that runs as a genuine single self-hosted instance
with no external account/license-server call required at container
startup, and needs no live third-party SaaS API — it satisfies roadmap §1
invariant 9 (real self-hostable instance, never a live vendor account)
directly. **A real `splunk/splunk:9.3.3` container was stood up and used
for real, both to research the exact HEC-enablement contract and to run
Scenario 0 of `run_poc.py` below.**

The pre-existing protocol-accurate local stand-in receiver (Scenarios 1-5,
inherited from an earlier pass in this same worktree) was **not** discarded
— it is kept because it does something a real black-box Splunk instance
structurally cannot: it inspects the *exact wire bytes* KronOS sent
(confirming the real concatenated-JSON batch format, not a `{"events":
[...]}` array, byte-for-byte) and drives deliberately-adversarial cases
(wrong auth scheme, oversized events) that would otherwise require mutating
a real Splunk instance's own token configuration mid-run. Real Splunk
(Scenario 0) and the protocol-accurate stand-in (Scenarios 1-5) are
complementary, not redundant — one proves "real vendor software accepts
this," the other proves "the exact bytes on the wire are what HEC's docs
say they must be."

## What was actually researched and verified this pass (not from memory)

1. **`splunk/splunk:9.3.3`** pulled for real (`docker pull
   splunk/splunk:9.3.3`, digest
   `sha256:5df3a46bd1c859dd317dafa5e14de7a1269ee11a57e8de0b1109431a971fe099`).
2. Fetched the real, current `docker-splunk` README
   (`github.com/splunk/docker-splunk/blob/9.3.3/README.md`) — confirms
   `SPLUNK_START_ARGS=--accept-license` + `SPLUNK_PASSWORD` as the two
   required env vars; does not itself document HEC env vars.
3. Fetched the real, current `splunk-ansible` `inventory/environ.py`
   (`raw.githubusercontent.com/splunk/splunk-ansible/develop/inventory/environ.py`,
   `getHEC()` function, lines 635-647) — the actual, current source of
   truth for HEC env-var wiring:
   ```python
   vars_scope["splunk"]["hec"]["token"] = os.environ.get("SPLUNK_HEC_TOKEN", ...)
   vars_scope["splunk"]["hec"]["port"] = int(os.environ.get("SPLUNK_HEC_PORT", ...))
   ssl = os.environ.get("SPLUNK_HEC_SSL", "")
   if ssl.lower() == "false":
       vars_scope["splunk"]["hec"]["ssl"] = False
   ```
4. Fetched the real, current `splunk-ansible`
   `inventory/splunk_defaults_linux.yml` — confirms HEC is **enabled by
   default** (`hec.enable: True`), on port **8088**, with **`ssl: True`**
   by default (hence `SPLUNK_HEC_SSL=false` was needed to get a plain-HTTP
   PoC without also managing a self-signed cert `verify=` override).
5. `docs.splunk.com/Documentation/Splunk/9.3.3/Data/TroubleshootHTTPEventCollector`'s
   own status-code table (fetched and read directly in the prior pass that
   built `splunk_hec_sink.py` itself, re-confirmed this pass by hand
   against the real running container with `curl` — see below) — every
   code/text pair asserted on in this PoC and in `splunk_hec_sink.py`
   (`0`/"Success", `2`/"Token is required", `3`/"Invalid authorization",
   `4`/"Invalid token") is the exact real response, not a guess.
6. Hand-verified with `curl` against the real running container, before
   writing any PoC-script assertion:
   ```
   $ curl -s http://127.0.0.1:18088/services/collector/event \
       -H "Authorization: Splunk 9b1c2b6e-3f2a-4d3b-9c1a-2f6e7a8b9c0d" \
       -d '{"event": {"message": "kronos poc real hec test"}}'
   {"text":"Success","code":0}
   $ curl -s http://127.0.0.1:18088/services/collector/event -H "Authorization: Splunk wrong-token" -d '{"event":"x"}'
   {"text":"Invalid token","code":4}
   $ curl -s http://127.0.0.1:18088/services/collector/event -d '{"event":"x"}'
   {"text":"Token is required","code":2}
   ```
7. Hand-verified the real `/services/search/jobs` REST contract (used by
   `run_poc.py` to independently confirm a pushed event was actually
   *indexed*, not just accepted) before wiring it into the script:
   ```
   $ curl -s -k -u admin:'KronosPoc-2026!' https://127.0.0.1:18089/services/search/jobs \
       -d output_mode=json -d exec_mode=oneshot \
       -d 'search=search index=main sourcetype=kronos:manualtest | head 5'
   {"...","results":[{"_raw":"{\"finding_id\": \"poc-manual-search-check-xyz\"}", ...}]}
   ```

## The real container used

```bash
docker run -d --name kronos-poc-splunk-hec \
  -p 18088:8088 -p 18089:8089 \
  -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_PASSWORD='KronosPoc-2026!' \
  -e SPLUNK_HEC_TOKEN='9b1c2b6e-3f2a-4d3b-9c1a-2f6e7a8b9c0d' \
  -e SPLUNK_HEC_SSL=false \
  splunk/splunk:9.3.3
```

Takes ~1-3 minutes to reach `docker inspect -f '{{.State.Health.Status}}'
kronos-poc-splunk-hec` == `healthy` (real `splunk-ansible` provisioning +
`splunkd` startup, not simulated). `run_poc.py` does **not** create or tear
this container down itself — it is meant to be left running and reused
across repeated PoC runs during development, the same way `docker-postgres-1`
already is for this whole initiative. Scenario 0 checks reachability first
and **skips itself with a loud, explicit warning** (never silently "passes")
if the container isn't up. Tear down with `docker rm -f
kronos-poc-splunk-hec` when genuinely done with this PoC line of work — it
is a throwaway PoC container, named `kronos-poc-*` per CLAUDE.md's own
container-naming convention.

## What's real vs. what's a deliberate stand-in

| Component | Real | Stand-in |
|---|---|---|
| Splunk Enterprise 9.3.3 (Scenario 0) | Yes — genuine `splunk/splunk:9.3.3`, real HEC ingest, real indexing, real search API | — |
| Postgres 16 (`docker-postgres-1`) | Yes — real INSERT/SELECT over a real asyncpg connection | — |
| `SplunkHecSink` / `SplunkDetectionMapper` / `StaticTokenAuthenticator(scheme="Splunk")` / `chunk_events` / `DetectionSinkPushService` | Yes — the real, unmodified production classes (both against real Splunk in Scenario 0 and the stand-in in Scenarios 1-5) | — |
| HTTP transport (Scenario 0) | Yes — real TCP socket, real HTTP/1.1, real Splunk-side JSON parsing/indexing | — |
| HTTP transport (Scenarios 1-5) | Yes — real TCP socket, real HTTP/1.1, real JSON | — |
| The receiver in Scenarios 1-5 | — | A local `http.server`-based Splunk-HEC-protocol-accurate stand-in this script starts/stops, used for wire-format-level assertions real black-box Splunk can't expose |

## Pinned versions

- `splunk/splunk:9.3.3` — pinned to match the version cited throughout
  `splunk_hec_sink.py`'s own module docstring (the Splunk docs URL it was
  verified against is versioned `9.3.3`).
- `httpx==0.28.1` installed (`pyproject.toml` pins `httpx>=0.27`) — the real
  HTTP client `SplunkHecSink` uses.
- `postgres:16-alpine` (`docker/docker-compose.dev.yml`) — the same live
  `docker-postgres-1` container prior PoCs in this initiative used.
- Python stdlib `http.server`/`threading` for the Scenarios 1-5 stand-in
  receiver (no version pinning needed).

## Scenarios covered (see `output.txt` for the actual captured run)

0. **Real Splunk Enterprise 9.3.3** — a real `Detection` → `SplunkDetectionMapper`
   → `SplunkHecSink.push_events()` → real HTTP POST → real Splunk container
   → real `{"code":0,"text":"Success"}` → `SinkAck.ACKNOWLEDGED`,
   independently re-confirmed by querying Splunk's own real
   `/services/search/jobs` REST endpoint and finding the pushed event
   actually indexed (`_raw` field parsed back and its `finding_id` matched
   against what was pushed) — proves genuine end-to-end acceptance, not
   just a 2xx response. Plus real wrong-token (403/`code:4`) and real
   missing-Authorization (401/`code:2`) failure cases against the same real
   container.
1. **Real end-to-end push (stand-in)** — same production classes against
   the local protocol-accurate stand-in; the receiver's own independent
   parse of the concatenated-JSON body and the full HEC envelope shape
   (`time`/`host`/`source`/`sourcetype`/`index`/nested `event`) is asserted.
2. **Real deliberate auth-failure case** — wrong token → real documented
   403 + `{"code":4}`.
3. **Real missing-Authorization-header and wrong-scheme cases** — three
   distinct real HEC error codes (missing header = `code:2`, wrong scheme
   = `code:3`), not one generic 401.
4. **Real size-limit-adjacent batching** — 5 real `Detection`s through a
   deliberately small `max_batch_bytes=2000` ceiling. The real, measured
   per-event size for this exact `Detection`/mapper shape is **902 bytes**
   (measured directly this pass — an earlier version of this PoC guessed
   "~450-550 bytes" without ever measuring it, was off by ~2x, and
   asserted a since-corrected, always-vacuously-true "≤900 bytes" ceiling
   that a single 902-byte event alone can never satisfy; `chunk_events()`'s
   own documented behavior — a single oversized event is still yielded
   alone rather than rejected — was real and correct, the *PoC's own
   pre-existing assertion* was the actual bug). Fixed to a real 2000-byte
   ceiling that forces an actual real 2+2+1 three-call split, independently
   confirmed against the real receiver's own observed request-body sizes.
5. **`DetectionSinkPushService` full orchestration + real audit trail** —
   mirrors R1's own Scenario 7, through the real `SplunkDetectionMapper`/
   `SplunkHecSink` pair, with a real `SINK_PUSH_ATTEMPTED`/`EXECUTED`/
   `FAILED` audit trail written to the real, live Postgres and
   independently re-verified (fresh connection,
   `AuditLogService.verify_chain()`) afterward. The audit-row-count
   assertion here was also a real, previously-unverified bug (see
   "Bugs this PoC run actually found" below) — fixed to the real observed
   count.

**33/33 checks passed** (see `output.txt` for the full, unedited captured
run — every line is real stdout from the run above, not paraphrased).

## Bugs this PoC run actually found (the whole point of Section F)

Running this PoC for the first time — as opposed to reading the
already-written code and judging it "looks right" — surfaced three real,
previously-unverified defects, none hypothetical:

1. **`splunk_hec_sink.py`'s own non-2xx error-context builder crashed** on
   a non-2xx response whose body is valid JSON `null` (or any non-dict
   JSON value) — `error_body.get("code")` raised `AttributeError` because
   the code only guarded against `response.json()` *raising*
   (`ValueError`/`TypeError`), not against it *succeeding* with a non-dict
   value. Fixed with an `isinstance(error_body, dict)` guard
   (`src/adapter/integration_sink/splunk_hec_sink.py`).
2. **Scenario 4's byte-ceiling assumption was never measured** — asserted
   "~450-550 bytes per event" and a "≤900 bytes" per-request ceiling that a
   single real 902-byte event can never satisfy on its own, making the
   assertion pass only by chunk_events()'s own documented "never split a
   single event" fallback, not by genuinely exercising multi-event
   batching. Fixed to a measured 902-byte baseline and a 2000-byte ceiling
   that forces a real 2-event-per-batch split.
3. **Scenario 5's audit-row-count assertion had an off-by-one** (`1 +
   batch_count + 1 + 1`) that implicitly, incorrectly assumed Scenario 1's
   direct `sink.push_events()` call (which never goes through
   `DetectionSinkPushService`/`audit_log` at all) contributed an audit row.
   Fixed to `batch_count + 1 + 1` (Scenario 4's batches + Scenario 5's own
   two `DetectionSinkPushService.push()` calls), matching the real observed
   count of 5.

All three were caught only because this PoC was actually executed and its
output actually read, not because the code "looked plausible."

## How to run

```bash
# 1. Ensure the real dev-stack Postgres is up (already running for this initiative):
docker ps --filter name=docker-postgres-1

# 2. Stand up the real Splunk container (see "The real container used" above)
#    if not already running; wait for it to report healthy:
docker inspect -f '{{.State.Health.Status}}' kronos-poc-splunk-hec

# 3. Run the PoC:
~/venv/bin/python3 poc/integration_sink_splunk_hec/run_poc.py
```

Nothing this script itself starts (the Scenarios 1-5 stand-in HTTP server)
is left listening afterward — independently confirmed via `server.shutdown()`
+ `thread.join()` before the script exits. `kronos-poc-splunk-hec` is left
running by design (see above); tear it down manually with `docker rm -f
kronos-poc-splunk-hec` when done with this line of work.
