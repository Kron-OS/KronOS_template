# PoC: Splunk HEC indexer-acknowledgement (`ackId`) polling

**Gap audit item:** `docs/GAP_AUDIT_2026-08.md` P1-3, Milestone V, item V6
("Sink acknowledgement depth").

**Objective:** implement and prove, for real, HEC's own optional indexer-
acknowledgement feature -- a token with `useACK=1`, an
`X-Splunk-Request-Channel` GUID header on every push, a real `ackId`
returned in the push response, and a separate, real
`POST /services/collector/ack` poll that resolves that `ackId` to `true`
only once the indexer has genuinely confirmed the write -- and prove it
end-to-end against a real Splunk instance, not assumed from the docs.

## Real container used

Reused `splunk/splunk:9.3.3` (same pinned tag/digest R2's own
`poc/integration_sink_splunk_hec/` already verified:
`sha256:5df3a46bd1c859dd317dafa5e14de7a1269ee11a57e8de0b1109431a971fe099`,
already cached locally). A **fresh** container was stood up for this item
(`kronos-poc-splunk-hec-ack`, distinct name/ports from R2's own
`kronos-poc-splunk-hec`, both per CLAUDE.md's `kronos-poc-*` naming
convention) since this item needed its own ack-enabled token, not R2's
plain one:

```bash
docker run -d --name kronos-poc-splunk-hec-ack \
  -p 18188:8088 -p 18189:8089 \
  -e SPLUNK_START_ARGS=--accept-license \
  -e SPLUNK_PASSWORD='KronosPoc-2026!' \
  -e SPLUNK_HEC_TOKEN='9b1c2b6e-3f2a-4d3b-9c1a-2f6e7a8b9c0d' \
  -e SPLUNK_HEC_SSL=false \
  splunk/splunk:9.3.3
```

## Research: can `useACK` be enabled via env var? No -- confirmed by direct source read

Re-fetched `splunk-ansible`'s own current `inventory/environ.py`
`getHEC()` source this pass (the same function R2's own PoC already used
to confirm `SPLUNK_HEC_TOKEN`/`SPLUNK_HEC_PORT`/`SPLUNK_HEC_SSL` are the
only three HEC env vars it reads):

```python
def getHEC(vars_scope):
    vars_scope["splunk"]["hec"]["token"] = os.environ.get("SPLUNK_HEC_TOKEN", ...)
    vars_scope["splunk"]["hec"]["port"] = int(os.environ.get("SPLUNK_HEC_PORT", ...))
    ssl = os.environ.get("SPLUNK_HEC_SSL", "")
    if ssl.lower() == "false":
        vars_scope["splunk"]["hec"]["ssl"] = False
    else:
        vars_scope["splunk"]["hec"]["ssl"] = bool(vars_scope["splunk"]["hec"].get("ssl"))
```

No `useAck`/`ack`/`idxAck` reference anywhere in that file (confirmed via
full-file search). `useACK` genuinely requires either Splunk Web (the
"Enable indexer acknowledgment" checkbox at token-creation time) or a real
REST API call -- there is no shortcut env var. This is a real,
investigated-not-assumed answer to the brief's own explicit question.

## Real REST call used to create the ack-enabled token

Splunk's own documented (`help.splunk.com`, "Use cURL to manage HTTP Event
Collector tokens, events, and services", Splunk Enterprise 9.3 doc set,
fetched this pass) token-management endpoint,
`/servicesNS/admin/splunk_httpinput/data/inputs/http`, against the
container's own management port (exposed on host port 18189):

```bash
curl -s -k -u admin:'KronosPoc-2026!' \
  https://127.0.0.1:18189/servicesNS/admin/splunk_httpinput/data/inputs/http \
  -d name=kronos_ack_token \
  -d token=1a2b3c4d-5e6f-7890-abcd-ef1234567890 \
  -d useACK=1 -d disabled=0 -d output_mode=json
```

Real captured response confirms `"useACK":"1"` in the created token's own
`content` block (see full JSON in this pass's shell history; the token was
then used, unmodified, for every scenario below).

## Real wire contract verified by hand with `curl` before writing any code

All of the following were observed directly against the real running
container, in this exact order, **before** `src/adapter/integration_sink/splunk_hec_sink.py`
was changed:

1. **Push with the channel header, real success:**
   ```
   $ curl -s http://127.0.0.1:18188/services/collector/event \
       -H "Authorization: Splunk 1a2b3c4d-5e6f-7890-abcd-ef1234567890" \
       -H "X-Splunk-Request-Channel: f52dc7df-06c7-47d0-99cd-9c97344477f5" \
       -d '{"event": {"message": "kronos poc ack test 1"}}'
   {"text":"Success","code":0,"ackId":0}
   ```
   Confirms the real key is **`ackId`** (lowercase "Id"), alongside the
   existing `code`/`text` pair -- not a separate/replaced response shape.
   A second push on the same channel returned `ackId:1` -- ack IDs
   increment per channel.

2. **Push WITHOUT the channel header against a `useACK=1` token -- real,
   distinct, previously undocumented-in-`splunk_hec_sink.py` error:**
   ```
   $ curl -s -w "\nHTTP_STATUS:%{http_code}\n" http://127.0.0.1:18188/services/collector/event \
       -H "Authorization: Splunk 1a2b3c4d-5e6f-7890-abcd-ef1234567890" \
       -d '{"event": {"message": "kronos poc ack test no channel"}}'
   {"text":"Data channel is missing","code":10}
   HTTP_STATUS:400
   ```

3. **Ack poll, real shape:**
   ```
   $ curl -s http://127.0.0.1:18188/services/collector/ack \
       -H "Authorization: Splunk 1a2b3c4d-5e6f-7890-abcd-ef1234567890" \
       -H "X-Splunk-Request-Channel: f52dc7df-06c7-47d0-99cd-9c97344477f5" \
       -d '{"acks": [0, 1]}'
   {"acks":{"0":true,"1":true}}
   ```
   Confirms the request key is `"acks"` (array of int ack IDs), the
   response key is also `"acks"` (an object keyed by the **string** form
   of each ack ID, boolean values) -- exactly the shape
   `SplunkHecSink.check_ack_status()` parses.

4. **Channel can be supplied as either a header OR a `?channel=` query
   param on the ack endpoint** (both real-tested, both accepted) --
   `splunk_hec_sink.py` uses the header form for consistency with the push
   request.

5. **Real, previously-undocumented-in-any-fetched-doc "read-once"
   behavior:** re-querying an ack ID that already resolved `true` returns
   `false` again:
   ```
   $ curl -s "http://127.0.0.1:18188/services/collector/ack?channel=f52dc7df-..." \
       -H "Authorization: Splunk 1a2b3c4d-5e6f-7890-abcd-ef1234567890" \
       -d '{"acks": [0]}'
   {"acks":{"0":false}}
   ```
   This matches Splunk's own documented language (`help.splunk.com`,
   "About HTTP Event Collector Indexer Acknowledgment"): "Once a client
   retrieves a true status for an ackID, HEC deletes that ackID status
   information. If you query the same ackID again, HEC will always return
   false." `check_ack_status()`/the poll loop treat a `true` result as
   final and never re-query the same ID afterward -- Scenario 2 of
   `run_poc.py` deliberately re-queries anyway, to prove this exact real
   behavior rather than just take the doc's word for it.

6. **Real, additional documented error for an unknown/malformed channel on
   the ack endpoint** (not previously in `splunk_hec_sink.py`'s own
   docstring, found by hand-testing before writing `check_ack_status()`):
   ```
   $ curl -s -w "\nHTTP:%{http_code}\n" http://127.0.0.1:18188/services/collector/ack \
       -H "Authorization: Splunk 1a2b3c4d-5e6f-7890-abcd-ef1234567890" \
       -H "X-Splunk-Request-Channel: not-a-guid-at-all" -d '{"acks": [0]}'
   {"text":"Invalid data channel","code":11}
   HTTP:400
   ```

## Docs fetched and read this pass (not from memory)

- `help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.3/get-data-with-http-event-collector/about-http-event-collector-indexer-acknowledgment`
  (`docs.splunk.com`'s own equivalent page returned HTTP 403 to automated
  fetches this pass -- `help.splunk.com` is Splunk's own current
  documentation host and was used instead, same publisher, same content).
  Confirms `useACK=true` in `inputs.conf`, the mandatory channel header,
  the `ackId`/`acks` shapes, and the "true is deleted after being read
  once" semantics -- all independently re-confirmed against the real
  container above, not just quoted.
- `help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.3/get-data-with-http-event-collector/use-curl-to-manage-http-event-collector-tokens-events-and-services`
  -- the real `/servicesNS/admin/splunk_httpinput/data/inputs/http`
  token-management endpoint and `useACK=1` parameter used to create the
  real token above.
- `raw.githubusercontent.com/splunk/splunk-ansible/9.3.3/inventory/environ.py`
  -- re-fetched to confirm no `SPLUNK_HEC_*` env var covers `useACK`
  (see "Research" section above).

## Design decision (this item's own required "decide and justify")

**Synchronous polling inside `push_events()` with a real, bounded,
per-sink-configured timeout (`ack_poll_timeout`, default 30s;
`ack_poll_interval`, default 1s), resolving to a genuine THIRD
`SinkAckStatus` (`ACK_PENDING`) if the timeout is reached before
confirmation -- never raising, never fabricating `ACKNOWLEDGED`.**

Full reasoning is in `splunk_hec_sink.py`'s own module docstring (the
authoritative version); short form: a bare "accepted" status with zero
polling attempt would waste the whole point of a caller opting into this
feature, and an unbounded/no-timeout wait would violate
`IntegrationSink.push_events()`'s own "one bounded call" ABC contract.
`ACK_PENDING` is the honest middle state this codebase's whole
`SinkAck`/`SinkAckStatus` abstraction already exists to make impossible to
skip past -- see `src/domain/integration_sink.py`'s own updated docstring.
A separate `check_ack_status()` method is provided as the explicit
"resolve it later, out-of-band" mechanism for a caller that would rather
not block on the synchronous default (Scenario 4 below exercises exactly
this path). `DetectionSinkPushService`/`SinkPushResult.all_acknowledged`
required **zero code changes** -- both already treat any non-`ACKNOWLEDGED`
status as "not fully confirmed," so `ACK_PENDING` is handled correctly by
construction, not by a special case added for it.

## Scenarios covered (see `output.txt` for the full, unedited real run)

All scenarios use the real, unmodified production `SplunkHecSink` (with
`enable_indexer_ack=True`), `SplunkDetectionMapper`, `StaticTokenAuthenticator`,
and `DetectionSinkPushService` classes -- no PoC-local reimplementation of
any of them.

1. **Real push with the default 30s timeout -- real ACKNOWLEDGED, with the
   real FALSE-then-TRUE transition proven via `ack_poll_attempts >= 2` and
   `ack_poll_elapsed_seconds >= 1.0`** (the real observed value was
   `ack_poll_attempts=2`, `ack_poll_elapsed_seconds≈1.02s`  -- one real
   immediate `FALSE` at `t≈0.004s` after the push, one real `TRUE` at
   `t≈1.02s`, matching the standalone timing probe run before writing
   `run_poc.py` -- see "Real timing probe" below).
2. **Real re-query of an already-resolved `ackId` returns `False`** --
   proves the "read-once" behavior is real, not assumed from the doc.
3. **Real near-zero `ack_poll_timeout=0.001` -- real `ACK_PENDING`**, one
   real poll attempt observing `False`, no exception, `indexer_confirmed=False`
   honestly reported.
4. **Real out-of-band `check_ack_status()` resolves the pending `ack_id`
   to `True`** after a real 2-second wait -- proves the separate
   resolve-later mechanism works independently of `push_events()`.
5. **Real negative: push without a channel against a `useACK=1` token** --
   real `400`/`{"code":10,"text":"Data channel is missing"}`, surfaced as
   `IntegrationSinkError`.
6. **Real negative: `check_ack_status()` with an invalid channel** -- real
   `400`/`{"code":11,"text":"Invalid data channel"}`.
7. **`DetectionSinkPushService` full orchestration with indexer ack
   enabled** -- real `SINK_PUSH_EXECUTED` audit row's own `ack_status`
   read back fresh from Postgres as `"acknowledged"` (indexer-confirmed,
   not merely accepted), real hash chain verified intact.

**17/17 checks passed, first real run, no bug found** (unlike R2's own
first real run, which found three real bugs -- this pass's design leaned
directly on R2's already-hardened `push_events()` scaffolding, e.g. the
`isinstance(error_body, dict)` guard R2 already added, so the same class
of defect couldn't recur here).

## Real timing probe (run before `run_poc.py` existed, to size the default poll interval)

A standalone script (not checked in -- pure exploratory, superseded by
`run_poc.py`'s own Scenario 1) pushed one event and polled
`/services/collector/ack` in a tight loop with no sleep, then again with a
real 1-second sleep between polls:

```
t=0.0030s push -> {'text': 'Success', 'code': 0, 'ackId': 0}
t=0.0039s poll#0 -> {'acks': {'0': False}}
... (15 rapid polls, all False, total <15ms) ...
```

```
t=0.0027s push -> {'text': 'Success', 'code': 0, 'ackId': 0}
t=0.0036s poll#0 -> {'acks': {'0': False}}
t=1.0046s poll#1 -> {'acks': {'0': True}}
CONFIRMED TRUE
```

This real, observed ~1-second real indexing latency on this single-node
dev container justified the 1.0s default `ack_poll_interval` (short enough
not to waste the 30s default timeout budget on unnecessary waiting, long
enough not to hammer `/services/collector/ack` with sub-millisecond
polling that this dev instance's own real behavior shows is pointless).

## What's real vs. what's a deliberate stand-in

| Component | Real | Stand-in |
|---|---|---|
| Splunk Enterprise 9.3.3, real `useACK=1` token, real indexer ack/poll | Yes -- genuine `splunk/splunk:9.3.3`, real REST-created token, real HEC ingest + ack polling | — |
| Postgres 16 (`docker-postgres-1`) | Yes -- real INSERT/SELECT over a real asyncpg connection | — |
| `SplunkHecSink` / `SplunkDetectionMapper` / `StaticTokenAuthenticator` / `DetectionSinkPushService` | Yes -- the real, unmodified production classes | — |
| HTTP transport | Yes -- real TCP socket, real HTTP/1.1 | — |

Nothing in this PoC is a stand-in -- unlike R2's own PoC (which kept a
local protocol-accurate receiver alongside real Splunk for wire-byte-level
assertions a black-box instance can't expose), this item's every scenario
runs directly against the real container, since the whole point is real
indexer timing that only real Splunk can produce.

## Pinned versions

- `splunk/splunk:9.3.3` -- same pin as R2's own PoC (see
  `poc/integration_sink_splunk_hec/README.md`), same digest, no version
  drift introduced.
- `httpx>=0.27` (`pyproject.toml`) -- the real HTTP client `SplunkHecSink`
  uses; `0.28.1` installed.
- `postgres:16-alpine` (`docker/docker-compose.dev.yml`) -- the same live
  `docker-postgres-1` container prior PoCs in this initiative used.

## How to run

```bash
# 1. Ensure the real dev-stack Postgres is up:
docker ps --filter name=docker-postgres-1

# 2. Stand up the real Splunk container (see "Real container used" above)
#    and wait for it to report healthy:
docker inspect -f '{{.State.Health.Status}}' kronos-poc-splunk-hec-ack

# 3. Create the real ack-enabled HEC token (see "Real REST call" above) --
#    only needed once per container lifetime.

# 4. Run the PoC:
~/venv/bin/python3 poc/splunk_hec_ack_polling/run_poc.py
```

`kronos-poc-splunk-hec-ack` is a throwaway PoC container -- torn down with
`docker rm -f kronos-poc-splunk-hec-ack` at the end of this item's own
verification pass (not left running, unlike R2's own `kronos-poc-splunk-hec`,
since this item's own token/container state isn't needed by any other
in-progress PoC).
