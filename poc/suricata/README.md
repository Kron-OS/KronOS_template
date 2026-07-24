# PoC: SuricataEveParser against a real Suricata EVE JSON sample

## Component pair

`src/external/parsers/suricata.py`'s `SuricataEveParser` (new, in-process,
stdlib `json` only) against a real `eve.json` sample — Suricata's own
real-time NDJSON output format.

## Versions (pinned, read from real upstream sources)

- Suricata: **8.0.6** (`suricata-8.0.6` git tag on
  [OISF/suricata](https://github.com/OISF/suricata)) — this repo has no
  prior Suricata pin (new module), so the latest released version was
  chosen per `CLAUDE.md` §F.2 step 1 ("never assume latest without
  checking" — verified via the GitHub tags API, `suricata-8.0.6` was the
  newest tag at the time this PoC was built).
- Schema reference used: Suricata's own official user guide,
  [`doc/userguide/output/eve/eve-json-format.rst`](https://github.com/OISF/suricata/blob/suricata-8.0.6/doc/userguide/output/eve/eve-json-format.rst)
  at that exact tag.
- No external service/container is involved — `SuricataEveParser` is a pure
  in-process parser (same trust tier as `CloudTrailParser`/`NginxParser`,
  per `CLAUDE.md` §G.3's "first-party module, pure Python/stdlib" bucket),
  so this PoC is a standalone Python script exercising `ParserRegistry` +
  the real parser directly against a real file on disk — no Docker.

## Real sample used

`tests/fixtures/samples/real/suricata/eve.json` — 6 real, captured Suricata
event lines from two independent real sources (full provenance in
`tests/fixtures/samples/real/suricata/NOTICE.md`):

- Line 1 (`fileinfo`): OISF's own `suricata-verify` golden test fixture
  (`tests/output-eve-fileinfo/expected/eve.json`, commit `93322a6`) — a
  real Suricata run against a real pcap (EICAR-over-HTTP download).
- Lines 2–6 (`alert`, `fileinfo`, `http`, `anomaly`, `flow`): copied from
  Suricata's own userguide, which states outright: *"Examples come from
  pcap found at
  https://app.any.run/tasks/ce7ca983-9e4b-4251-a7c3-fefa3da02ebe/."* — all
  five share `flow_id: 1676750115612680`, i.e. one real, correlated
  capture, not five independently invented snippets.

`dns`/`tls` real full-record examples were searched for and **not found** —
see the NOTICE.md's "What was checked and NOT included" section for exactly
what was checked (OISF's `suricata-verify` ships no committed multi-type
`eve.json` corpus at all; the userguide's DNS/TLS sections show only inner
sub-object schema snippets, never a full enveloped real-capture record).
Fabricating an envelope around those snippets was rejected as exactly the
kind of "plausible but unverified" output `CLAUDE.md` §F prohibits.

## What this actually does

`run_poc.py`:

1. Builds a real `ParserRegistry` with `CloudTrailParser`, `NginxParser`,
   and `SuricataEveParser` (the three FAST JSON/text parsers), and runs
   real detection (`ParserRegistry.get_parser()`, first-match-wins) against
   the real `eve.json` fixture's real header bytes — proving the fixture
   routes to `SuricataEveParser`, not `CloudTrailParser` or `NginxParser`.
2. Cross-checks the *other two* real fixtures
   (`tests/fixtures/samples/real/aws_cloudtrail.jsonl`,
   `tests/fixtures/samples/real/apache_access.log`) still route to
   `CloudTrailParser`/`NginxParser` respectively with `SuricataEveParser`
   also registered — proving no cross-routing regression.
3. Runs the real `SuricataEveParser().parse()` against the real fixture
   bytes and prints every resulting `TimelineRecord`'s real field values
   (`@timestamp`, `message`, ECS `event.*`, the full `extra` dict, and the
   `kronos.*` provenance block) as JSON.

Run:

```bash
python3 poc/suricata/run_poc.py
```

(repo venv: `.venv/bin/python poc/suricata/run_poc.py` — no other setup
needed, stdlib `json` only, no external service).

## Real findings

- **Detection is correct and non-colliding.** All three real fixtures
  (Suricata/CloudTrail/nginx) route to the correct parser with all three
  parsers registered together — confirmed by the captured output, not
  assumed from reading `supports()` source.
- **`flow_id` is a reliable, Suricata-specific detection signal.** It
  appears on every real EVE JSON line tried here (`alert`, `fileinfo`,
  `http`, `anomaly`, `flow`), never collides with CloudTrail's
  `"Records"`/`"CloudTrailEvent"` markers, and needs no `community_id`
  (which is opt-in and absent from all 6 real sample lines — confirming the
  task's suggested `community_id` signal would NOT have worked as the sole
  detection field against this real data, `flow_id` was used instead).
- **The `"flow"` sub-object appears on two different event types with
  different meanings** — the standalone `flow` event's own summary
  (`flow.bytes_toserver: 3536402` for the whole session) vs. the `alert`
  event's *embedded* `flow` snapshot (`flow.bytes_toserver: 1616`, just up
  to the alerting packet). `_build_extra()` maps both through the same
  `flow.*` keys since they're the same real field names Suricata uses in
  both places; a caller correlating by `event.type` (`["connection",
  "end"]` for the flow-summary record) rather than field presence alone
  gets the right one — this was actually hit and fixed while writing
  `tests/unit/parsers/test_suricata.py` (see that file's
  `test_real_flow_record_maps_byte_and_packet_counters`).
- **`datetime.fromisoformat` parses EVE's real timestamp format natively**
  on Python 3.11+ (`"2023-09-18T06:13:41.532140+0000"`, no colon in the UTC
  offset) — confirmed against all 6 real timestamps in the fixture, no
  custom string munging needed (unlike `CloudTrailParser`, which has to
  `.replace("Z", "+00:00")` for its own source format).

See `output.txt` for the full real captured run (all 6 records, plus the
cross-routing checks).
