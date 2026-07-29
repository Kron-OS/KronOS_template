# Provenance

`eve.json` in this directory is a hand-assembled **NDJSON file built entirely
from real, captured Suricata output** — no line was invented to "look
plausible." It combines two independent real sources:

1. **Line 1** (`fileinfo`) is copied byte-for-byte from
   [OISF/suricata-verify](https://github.com/OISF/suricata-verify) — Suricata's
   own upstream test/QA repository — commit `93322a61d0174bdd5ace6671edfee97248f7ac0f`,
   path `tests/output-eve-fileinfo/expected/eve.json`. This is a *golden
   test fixture*: OISF's CI runs real Suricata against `input.pcap` in that
   same test directory and asserts the resulting `eve.json` matches this
   file (`test.yaml` checks `fileinfo.filename: eicar.com`, count 1). It is
   real captured tool output, not hand-written.
2. **Lines 2–6** (`alert`, `fileinfo`, `http`, `anomaly`, `flow`) are copied
   from Suricata's own official user guide,
   [`doc/userguide/output/eve/eve-json-format.rst`](https://github.com/OISF/suricata/blob/suricata-8.0.6/doc/userguide/output/eve/eve-json-format.rst)
   at tag `suricata-8.0.6` (the latest released version as of writing — the
   same content is also on `master`, confirmed by diffing the two). These
   five records all share `flow_id: 1676750115612680` and are explicitly
   presented by the doc as one real, correlated capture — the doc's own
   text: *"Further below, you can see several examples of events logged by
   Suricata: an alert for an HTTP rule, fileinfo, http, anomaly, and flow
   events, all easily correlated using the flow_id EVE field"* followed by
   *"Examples come from pcap found at
   https://app.any.run/tasks/ce7ca983-9e4b-4251-a7c3-fefa3da02ebe/."* — i.e.
   OISF states outright these are from a real pcap run through Suricata, not
   illustrative/invented values. Extracted programmatically (Python
   `json.loads` on each pretty-printed block in the `.rst` source, then
   re-serialized compact/single-line to match real `eve.json`'s one-object-
   per-line convention) — field values are unmodified from the source.

Each line is independently valid JSON; the file as a whole is valid NDJSON
(Suricata's real on-disk `eve.json` format: one JSON object per line, no
enclosing array).

| Line | `event_type` | Source |
|---|---|---|
| 1 | `fileinfo` | suricata-verify `tests/output-eve-fileinfo/expected/eve.json` (real Suricata run against `input.pcap`, EICAR-over-HTTP) |
| 2 | `alert` | Suricata userguide, `flow_id=1676750115612680` correlated set |
| 3 | `fileinfo` | Suricata userguide, same correlated set |
| 4 | `http` | Suricata userguide, same correlated set |
| 5 | `anomaly` | Suricata userguide, same correlated set |
| 6 | `flow` | Suricata userguide, same correlated set |

## Suricata version

Pinned to **Suricata 8.0.6** (`suricata-8.0.6` git tag) for the userguide
excerpt — this repo has no prior Suricata integration/version pin to match
against (this module is new), so 8.0.6 was chosen as "the current stable
release at the time this fixture was built," per `CLAUDE.md` §F.2 step 1's
instruction never to assume "latest" without checking. The `suricata-verify`
line's exact Suricata version isn't stated in that repo (test fixtures don't
carry a version stamp); its `event_type: fileinfo` shape matches 8.0.6's
schema (`doc/userguide/output/eve/eve-json-format.rst`, "Event type:
fileinfo" section) so it is compatible with the same pin.

## What was checked and NOT included (honesty note, not a gap being hidden)

The task asked for `dns` and `tls` examples alongside `alert`/`http`/`flow`
if real ones could be found. Both were searched for and deliberately
**excluded** rather than fabricated:

- `OISF/suricata-verify` ships **no committed multi-event-type `eve.json`
  corpus** at all — of ~9,225 files in the repo, exactly one committed
  `eve.json` exists (`tests/output-eve-fileinfo/expected/eve.json`, used as
  line 1 above); every other test directory runs a real pcap through
  Suricata at CI time and asserts on the *output* via `jq`-style filters in
  `test.yaml`, without committing the raw JSON. There is no dns/tls example
  to pull from this repo without running Suricata against a pcap ourselves
  — out of scope per the task ("no tool installation needed... not running
  Suricata itself").
- The userguide's "Event type: DNS" and "Event type: TLS" sections
  (`eve-json-format.rst`) only show the **inner `"dns"`/`"tls"` sub-object**
  as a schema illustration (e.g. `"dns": {"type": "request", ...}`), never a
  full enveloped record (`timestamp`/`flow_id`/`event_type`/5-tuple +
  the sub-object) the way the alert/fileinfo/http/anomaly/flow section does,
  and the doc does not state these particular snippets come from one real
  pcap run the way the correlated set does. Synthesizing a full envelope
  around them (inventing a `timestamp`/`src_ip`/`flow_id` to wrap a real
  `"dns"` object) would itself be exactly the "plausible but unverified"
  fabrication `CLAUDE.md` §F prohibits, so it was not done.

If/when a real dns/tls `eve.json` sample surfaces (e.g. by later running
Suricata against a real pcap, which is out of scope for this lightweight
in-process-parser PoC), add it here and extend `SuricataEveParser`'s test
coverage accordingly — the parser's field-mapping already treats `dns`/`tls`
generically via the `extra` passthrough (see `src/external/parsers/suricata.py`),
so no parser code change would be needed, only a new fixture line.

## License

Suricata (including `doc/userguide/`) is licensed under the GNU General
Public License, Version 2.0
(https://github.com/OISF/suricata/blob/suricata-8.0.6/LICENSE). The
`suricata-verify` repository is licensed under the MIT License
(https://github.com/OISF/suricata-verify/blob/master/LICENSE.txt). These
five JSON *values* (field data captured by a GPL-2.0/MIT-licensed tool
during a real test run) are redistributed here as a plain-data test fixture
under the same terms as `tests/fixtures/samples/real/NOTICE.md`'s existing
convention for this directory.

Used by `tests/unit/parsers/test_suricata.py` and `poc/suricata/`.
