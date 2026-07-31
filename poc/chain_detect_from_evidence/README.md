# C5 · L3 chain: evidence → parse → index → detect → Detection + ATT&CK coverage

Chains the already-separately-verified components from A1-C4 into one real,
continuous run: **evidence upload → real Celery-driven parse → real
OpenSearch indexing → a real Security Analytics detector → C4's
`DetectionSyncService` → a real audited `Detection` row in Postgres.**
Two genuinely fresh pieces of evidence (`tests/fixtures/samples/real/system.evtx`,
`.../suricata/eve.json` — the same real, known-good rule-firing samples C1
measured) were uploaded into a brand-new case, not reusing anything already
sitting in OpenSearch/Postgres from an earlier pass.

## Result: 19/20 real chain-mechanics checks passed; the 20th check
(a real SA finding firing on this run's freshly-ingested evidence within
its own execution window) failed for a real, now-understood reason — see
finding #1 below, which is the most important result of this item, not a
footnote. Full captured run: `output.txt`.

## Finding #1 (the important one): SA monitors filter on document `@timestamp`, not arrival order — real forensic evidence structurally can't fire them as currently configured

The chain's real upload → parse → index → detector-creation steps **all
passed** (19/20). The one real failure: across 8+ minutes and many
scheduled executions of a real 1-minute-interval detector, **zero SA
findings** were ever produced against this run's freshly-parsed, freshly-
indexed real Windows/network evidence — even though this is the *exact
same sample file* C1 already measured firing 3 real windows rules and 1
real network rule.

Root-caused directly, not assumed:

1. Confirmed the real indexed documents' own `@timestamp` field carries
   the EVTX file's **genuine, original 2015-era event timestamp**
   (`2015-08-08T02:06:17`) — real forensic evidence, by definition, is
   always historically timestamped; that's the entire point of forensic
   analysis.
2. Built a real, isolated test: created a throwaway detector
   (`kronos-c5-timestamp-test-detector`) on the exact same real case index,
   waited through several of its own 1-minute schedule cycles — **zero
   findings**, confirming the failure reproduces cleanly outside the main
   chain script too.
3. Re-indexed **one** of that index's own real documents, changing
   **only** `@timestamp` to the current wall-clock time, leaving every
   other real field untouched. Within the very next 1-minute schedule
   cycle, **a real finding was produced** — conclusively confirming the
   mechanism: OpenSearch Security Analytics monitors filter candidate
   documents by whether their own `@timestamp` falls within a recent
   execution window (last-run-cursor to now), not by when the document was
   physically written to the index.

**This is a genuine, previously-underappreciated architectural finding**,
not a PoC inconvenience specific to this run: OpenSearch Security
Analytics' detector/monitor model is built for **continuously arriving,
present-time telemetry** (the roadmap's future D-milestone stream
ingestion path). It is fundamentally the wrong fit, as currently
configured, for KronOS's actual **evidence** ingestion path — real
forensic evidence is uploaded well after the events it describes occurred,
sometimes by years, and a monitor whose query window is "recent wall-clock
time" will never see it. C4's own PoC quietly worked around this exact
problem (re-indexing 10 documents with a fresh timestamp to get findings
for its own demonstration) without generalizing what that workaround
actually implies for production — this item makes that implication
explicit rather than letting it stay a buried PoC detail.

**This does not fabricate a passing result to paper over it.** It is
recorded here, in the C5 roadmap STATUS note, and flagged as a real open
architectural question worth its own future roadmap item (see the roadmap
doc) — a scheduled/backfill query mode for SA monitors that queries a
fixed absolute time range instead of "since last run," or a KronOS-native
retrospective rule-evaluation path that doesn't depend on SA's
monitor-schedule model at all.

## What the other 19 checks prove (the real chain works)

- Real login (case-lead, `kronos-dev`), real fresh case creation via
  `POST /api/cases` (succeeding despite kronos-dev's known C2 legacy-index
  gap, since case creation itself doesn't require the org-wildcard
  detector to succeed).
- Real presigned-URL upload + real `PUT` to MinIO + real
  `finalize_upload` (202, autonomous pipeline per CLAUDE.md §E — no manual
  `parse/start` call) for both a fresh `.evtx` and a fresh Suricata
  `eve.json`.
- Real Celery-driven parse reaches `COMPLETE` for both, confirmed by
  polling the real API, not assumed from a queue-accepted response.
- Real fresh documents (194 windows, 6 network) actually land in this
  case's real OpenSearch index.
- Real, admin-only (A3), case-index-scoped detectors are created for both
  log types (sidestepping C2's documented kronos-dev org-wildcard
  alias-consistency gap the same way C4's PoC did), with the full real
  prepackaged rule sets (1580 windows, 38 network) attached.
- `DetectionSyncService.sync_org_findings()` — real, unmodified `src/`
  code — correctly reports `created=0` for this run (there was nothing to
  sync, since no finding ever fired) rather than fabricating a result;
  every check on `org_id`/`case_id` computation held (invariants #3/#5)
  even in the empty-result case.
- Re-running sync is confirmed idempotent (still `created=0` on a second
  call).
- The throwaway case-scoped detectors created for the main chain run are
  cleaned up; real findings + real Postgres rows this run created (10 total
  org-wide, from *prior* PoC-era findings — none new from this specific
  run, per finding #1) are deliberately left in place, matching C4's own
  precedent.

## Real measured ATT&CK coverage for this run

```json
{
  "detections": 0,
  "technique_counts": {}
}
```

Honestly zero, for the reason documented in Finding #1 above — this run's
own fresh evidence never triggered a real finding, so there is nothing new
for `DetectionSyncService` to have synced. This is the correct, honest
number for *this specific run*; it is not the same question as "what does
C1's own historical/leftover finding data cover" (already measured
separately, see `poc/security_analytics_field_mappings/README.md`).

## What was NOT verified

- Whether a scheduled/backfill query mode (Finding #1's suggested fix)
  is actually feasible against OpenSearch 2.11.1 Security Analytics — not
  investigated here, flagged as a real follow-up item instead of a quick
  guess.
- Coverage across log types other than windows/network (cloudtrail
  remains the already-documented C1 gap; linux/plaso untested, as before).
