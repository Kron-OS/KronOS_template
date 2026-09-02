# PoC: Plaso parses a standalone `.evtx` directly (Gap Audit Milestone VVVV)

**Question this answers:** before removing `FastEvtxParser` from the
production parser registry and making `PlasoParser` the sole EVTX claimant
(`src/external/dependencies.py`, `src/external/parsers/plaso.py`), does
`plaso==20260512` (the version pinned in `docker/plaso/Dockerfile`, confirmed
live: `docker exec docker-celery-worker-plaso-1 python3 -c "import plaso;
print(plaso.__version__)"` → `20260512`) actually handle a **loose** `.evtx`
file the same way it already handles one embedded inside an E01 image, or
does it only work in the image case?

## Why this mattered

A real bug report: uploading the same KAPE triage as a zip of loose `.evtx`
files (routed to `FastEvtxParser`, fast/in-process) and as an E01 disk image
(routed to `PlasoParser`, since Plaso is the only parser that can open a
whole image) produced two **incompatible field shapes** for the exact same
Windows Event Log data -- `FastEvtxParser` emits ECS-flattened
`event.code`/`winlog.event_data.*`, Plaso emits its own raw
`event_identifier`/`message_identifier`/`xml_string`/`source_name`/etc. The
underlying OpenSearch dynamic-indexing bug (Gap Audit Milestone UUUU) was
already fixed and verified separately (`poc/opensearch_auto_index_fields/`)
-- both shapes are equally filterable once indexed -- but the two field
*names* never matched each other, which is what actually read as "results
are different" / "can't filter" when comparing the two uploads side by side.
The fix: stop registering `FastEvtxParser` in the live registry so every
`.evtx`, loose or embedded, goes through Plaso and gets the same shape. This
PoC is the required real-run check (CLAUDE.md §F) that Plaso can actually
take over the loose-file case before flipping that switch.

## Real run

```
docker cp tests/fixtures/samples/real/system.evtx docker-celery-worker-plaso-1:/tmp/system.evtx
docker exec docker-celery-worker-plaso-1 python3 /app/plaso-worker/kronos-plaso-worker.py \
  --evidence-path /tmp/system.evtx --evidence-id 00000000-0000-0000-0000-000000000001 \
  --case-id 00000000-0000-0000-0000-000000000002 --org-id 00000000-0000-0000-0000-000000000003 \
  --org-alias poc --sha256 deadbeef > output.jsonl 2> stderr.txt
```

Real, captured result: exit 0, **391 events**, ~5.7s wall-clock (`time`
output: `real 0m5.688s`). `stderr.txt` (`log2timeline_psort_stderr.txt` in
this directory) shows the exact real subprocess invocations:

```
INFO Starting Plaso parse: /tmp/system.evtx
INFO Running log2timeline: /opt/venv/bin/log2timeline --quiet --status_view none --storage-file /tmp/tmp6allch94.plaso /tmp/system.evtx
INFO Running psort: /opt/venv/bin/psort --quiet -o json_line -w /tmp/tmp2vbf3sve.jsonl /tmp/tmp6allch94.plaso
INFO Plaso parse complete: 391 events
```

No extra flags, no dfVFS type-indicator config -- log2timeline auto-detects
a bare `.evtx` path exactly like it already auto-detects an E01 path, and
routes it through the same `winevtx` plugin either way (confirmed by
`"parser": "winevtx"` in the first record, `first_record_sample.jsonl` in
this directory).

Real first record (`first_record_sample.jsonl`) confirms the exact field
shape carries over identically to the E01 case (`event_identifier: 4608`,
`message_identifier: 4608`, `source_name`, `provider_identifier`,
`xml_string`, `computer_name`, `record_number` -- same names as
`kronos-kronos-dev-case-3033bc95-...-201508`'s real E01-derived documents,
inspected directly via the OpenSearch HTTP API in the same investigation
this PoC is part of).

One difference from the E01 case, expected and already handled by
`_plaso_source_path()` (`src/external/sandbox/firecracker.py`): a loose
single-file parse's `display_name` is `"OS:/tmp/system.evtx"` (the `OS:`
dfVFS prefix for a bare local file, not a real in-image path), so
`kronos.source_path`/`container_sha256` stay unset for this record --
exactly the documented, pre-existing behavior for any single-file Plaso
parse (registry hive, prefetch, etc.), not a regression.

## Follow-up real verification (full pipeline, not just the worker script)

Also verified through the **entire real system**, not just the worker in
isolation, after wiring the registry change into
`src/external/dependencies.py` and `src/external/parsers/plaso.py`:

1. `docker restart docker-celery-worker-1 docker-celery-worker-plaso-1
   docker-celery-beat-1` (Celery doesn't hot-reload; the FastAPI backend
   does via uvicorn `--reload` and had already picked up the change).
2. A real Playwright E2E run (case-lead login via real Keycloak SSO,
   `casesPageAsCaseLead.createCase()` then `uploadEvidence(system.evtx)`)
   against the live dev stack: `STATES Uploading -> Parsing -> Complete`.
3. Queried the real resulting OpenSearch index directly:
   `kronos.parser: "plaso"` (not `"evtx-rs"`), 391 hits, `event_identifier`
   present, no `event.code`/`winlog.*` at all -- confirming the loose
   `.evtx` upload is now genuinely parsed by Plaso end-to-end through the
   real Celery/OpenSearch pipeline, not just in this isolated worker-script
   PoC.

## Status

Confirmed safe to flip the registry. `src/external/parsers/evtx.py`
(`FastEvtxParser`) itself is left in place, still unit-tested directly
(`tests/unit/parsers/test_evtx_parser.py`,
`tests/unit/test_pipeline_end_to_end.py`'s own local FAST-only registry) --
only removed from `get_parser_registry()`'s live selection path.
