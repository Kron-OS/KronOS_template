# Gap Audit — Milestone VVVV (2026-09-02)

**Scope:** a real, reported bug — the same KAPE triage sent to KronOS twice,
once as a zip of loose files and once as an E01 disk image, gave "different
results," and the report named `event_identifier` (a real Windows Event ID,
`1100`) as unfilterable on the Plaso/E01 side. Two real questions to
untangle: (1) is Gap Audit Milestone UUUU's OpenSearch dynamic-indexing fix
actually reaching the real Discover UI a user sees, not just the raw HTTP
API, and (2) why would the two uploads of the *same* underlying evidence
look different at all.

## What UUUU already fixed, re-verified live at the UI layer (not assumed)

A real, authenticated (Keycloak SSO) headless-browser session against the
real case named in the report
(`kronos-kronos-dev-case-3033bc95-d03d-4ec3-ae1c-11b0d99bb8d6-201508`)
confirmed `event_identifier:1100` returns real hits (8, matching a raw
`curl` `term` query against the same index), the "Available fields"
sidebar lists `event_identifier`, and the "+ Add filter" picker offers it
as a real option. Screenshots and the full method are in
`poc/opensearch_dashboards_ui_verification/`. **Milestone UUUU's fix is
confirmed working end-to-end, including the OpenSearch Dashboards layer**
— an initial hypothesis that Dashboards' own saved index-pattern object
(a separate cache from the underlying OpenSearch mapping,
`src/adapter/opensearch/dashboards_client.py`) might be stale in a way
that blocks filtering was tested directly and **ruled out**: Discover
evidently re-fetches live fields at page load rather than trusting only
its persisted cache.

## The real remaining issue: two parsers, two field vocabularies, one artifact type

`FastEvtxParser` (`src/external/parsers/evtx.py`) handled loose `.evtx`
files (the zip path) and emitted ECS-flattened fields — `event.code`,
`winlog.event_data.*`. `PlasoParser` (`src/external/parsers/plaso.py`) is
the only parser that can open a whole disk image, so the E01 path always
went through it, and Plaso emits its own raw field names for the same
artifact — `event_identifier`, `message_identifier`, `xml_string`,
`source_name`, `provider_identifier`, `computer_name`. Both shapes are
independently correctly indexed and filterable (confirmed above) — the
"different results" the report actually observed was two different field
*vocabularies* for the same underlying Windows Event Log content,
depending only on which container the same artifact happened to arrive in.

Per the report's own suggested direction ("maybe the fast parser isn't
useful for now, just bypass fast parser, prefer plaso"): `FastEvtxParser`
is removed from the production parser registry
(`src/external/dependencies.py.get_parser_registry()`); `PlasoParser`'s
own `supports()` no longer refuses EVTX magic (`src/external/parsers/plaso.py`)
and is now the sole EVTX claimant for both a loose file and one embedded
in an image (`ZipArchiveParser`'s own recursive re-dispatch already routes
inner `.evtx` members through the same registry, so this applies uniformly
with no separate change needed there). `FastEvtxParser`'s class and its
own direct unit tests are left in place, unregistered rather than deleted
— reversible if a faster in-process path is wanted again later.

### Real verification, not assumed

1. `poc/plaso_evtx_direct/`: `plaso==20260512` (the exact pinned version,
   confirmed live via `docker exec docker-celery-worker-plaso-1 python3 -c
   "import plaso; print(plaso.__version__)"`) parses a **standalone**
   `.evtx` file directly — no extra flags needed, same `log2timeline`/
   `psort` invocation already used for E01/raw images — 391 real events
   from the real `tests/fixtures/samples/real/system.evtx` fixture in
   ~5.7s, same `event_identifier`/`xml_string`/etc. shape as the E01 case.
2. Full real pipeline: `docker restart` the two Celery worker containers
   (Celery doesn't hot-reload; the FastAPI backend already had via
   uvicorn `--reload`), then a real Playwright run (real Keycloak SSO
   login, real case creation, real upload of `system.evtx`) against the
   live dev stack — `Uploading -> Parsing -> Complete`. Queried the real
   resulting OpenSearch index directly afterward: `kronos.parser:
   "plaso"` (not `"evtx-rs"`), 391 hits, `event_identifier` present, no
   `event.code`/`winlog.*` at all.
3. `tests/unit/test_plaso_parser.py::test_supports_evtx` updated (was
   `test_rejects_evtx`, asserting the now-reversed behavior) — real
   regression guard, not just a PoC.
4. Full backend suite: `2063 passed, 2 skipped in 28.75s`, no regressions.
   `ruff`/`mypy` clean on both changed files.

## Status

Both original questions closed. The dynamic-indexing fix (Milestone UUUU)
is confirmed correct all the way to the real browser UI. The actual root
cause of "results are different" between the zip and E01 uploads — two
parsers, two field vocabularies for the same artifact type — is fixed by
making Plaso the sole EVTX handler, so a loose `.evtx` and one embedded in
an image now produce identical, directly-comparable field names.

## Recommendation for the next cycle

1. `FastEvtxParser` is now dead code in the live path (still imported and
   registered by its own isolated tests). If no future need for an
   in-process fast path re-emerges, consider removing it outright in a
   later cycle rather than carrying it indefinitely — deliberately not
   done this cycle (reversibility was the explicit goal here).
2. Existing evidence already parsed by `FastEvtxParser` before this change
   keeps its old `event.code`/`winlog.*` shape — this change only affects
   new parses. `scripts/reindex_kronos_dynamic_fields.py` (Milestone
   UUUU) does not re-parse or reshape existing documents, only refreshes
   their indexability; a genuine re-parse (delete + re-upload) is the only
   way to get an already-ingested zip's events onto Plaso's field shape,
   and is an operator/product decision, not something to force here.
