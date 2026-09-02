# PoC: real-browser confirmation that Milestone UUUU's fix reaches the actual Discover UI (Gap Audit Milestone VVVV)

**Question this answers:** a live bug report said "Plaso fields are not
dynamic, I can't filter on event identifier 1100" for
`https://kronos.local/cases/3033bc95-d03d-4ec3-ae1c-11b0d99bb8d6`'s E01
evidence. Gap Audit Milestone UUUU had already fixed OpenSearch's own
dynamic-field mapping and verified it via raw HTTP
(`poc/opensearch_auto_index_fields/`). Two real possibilities remained
unverified: (1) does the fix actually reach the real, authenticated
OpenSearch Dashboards Discover embed a user sees, not just the raw
OpenSearch HTTP API, and (2) is OpenSearch Dashboards' own saved
index-pattern (a *separate* cached field list,
`src/adapter/opensearch/dashboards_client.py`) stale in a way that would
still block filtering even with the underlying mapping fixed?

## Method

A real, authenticated (Keycloak SSO, dev-seeded `admin` user) headless
Chromium session (Playwright, already a project dependency) against the
live dev stack, navigating to this exact case's real Timeline tab (the
same real `iframe[title="Timeline Analysis"]` `dashboards-embed.spec.ts`
already asserts on) and interacting with the real Discover UI: typing KQL
queries into the real query bar, reading the real hit count, reading the
real "Available fields" sidebar, and opening the real "+ Add filter" field
picker.

Run: `node run_poc.mjs` (requires the dev stack up, `kronos.local` in
`/etc/hosts`, and `frontend/node_modules` installed for the bundled
Playwright).

## Real, captured findings

1. `event.code:1100` (the zip/FastEvtxParser field): **4 hits** rendered
   inside the real iframe.
2. `event_identifier:1100` (the Plaso-only field the bug report named):
   **8 hits** -- matches the raw OpenSearch `term` query result obtained
   independently via `curl` against the same index
   (`kronos-kronos-dev-case-3033bc95-...-201508`) before this browser run.
   Screenshot: `2_event_identifier.png` -- shows the real Discover UI with
   "8 hits" and a populated histogram.
3. Free-text `1100` (exactly the query embedded in the bug report's own
   pasted URL): **12 hits** -- matches the raw `query_string` result
   obtained the same way.
4. **Sidebar "Available fields"**: contains `event_identifier` and
   `message_identifier` as real, listed fields (screenshot:
   `4_sidebar_full.png`).
5. **"+ Add filter" field picker**: offers `event_identifier` as a real,
   selectable autocomplete option (screenshot: `5_add_filter_picker.png`).

## Conclusion: the reported symptom does not currently reproduce

Filtering on `event_identifier` -- by typed KQL, by the sidebar, and by
the "+ Add filter" UI -- all work correctly, right now, in a fresh
authenticated session. Milestone UUUU's fix is confirmed live end-to-end,
not just at the raw HTTP layer. OpenSearch Dashboards' own
`_fields_for_wildcard` live endpoint (checked separately via `curl` before
this browser run) already reflects the new fields even though the *saved*
index-pattern object's persisted `fields` blob was stale (189 fields,
missing `event_identifier`) -- Discover evidently re-fetches live fields
at page load rather than trusting only the persisted cache, so that
staleness turned out NOT to be user-facing (an initial hypothesis this PoC
was built to test, and ruled out by the real run rather than assumed).

**The real, still-open gap** this investigation actually found is
different: `FastEvtxParser` (zip path) and `PlasoParser` (E01 path) emit
*different field names* for the same Windows Event Log content
(`event.code` vs `event_identifier`) -- both are correctly indexed and
filterable independently, but comparing the two uploads side by side (as
the bug report's own scenario did -- one zip, one E01 of the same triage)
looks exactly like "results are different" / "can't filter [the same
way]". That is what `poc/plaso_evtx_direct/` and the
`src/external/dependencies.py` / `src/external/parsers/plaso.py` change in
this same milestone actually fix -- not a residual OpenSearch/Dashboards
bug.
