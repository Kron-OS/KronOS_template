# PoC: cases.py's Dashboards-embed-URL route, backend side only (step 10)

## Component pair
`src/external/routes/cases.py`'s `get_dashboard_url()` (`GET
/{case_id}/dashboard-url`), run as the real, unmodified route inside the
real FastAPI app (`create_app()`) — plus the real, pinned
`opensearch-project/OpenSearch-Dashboards@2.11.1` source and its exact
`rison-node@1.0.2` dependency (from that repo's own `package.json`), used
to check whether the URL this route hand-builds is actually well-formed
for the real app it targets.

**Scope, deliberately backend-only:** this route was never run before, and
prior agent work hand-built a Dashboards deep-link (app path + a RISON-encoded
global-filter state) that looked plausible but was never checked against
the real target app's actual routing/state-encoding. Whether the resulting
URL, once loaded in a *real browser*, actually shows the right data is a
separate question — that needs a live browser and is `poc/frontend_browser`'s
job (not yet done). This PoC verifies everything that's checkable without
one: the route's own logic, and whether the string it emits is genuinely
valid input for the real Dashboards version pinned in this repo.

## Versions (pinned, read from this repo)
- `opensearchproject/opensearch-dashboards:2.11.1` (`docker/docker-compose.dev.yml`)
- Real GitHub source read at tag `2.11.1` of `opensearch-project/OpenSearch-Dashboards`
- `rison-node@1.0.2` — read directly from that repo's own `package.json` at
  the same tag, then installed for real (not assumed) via `npm install
  rison-node@1.0.2` in a throwaway `node:20-alpine` container

## What this actually does
`run_poc.py` boots the real FastAPI app, wires a real `InMemoryCaseRepository`
(the route's own logic never touches OpenSearch — it only builds a URL
string — so no OpenSearch/Postgres container is needed for this half),
seeds two real cases (one the caller owns, one belonging to a different
org), and drives the real route through 8 checks. `run_poc.sh` then takes
the exact `_g` RISON blob the route actually produced and decodes it with
the real pinned `rison-node` library via a real Node container.

## Real findings, verified against the pinned 2.11.1 source (not guessed)

1. **The app path `/app/data-explorer/discover` is correct.** Read the real
   source: `data_explorer`'s `PLUGIN_ID` is literally the string
   `'data-explorer'` (`src/plugins/data_explorer/common/index.ts`), and
   `discover`'s `plugin.ts` registers "discover" as a **view** inside that
   single app via `dataExplorer.registerView({ id: PLUGIN_ID, ... })` where
   discover's own `PLUGIN_ID` is `'discover'`. So the real, full path is
   exactly `app/<data-explorer-app-id>/<discover-view-id>` — matching what
   `cases.py` already builds.

2. **`_g` is the correct real query-param key for global state.** Read the
   real source: `data_explorer/public/plugin.ts`'s `createOsdUrlTracker`
   call registers `stateParams: [{ osdUrlKey: '_g', ... }]` for exactly the
   filters/time/refreshInterval state this route sets.

3. **The hand-built RISON string is genuinely well-formed.** Decoded the
   *exact* string the real route produced (not a hand-copied example) with
   the real pinned `rison-node@1.0.2` — decodes cleanly to the intended
   nested structure (`output.txt`). No quoting/escaping bugs.

4. **The raw `meta.index` string (not a real index-pattern saved-object ID) is NOT a bug in this version — confirmed, not assumed.**
   Dashboards' own `buildPhraseFilter()` helper (`phrase_filter.ts`) always
   sets `meta.index` to `indexPattern.id` (a saved-object UUID), which made
   the raw pattern *string* `cases.py` uses look suspicious at first. But
   the actual filter-matching code that would care about this
   (`filter_matches_index.ts`) only checks `filter.meta.key` against the
   index pattern's real field list — with an explicit maintainer comment:
   *"We should probably modify this to check if filter.meta.index matches
   indexPattern.id instead, but that's a breaking change."* In other
   words: in 2.11.1, `meta.index` is not actually consulted for this at
   all. As long as the real KronOS ECS index template maps `kronos.case_id`
   as a real field (confirmed in `poc/full_pipeline/`), this filter is
   correctly recognized regardless of what string is in `meta.index`.

## Real finding, flagged not resolved (needs a browser — explicitly out of scope here)
The URL never specifies **which index pattern** Discover should actually
open — there's no `_a` (app state) parameter, no index-pattern reference
anywhere. Whether Data Explorer/Discover falls back to a sensible default
(e.g. the last-used pattern, or a pattern inferred from the case's own
index naming) or opens with no results / an error is a real, open question
that genuinely requires a live browser session to observe — the same class
of question `poc/frontend_browser` (not yet done) is scoped to answer.
Flagging clearly rather than guessing, same reasoning as every other
"needs a design decision / needs a browser" flag elsewhere in this repo's
PoCs.

## Result: 8/8 real checks passed (`output.txt`)
- Real `503` when Dashboards isn't configured.
- Real `404` for a nonexistent case, and for a case belonging to a
  different org (via `case_repo.get_by_id`'s own org-scoping — never a
  403 that would leak the case's existence).
- Real `200` with a real, correctly-rooted embed URL for the case's actual
  owner/member.
- Real app path, real `_g` key, real `embed=true` — all confirmed against
  pinned source, not assumed.
- The real RISON blob the route produced decodes cleanly with the real
  pinned `rison-node@1.0.2`.

## Files
- `run_poc.sh` — orchestration: runs `run_poc.py`, then decodes the real
  captured `_g` blob with a real Node container
- `run_poc.py` — the actual verification, using the real FastAPI route
- `output.txt` — captured transcript of the last real run (8/8 passed)
