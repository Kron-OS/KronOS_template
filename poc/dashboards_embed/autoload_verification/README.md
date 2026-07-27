# Autoload verification — resolving `poc/dashboards_embed/README.md`'s flagged question

**Question that PoC left open:** "The URL never specifies which index
pattern Discover should actually open ... genuinely requires a live
browser session to observe." This closes it, and also closes the
separate tenant-selector-dialog gap noted in
`poc/opensearch_dashboards_dls/README.md`'s "Remaining" section.

**Versions pinned:** `opensearchproject/opensearch-dashboards:2.11.1`;
real source read at that tag for both
`opensearch-project/OpenSearch-Dashboards` and
`opensearch-project/security-dashboards-plugin` (the bundled plugin that
owns tenant resolution — a separate repo from the main one).

## Real finding #1: state must live in the URL fragment, not the top-level query string

The original `get_dashboard_url()` put `_g` (and, in an early draft of
this fix, `_a`) in the top-level query string — matching how a classic,
directly-mounted Kibana/OSD `discover` app's own
`DiscoverUrlGenerator` (`src/plugins/discover/public/url_generator.ts`)
works. But `/app/data-explorer/discover` isn't that — `discover` is
mounted as a *view* inside the newer `data_explorer` wrapper app
(confirmed in the prior PoC), and `data_explorer`'s own Redux persistence
(`src/plugins/data_explorer/public/utils/state_management/redux_persistence.ts`
at tag `2.11.1`) reads/writes its entire state under the key `_a` via
`services.osdUrlStateStorage`, which for this app is the URL **fragment**
(`#?_a=...&_g=...&_q=...`), not the top-level query string.

Verified by direct observation, not just source-reading: loaded a
hand-built URL with `_a`/`_g` in the top-level query string in a real,
logged-in browser (Playwright) and read back `page.url` afterward — the
app had silently discarded both and fallen back to its own
`metadata_slice.ts`'s `getPreloadedState()` default (whatever index
pattern was last viewed), landing on a *different, stale* case's data
with zero error. This is worse than an obvious failure: it silently shows
the *wrong* case's timeline, still filtered oddly enough to look
plausible.

## Real finding #2: the correct `_a`/`_g`/`_q` split

Rebuilt the URL with state in the fragment and reloaded — the real app's
own router settled on:
```
_a=(discover:(columns:!(_source),isDirty:!f,sort:!()),metadata:(indexPattern:'<id>',view:discover))
_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-30d,to:now))
_q=(filters:!(<the kronos.case_id filter>),query:(language:kuery,query:''))
```
`_a.metadata.indexPattern` (`metadata_slice.ts`'s `MetadataState.indexPattern`)
is what selects the active index pattern by its real saved-object id —
here, the exact deterministic id `DashboardsIndexPatternProvisioner`
already provisions (`case_index_pattern_id()`, now a shared helper so the
two can never drift apart). The case filter moved from `_g` (global
state, the prior design) to `_q` (query state) — confirmed this is what
the real app itself produces by default, not assumed.

## Real finding #3: `security_tenant` query param skips the tenant dialog

Read the real `security-dashboards-plugin` server source
(`server/multitenancy/tenant_resolver.ts` at tag `2.11.1.0`):
`resolveTenant()` checks a `security_tenant` (or `securitytenant` /
`securityTenant_`) URL query param **before** falling back to the session
cookie. Adding `security_tenant=kronos-{org_alias}` as a **top-level**
query param (this one *is* read there — tenant resolution happens
server-side per-request, unrelated to the client-side Redux/fragment
routing above) resolves the org's tenant on the very first request.
Verified directly: loading the URL in a real logged-in browser never
showed the "Select your tenant" dialog at all, unlike every prior real
browser pass in this session.

## What was verified, for real

`run_poc.py` calls the real, updated `get_dashboard_url()` route (backend
only, `InMemoryCaseRepository`, no OpenSearch needed for this half) — 11/11
checks: `security_tenant` present at top level, `_a`/`_g`/`_q` absent from
the top level (would be silently ignored there), all three present in the
fragment, `_a` referencing the real provisioned index-pattern id, `_q`
carrying the case filter, `_g` carrying the time range. `run_poc.sh` then
decodes all three RISON blobs with the real pinned `rison-node@1.0.2` — all
decode cleanly (`output.txt`).

**Real browser confirmation** (against the live dev stack, not
scriptable as a hermetic backend-only PoC): loaded a hand-built URL
matching this exact shape in a real logged-in browser — Discover opened
directly on the correct index pattern, the `kronos.case_id` filter was
already applied, a real matching document was shown, and the tenant
dialog never appeared.

**Shipped and re-verified end-to-end after rebuilding the real dev
stack**: logged in as `case-lead` through the real SPA, clicked a real
case's Timeline tab — the iframe's own URL (built by the real, rebuilt
`get_dashboard_url()`, not hand-crafted) loaded Discover directly on the
correct index pattern (`kronos-kronos-dev-case-9a2db8f3...-*`), with the
`kronos.case_id` filter already applied and a real matching document
shown — **zero clicks, no tenant dialog** —
`browser_verification_zero_click_autoload.png`. This closes the
"Discover doesn't auto-open with this pattern selected" caveat left open
in `poc/dashboards_index_pattern_provisioning/README.md`.
