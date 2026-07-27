# Auto-provisioning the per-case OpenSearch Dashboards index pattern

**Versions pinned:** `opensearchproject/opensearch-dashboards:2.11.1`,
`opensearchproject/opensearch:2.11.1` (matching `docker-compose.dev.yml`).

## The gap this closes

`poc/opensearch_dashboards_dls/` fixed real users being denied all
`kronos-*` document reads. Following up on that fix in a real browser
(previous session) surfaced the *next* blocker: `cases.py`'s
`get_dashboard_url()` only ever put a raw index-name **string** into the
embed URL's filter (`meta.index: 'kronos-{org_alias}-case-{case_id}-*'`) —
it never created an actual saved **index-pattern object**. OpenSearch
Dashboards' Discover view needs a real saved object to open, not just a
filter string, so every real user landed on "Ready to try OpenSearch
Dashboards? First, you need data" / "you must create an index pattern to
retrieve data" — solvable only by manually typing the pattern into the
Index Patterns wizard every time, which is what the prior PoC's browser
pass had to do by hand.

This is already documented as a known, pre-existing gap
(`PROGRESS.md`'s flag E, `poc/dashboards_embed/README.md`) — not something
either DLS fix introduced.

## Design constraint (confirmed against real 2.11.1 source, not assumed)

`IndexPatternAttributes` (`src/plugins/data/common/index_patterns/types.ts`
at tag `2.11.1`) has fields `type, fields, title, typeMeta, timeFieldName,
intervalName, sourceFilters, fieldFormatMap` — **no separate display-name
field**. `title` is simultaneously the technical matching pattern and the
only label the UI shows. Per explicit user decision, `title` is set to the
real matching pattern (`kronos-{org_alias}-case-{case_id}-*`), not the
case's human title — the two can't coexist in one field in this version,
and a non-matching title would break Discover entirely.

## The real API, verified against the live dev stack (not assumed)

- `POST /api/saved_objects/index-pattern/{id}?overwrite=true` is the
  idempotent create-or-replace call. **`PUT` is update-only and 404s** if
  the object doesn't already exist — the first, wrong thing tried here.
- The `osd-xsrf` header is mandatory on any non-`GET` call, or Dashboards
  flatly 400s: `"Request must contain the osd-xsrf header."`
- `securitytenant` header selects which tenant's backing index gets
  written — must be `kronos-{org_alias}`, matching
  `scripts/provision_dashboards_tenant.sh`'s own tenant naming, or real
  users querying that tenant never see the object.
- `admin:admin` Basic auth works against Dashboards' own API even with
  `opensearch_security.auth.type: openid` configured, because
  `basic_internal_auth_domain` (order 4) stays enabled alongside the
  `openid_auth_domain` (order 10) — OpenSearch tries domains in order and
  the Basic credentials match the still-enabled basic domain. This is the
  same mechanism `keycloak-init`/`dashboards-tenant-init` already rely on
  for their own admin-credentialed provisioning calls.

## Implementation

`src/adapter/opensearch/dashboards_client.py` — new
`DashboardsIndexPatternProvisioner`, a thin adapter (not an ABC — there is
exactly one real implementation, matching `RFC3161TimestampService`'s own
precedent for a single-technology integration). Wired via
`src/config.py`'s new `opensearch_dashboards_internal_url` setting (plain
`http://opensearch-dashboards:5601`, Docker-internal — no TLS/nginx hop
needed for a container-to-container call, unlike the existing
browser-facing `opensearch_dashboards_url`), constructed in
`src/external/startup.py` (`None` — honestly disabled — when unset, same
pattern as `timestamp_service`), and called from `cases.py`'s
`create_case()` after the case is persisted. Best-effort: failures are
logged, not raised, so a transient Dashboards outage never blocks case
creation — a user can still fall back to the manual wizard.

## What was verified, for real

`run_poc.py` imports the real `DashboardsIndexPatternProvisioner` class
(not a reimplementation) and calls it against the actual running dev
stack's real OpenSearch Dashboards (`localhost:5601`). **8/8 checks
passed** (`output.txt`):

- First call creates the saved object with the exact expected `title` and
  `timeFieldName`.
- Second call (idempotent re-run) succeeds and reuses the same object id
  rather than duplicating it.
- The object is discoverable via the real `_find` API a real user's
  browser actually calls, under the correct `securitytenant`.
- The exact title string is confirmed to be valid OpenSearch index-pattern
  syntax via a direct `_resolve/index` call.
- A deliberately unreachable Dashboards endpoint is swallowed
  (best-effort logged, not raised) — confirms case creation would not be
  blocked by a Dashboards outage.

## Shipped and verified against the real, rebuilt dev stack

Rebuilt `kronos-backend`/`celery-*` images (`docker compose up -d --build`)
and relaunched. Created a real case via the real API
(`POST /api/cases`, real PKCE login as `case-lead`) — the backend's own
logs show `dashboards_index_pattern_ensured` immediately, and the real
saved object exists via `GET /api/saved_objects/index-pattern/{id}` with
the exact expected title, with **zero manual steps**.

**Real Playwright browser confirmation**: logged in as `case-lead`,
opened the new case's Timeline tab, selected the case's org tenant (a
separate, pre-existing dialog — see below), and the Index Patterns list
shows **both** the case created here and the one manually created in the
prior session — `browser_verification_auto_created_pattern_listed.png`.
No manual "Create index pattern" wizard step was needed for this new
case, unlike every case before this fix.

**Still not zero-click end-to-end**: Discover itself doesn't auto-open
with this pattern selected — the tenant-selector dialog (a separate,
pre-existing gap, see `poc/opensearch_dashboards_dls/README.md`'s
"Remaining" section) and `get_dashboard_url()`'s embed URL not
referencing the new saved object's real ID (rather than a raw filter
string) both still require the user to navigate into Discover manually
once the pattern is provisioned. This PoC's scope was the auto-provisioning
itself, which is confirmed working; making the embed URL open Discover
directly against the provisioned pattern is further follow-up work, not
covered here.

## Not yet done

- `docker/docker-compose.prod.yml`'s `kronos_backend` OpenSearch internal
  user would need an explicit `kibana_all_write`-equivalent grant (or
  superuser) for this to work in prod as configured — only verified for
  dev's `admin`-credentialed backend in this pass, left as a flagged
  follow-up rather than guessed at.
- No backfill for cases created *before* this shipped — their index
  pattern still needs the manual one-time wizard step
  (`poc/opensearch_dashboards_dls/README.md`'s workaround) until someone
  visits their Timeline tab under a version with this fix, or a manual
  backfill script is written.
