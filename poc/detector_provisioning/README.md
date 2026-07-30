# C2 · Per-org Security Analytics detector provisioning

Verifies `src/adapter/opensearch/detector_provisioner.py`
(`SecurityAnalyticsDetectorProvisioner`) against the real, live dev-stack
OpenSearch 2.11.1 Security Analytics plugin, and the real end-to-end route
wiring in `src/external/routes/cases.py`'s `create_case()`.

## Versions pinned

- OpenSearch 2.11.1, Security Analytics plugin bundled in `docker/docker-compose.dev.yml`'s `opensearch` image (same cluster C1/A3 verified against).
- `httpx` as pinned in `pyproject.toml`.

## Run

```
source ~/venv/bin/activate
python poc/detector_provisioning/run_poc.py
```

Requires the real dev stack up. If HTTPS calls to `kronos.local` fail with a
certificate-expired error (step-ca leaf cert has a 24h TTL, no auto-renew):
`docker compose -f docker/docker-compose.dev.yml up -d tls-init && docker
restart docker-nginx-1`, then retry.

## Result: 16 passed, 0 failed (see `output.txt` for the full real run)

## Real bugs found and fixed during this verification pass

Three genuine, reproducible bugs were caught by actually running this against
the live cluster/stack — none were visible from reading the code or from the
mocked unit tests (`tests/unit/adapter/test_detector_provisioner.py`), which
is exactly the failure mode CLAUDE.md §F exists to catch.

1. **Missing `verify=False` on the internal `httpx.AsyncClient`.** The
   backend's internal `OPENSEARCH_URL` is `https://opensearch:9200` even on
   the docker-internal network (TLS 1.3 internally, per CLAUDE.md's tech
   stack decisions), using the dev step-ca chain. The main
   `OpenSearchClient` already sets `verify_certs=False` for this reason;
   the new provisioner's own `httpx.AsyncClient` didn't, so every real call
   failed with `CERTIFICATE_VERIFY_FAILED`. Fixed.

2. **`extra={"name": name}` in two `logger.info`/`logger.warning` calls.**
   `name` is a reserved `LogRecord` attribute — passing it via `extra`
   raises `KeyError: "Attempt to overwrite 'name' in LogRecord"` inside
   `Logger.makeRecord`, but only when the logger's effective level actually
   enables that call (`isEnabledFor` short-circuits it otherwise). Default
   `WARNING`-level logging hid this locally; CLAUDE.md §B.4 mandates
   structured INFO-level logging in production, where this would have
   crashed **every** real detector-provisioning call not caught by the
   `httpx.HTTPError` except clause — i.e. every successful creation and
   every idempotent skip. Renamed to `detector_name` in both call sites.

3. **Idempotency check queried the wrong field shape.** `GET
   .../.opensearch-sap-detectors-config/_mapping` shows `detector` is a
   `nested` object containing `name` — not a top-level field — even though
   the plugin's own `_search` REST response flattens it back into a
   top-level `name` in each hit's `_source` for API consumers. A flat
   `term` query on `name.keyword` isn't rejected as invalid syntax; it just
   silently matches zero documents, always. This defeated the entire
   point of the idempotency check: `ensure_org_detectors()` created a
   duplicate detector on every single call, never finding the one it made
   moments before. Fixed to `{"nested": {"path": "detector", "query":
   {"term": {"detector.name.keyword": name}}}}`, matching the pattern
   `_fetch_prepackaged_rule_ids()` already used correctly for `rule.category`.
   Confirmed via direct curl before touching the source, then re-verified
   idempotent (Part 1: create twice, still exactly 3 detectors).

All three are now exercised by the real run captured in `output.txt`, not
just asserted from reading the diff.

## A fourth, real, *unresolved* finding (data-quality, not a code defect)

Part 2 (real `POST /api/cases` against the actual dev-stack org
`kronos-dev`) found that detector creation for that specific org fails with
a real, reproducible `security_analytics_exception` 500: `"an alias must
refer to an existing field in the mappings"`.

Root cause, confirmed directly (not inferred): `kronos-dev` has accumulated
~40 case indices across this session's own iterative PoC history, and some
predate the A1 index-template hardening. Those legacy indices have the
*same* ECS field mapped with a *different* concrete type than
template-created ones (e.g. `cloud.service.name` is plain `keyword` on
post-A1 indices, but dynamically-inferred `text` + `.keyword` subfield on
pre-A1 ones — confirmed via `GET <index>/_mapping` on both). OpenSearch
Security Analytics runs a cross-index alias-consistency check when creating
a detector over a wildcard index pattern (`kronos-kronos-dev-*` here), and
that check legitimately rejects the type mismatch.

This is **not** a flaw in the provisioner's design or the idempotency logic:
Part 1 proves detector creation, per-org/per-log-type naming and scoping,
and idempotent re-runs all work correctly end-to-end against a *clean* org
with consistently-mapped indices — which is the state any real new tenant
is in post-A1 (no legacy pre-hardening indices to conflict with). It is a
data-quality artifact specific to this dev org's own history of being used
as the target of many earlier PoCs in this same session.

What **is** verified to hold even under this real failure: the binding
safety property the design exists to guarantee. `ensure_org_detectors()`
is `await`ed directly from `create_case()` with no try/except around it —
its own internal per-log-type `except httpx.HTTPError` is what has to catch
this, and it does: both real case creations in Part 2 still returned `201`,
and no partial/duplicate detector was left behind by the failed attempts.

Follow-up (not in C2's scope — a data-migration concern, not a code change):
reindexing `kronos-dev`'s pre-A1 indices to the current template, or a
one-time backfill script, would let detector provisioning succeed for this
specific dev org too. Tracked here rather than attempted as unplanned scope
creep on top of C2.

## What Part 1 (direct class-level, synthetic clean org) proves

- Exactly 3 detectors created (`windows`, `cloudtrail`, `network` — the C1
  gate's verified-coverage log types via `get_default_log_types()`), each
  named `kronos-{org_alias}-{log_type}-detector`.
- Each detector's index pattern is `kronos-{org_alias}-*` — per-org, not
  per-case (a case's log types aren't known in advance; see the class
  docstring for the full rationale already reviewed at design time).
- Each detector carries the real, full prepackaged rule set for its log
  type fetched live from `_plugins/_security_analytics/rules/_search`
  (windows: 1580 rules, cloudtrail: 32, network: 38 — consistent with the
  cluster-wide totals C1 already established).
- Re-running `ensure_org_detectors()` a second time creates no duplicates.
- The real OpenSearch 2.11.1 PUT-update defect this design was built around
  (`PUT` with the same empty-`triggers` shape `POST` accepts returns a real
  500, `kotlin.collections.EmptyMap cannot be cast to
  kotlin.collections.MutableMap`) is reproduced directly, confirming
  check-then-create-only (never update-in-place) is the right call, not
  just a defensive guess.
- All synthetic-org detectors are cleaned up at the end of the run.

## What Part 2 (real end-to-end via the actual backend API) proves

- A real case-lead login (`auth_helpers.real_browser_login`) followed by a
  real `POST /api/cases` triggers `detector_provisioner.ensure_org_detectors()`
  through the actual FastAPI DI chain — not called directly, the real route
  wiring in `src/external/routes/cases.py`.
- A tenant JWT cannot call Security Analytics directly (`403`) — the A3
  gate's binding condition (SA is admin-only, never tenant-facing) holds;
  the provisioner's own admin credentials (fixed at construction from
  `settings.opensearch_username`/`password`, never a per-request tenant
  token) are the only path that ever reaches SA.
- A second real case creation for the same (affected) org neither duplicates
  detectors nor fails case creation — the graceful-degradation contract
  holds under the real failure mode found above.
- Both throwaway real cases created during the run are archived via `DELETE
  /api/cases/{id}` at the end.
