# Gap Audit — Milestone NN (2026-08-22)

Fresh full-repo gap audit, per `docs/GAP_AUDIT_2026-08-22_MILESTONE_MM.md`'s
own recommendation now that the second multi-scenario assessment's
findings (Milestones JJ through MM) are fully worked through. This pass
used the two named-in-advance items from that recommendation plus a fresh,
direct code review of an area not touched by the recent JJ-MM chain (the
org-admin routes) — the "re-examine recently-landed/never-independently-
reviewed code directly" method that has repeatedly found real bugs this
initiative's own docs-scanning approach stopped finding around Milestone
CC.

---

## 1. Remaining `kronos-backend`/`celery-worker` `Config.Env` secret exposure — FIXED

**Finding.** A fresh, broader grep across every `SecretStr` field actually
declared in `src/config.py` (not just the DSN-shaped ones Milestone MM's
own grep caught) found four more real, still-plaintext secrets in
`docker-compose.prod.yml`'s `kronos-backend`/`celery-worker`
`environment:` blocks: `MINIO_SECRET_KEY`, `OPENSEARCH_PASSWORD`,
`KEYCLOAK_CLIENT_SECRET`, `VAULT_TOKEN`.

**Fix.** No `src/config.py` change needed — `secrets_dir` (added by
Milestone MM) already applies generically to any `Settings` field, not
just the four DSN ones it was originally added for. Verified directly:
a real Python-level `Settings()` call in this repo's dev venv resolved all
four correctly from real secrets_dir files before the compose file was
touched, and optional `SecretStr | None` fields (`splunk_hec_token`,
`sentinel_client_secret`, `defender_client_secret`) were confirmed to
degrade correctly (resolve to `None`, no crash) when neither an env var
nor a secrets_dir file is present — though those three are lower-value
(only relevant when that specific SIEM/EDR integration is configured) and
left as an explicit, not-yet-actioned follow-up rather than folded into
this pass.

Removed the four plaintext values from both services' `environment:`
blocks, added four `source:`/`target:` entries to each service's existing
`secrets:` block, and four new top-level `external: true` secrets.

**Real verification (not just Python-level).** An initial Docker-level
verification attempt appeared to fail — `Settings()` raised 8 validation
errors, every secrets_dir-backed field missing — traced immediately to a
stale `kronos-backend:dev` image (rebuilt during Milestone MM's own
"stale container" item, but *before* that same milestone's own
`secrets_dir` fix had actually been merged, so that image's `src/config.py`
simply predated the mechanism — confirmed directly via
`inspect.getsource(src.config)` inside that image). Rebuilt fresh from
current `HEAD` and re-ran: a real `Settings()` call inside the real,
freshly-built image resolved all four new fields (plus the four
already-fixed DSN fields) from real mounted secret files, and
`docker inspect --format '{{json .Config.Env}}'` showed zero occurrences
of any of the six distinct real secret values used in the test run.
`docker compose config` (dummy values for every referenced var) resolves
cleanly. Full suite unaffected (no `src/` change): 2025 passed, 2 skipped.

Full writeup: `poc/backend_prod_secret_config_env_exposure/README.md`'s
own "Extension (Gap Audit Milestone NN)" section (same PoC directory as
Milestone MM's original fix, since this is a direct continuation of the
same finding).

**Remaining, explicitly not fixed:** Keycloak's own `KC_DB_PASSWORD`/
`KC_ADMIN_PASSWORD` (the `keycloak` service itself). Checked against
Keycloak's own real, current documentation (server configuration guide +
container guide, for the pinned `quay.io/keycloak/keycloak:26.2`): no
`_FILE`-suffix or file-based secret convention exists for Keycloak's own
config system — its only documented secret-indirection mechanism is a
Java KeyStore (`--config-keystore`/`--config-keystore-password`), a
heavier, differently-shaped fix that still needs its own password
supplied somewhere. Left as a named, separate follow-up.

---

## 2. `invite_user`'s reuse path could silently fail to demote a user — FIXED

**Finding**, from a direct code review of `src/external/routes/admin.py`
(an area with no recent JJ-MM-chain touches): `POST /api/admin/org/
users/invite`'s own docstring claims that re-inviting an email that
already exists **and already belongs to the caller's org** gets the user
"reused and simply re-assigned the requested role" — but the actual
implementation called `_assign_realm_role()`, which only **adds** a role
mapping in Keycloak, never removes an existing one. `update_user_role`
(the dedicated `PATCH /users/{id}/role` endpoint) correctly calls
`_set_realm_role()` instead, which explicitly fetches current managed
roles, deletes the stale ones, then assigns the new one — proving the
correct helper already existed and was simply not used by `invite_user`.

**Concrete impact:** an org-admin attempting to demote an existing member
(e.g. re-inviting an `org-admin` with `role=read-only`, intending to
reduce their privilege) would silently leave that user with **both**
`org-admin` and `read-only` managed roles simultaneously — the user
remains a real, live org-admin, contradicting the operator's own intent
and the route's own documented contract. This is a genuine privilege-
retention bug, not merely a docstring inaccuracy: the operator has no
visible signal that the demotion didn't actually happen (the route
returns 201 with the *requested* role in its response body's `role`
field, which was accurate for what was *requested*, not what Keycloak
actually ended up with).

**Real, live verification before any fix** (CLAUDE.md §F): a Playwright/
browser-level repro would have required a full aal2 step-up flow just to
reach this route; instead, the actual Keycloak Admin REST API calls
`_assign_realm_role`/`_set_realm_role` themselves make were reproduced
directly against the real, running Keycloak 26.2.5, bypassing the
unrelated aal2 gate to isolate the actual question (does Keycloak's own
role-mapping API add or replace?). A real throwaway user was created in
the real `kronos-dev` org, assigned `org-admin`, then "re-invited" with
`read-only` using the exact add-only call shape `invite_user` used —
confirmed the user ended up with **both** roles. A follow-up step
applying `_set_realm_role`'s own explicit delete-stale-then-assign logic
to the same real user correctly left only `read-only`, proving this is a
real `invite_user`-specific bug, not a Keycloak API limitation. **8/8
checks passed** (`poc/admin_reinvite_role_escalation/`).

**Fix.** `invite_user` now calls `_set_realm_role` instead of
`_assign_realm_role`, matching `update_user_role`'s own correct semantics
— a re-invited user's managed role set is now authoritative (exactly the
requested role, nothing stale left over), for both the "new user" and
"reused existing member" paths (unconditionally, since a brand-new user
has no stale roles to remove, making this safe either way).

**Tests.** New `test_invite_user_reuse_path_replaces_role_not_just_adds_it`
in `tests/unit/test_admin_routes.py`: calls the real `invite_user` route
function directly (mocking only `_create_or_get_user`/`_add_org_member`/
`_assert_user_in_org`/`_set_realm_role`), asserting `_set_realm_role` is
called with the exact requested role and that `_assign_realm_role` is
never called directly from this path (an `AssertionError` trap if it
were) — a regression test that would have caught this bug immediately.

**Verification.** Full suite: **2026 passed, 2 skipped** (2025 + 1 new
test). `ruff`/`black`/`mypy` clean on both changed files.

---

## 3. `admin_connector_status.py`/`admin_integration_sources.py` reviewed, no new gap

Direct review of both sibling admin route files (read-only connector
status, and integration-source API-key provisioning/revocation).
Confirmed org-scoping is exclusively from `tenant.org_id`, never
client-supplied; the connector-status route's push/poll asymmetry is
handled honestly (no fabricated status for an unconfigured/unreachable
source); the integration-source-key routes correctly thread a matching
`resource_id` (`f"{source_type}:{sourceId}"`) between step-up ticket
mint-time expectation and consume-time check for both provision and
revoke, mirroring the same real security discipline Milestone JJ's
resource-mismatch fix established elsewhere. No new gap found.

## 4. `CorrelationSyncService`'s audit events could mis-attribute a cross-case correlation — FIXED

**Finding**, from the same direct-review pass extended into the security-
analytics correlation layer (`src/application/correlation_sync.py` — not
yet wired to any real route/beat task, an explicit, already-documented
scope decision from when Milestone F3 was originally built, not a new
gap): `_sync_one()`'s audit event always used `detection_a`'s own
`case_id`, even when the correlated pair's two detections belong to two
**different** cases — a real, plausible scenario, since case correlation
is only ever a best-effort parse of each finding's own `source_index`
(the same class of gap Milestone LL already fixed for
`ContainmentAction`/`DetectionSinkPushService`, just not yet extended to
this newer, not-yet-wired sync path).

**Fix.** The audit event's `case_id` is now `detection_a.case_id` only
when both sides agree; an honest `None` (never a guessed/first-wins
value) when they disagree — identical reasoning to
`DetectionSinkPushService`'s own multi-case-batch handling.

**Tests.** Two new tests in `test_correlation_sync.py`: same-case pair
correctly case-scopes the audit row; different-case pair correctly
leaves it `None`.

**Verification.** Full suite: **2028 passed, 2 skipped** (2026 + 2 new
tests). `ruff`/`black`/`mypy` clean (one `black` reformat needed on the
new code, applied and re-verified).

**Honest severity note:** since this code path has no real caller yet
(per F3's own documented scope), this fix has zero production impact
today — it is a correctness/consistency fix for when the feature is
eventually wired to a route or beat task, not an active bug being
exploited. Worth doing now specifically because it is small, mechanical,
and prevents the same class of gap from being (re)discovered later once
the feature does go live.

---

## Recommendation for the next wake-up cycle

1. **The lower-value optional SIEM/EDR secrets** (`splunk_hec_token`,
   `sentinel_client_secret`, `defender_client_secret`) confirmed to degrade
   safely with `secrets_dir` but not yet moved off plaintext
   `environment:` — a small, mechanical follow-up once/if those
   integrations see real production use.
2. **Keycloak's own `KC_DB_PASSWORD`/`KC_ADMIN_PASSWORD`** — no native
   file-secret convention exists; would need either a Java KeyStore
   (heavier, differently-shaped) or accepting this as a residual, smaller-
   blast-radius exposure (Keycloak itself, unlike `kronos-backend`, is not
   this platform's own code).
3. **Continue the direct-code-review method** that found items 2 and 4
   above — this pass covered `src/external/routes/admin.py` (full),
   `admin_connector_status.py`/`admin_integration_sources.py` (clean), and
   `src/application/correlation_sync.py`/`correlation_client.py` (one
   fix). The parser/ingestion layer
   (`src/application/parsing_orchestration.py`, the individual
   `src/external/parsers/*.py` modules) and the remaining OpenSearch
   adapters (`src/adapter/opensearch/*.py` beyond the correlation ones
   just reviewed) are the largest remaining areas with no recent
   independent review — real candidates for the next pass, per this
   initiative's own repeated finding that "code that has never been
   independently reviewed by anyone other than the agent who wrote it" is
   where new real bugs keep turning up.
4. **`CorrelationSyncService` itself is still unwired** (F3's own
   documented, deliberate scope decision — no route or beat task calls
   `sync_org_correlations` anywhere) — not a bug to fix, but worth
   revisiting if/when correlation data becomes a real product priority.
