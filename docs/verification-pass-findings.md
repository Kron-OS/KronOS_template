# Verification-First Pass — Findings Summary and Remaining Task List

**Date:** 2026-07-22
**Scope:** Every bug found while executing CLAUDE.md Section F's verification-first PoC pass across the whole stack (Plaso, OpenSearch, MinIO, Vault/KES, Keycloak, Celery, RFC3161, Postgres, ClamAV, nginx, Helm/Kubernetes, OpenSearch Dashboards, frontend build). See `poc/*/README.md` for full per-pair detail; this document is the consolidated ledger plus what's left to reach a clean, error-free build.

---

## 1. Bugs found and fixed (shipped to `src/`/`docker/`/`charts/`/`scripts/`)

| # | Component | Bug | Commit |
|---|---|---|---|
| 1 | Plaso worker | Wrong `log2timeline`/`psort` binary lookup — parsing was a silent no-op | `db9133d` |
| 2 | Plaso worker | psort refused to write because the worker pre-created its output file | `db9133d` |
| 3 | Plaso → timeline | Forensic event timestamps silently replaced with ingest-time "now" | `db9133d` |
| 4 | `pyproject.toml` | Missing `opensearch-py[async]` extra (`AsyncOpenSearch` needs it) | `db9133d` |
| 5 | `RFC3161TimestampService.verify()` | Never successfully parsed a real TSA response (wrong ASN.1 assumptions); existing unit tests mocked the wrong shape | `e51c657` |
| 6 | `keycloak_auth.py` | JWT audience check silently bypassed by a token with no `aud` claim at all | `e51c657` |
| 7 | Vault → KES → MinIO SSE-KMS chain | Didn't work as configured (KES config schema, missing Vault policy grants, KES templating syntax) | `e51c657` |
| 8 | `wire_dependencies_async()` | Never wired `PostgresCaseRepository` — cases lived only in a process-local in-memory repo, losing all data on restart/across replicas | `110cca4` |
| 9 | `ensure_index_template()` | Defined three times, called nowhere — every OpenSearch index built by dynamic mapping instead of the ECS template, silently breaking exact-match `term` queries | `cfdde10` |
| 10 | `celery_app.py` `anchor_audit_log` | Computed "yesterday" via local server `date.today()` instead of UTC — wrong day whenever the server is ahead of UTC | `cfdde10`, `0a6ee04` |
| 11 | `kronos_attest/report.py` `day_report()` | `tsa_anchored` could never be `True` — filtered on `details.get("day")` but the stored key is `"date"`; an existing test had the same wrong key baked into its own fixture, so it never caught this | `0a6ee04` |
| 12 | `src/external/routes/step_up.py` | `POST /api/step-up/ticket` — the endpoint `DELETE /api/evidence/{id}`'s own docstring names as required — never existed anywhere; `issue_ticket()` had zero callers | `5e92110` |
| 13 | `src/adapter/opensearch/client.py` / `timeline_ingest.py` / `scripts/provision_keycloak_org.sh` / `docker/keycloak/kronos-realm.json` | `ensure_tenant_role()` created a per-org DLS role but nothing ever mapped a user to it — replaced with a verified, simpler generic-role + flat-`org_id`-claim design (see `poc/opensearch_jwt/`, `poc/keycloak_opensearch_dls/`) | `dd5f2cd` → `6d1a350` |
| 14 | `docker/nginx/nginx.conf.template` | Comment falsely claimed an unset CSP-origin var "safely" substitutes to empty string — real behavior is nginx **crashes at startup entirely** (`nginx: [emerg] unknown "..." variable`) | `122e0c3` |
| 15 | `charts/kronos/templates/nginx/` | nginx Deployment mounted a ConfigMap (`{fullname}-nginx-config`) that no template in the chart ever created — every real Kubernetes deployment would leave nginx (the sole DMZ/ingress layer) stuck in `ContainerCreating` forever, blocking all traffic | `122e0c3` |
| 16 | `docker/docker-compose.test.yml` | Bind-mounted `docker/keycloak/realm-export.json`, which never existed (only `kronos-realm.json` does) — the test stack's Keycloak never got a real realm | `ccb167d` |
| 17 | `docker/keycloak/kronos-realm.json` | **Self-introduced regression** (from fix #13, commit `6d1a350`): the new `kronos-org-id` client scope's description was 334 characters — over Keycloak's own `CLIENT_SCOPE.DESCRIPTION` `VARCHAR(255)` column limit. A real Keycloak import of the realm this repo ships **crashed outright** (`Value too long for column "DESCRIPTION"`) on H2 (`dev-mem`), which both `docker-compose.dev.yml` and `docker-compose.test.yml` use — meaning the real dev stack's Keycloak had been unable to import its own realm file since that commit. Found while fixing #16 by actually re-running the import against real Keycloak 26.0/26.2, not assumed. | `ccb167d` |
| 18 | `docker/docker-compose.test.yml` | Keycloak healthcheck was broken for three independent reasons, confirmed against a real container: no `KC_HEALTH_ENABLED` (health endpoints never register), `/health` lives on the management port 9000 not 8080, and the Keycloak 26 image ships no `curl` at all — the healthcheck could never pass. Replaced with the same real, working `bash /dev/tcp` probe `docker-compose.dev.yml` already used. | `ccb167d` |
| 19 | `src/external/fastapi_app.py` / `docker/nginx/nginx.conf.template` / `charts/kronos/templates/{backend,nginx}/deployment.yaml` | No `/healthz` or `/health` route existed anywhere in the backend (see flag G below — promoted from flagged to fixed). Added a real, dependency-free `GET /healthz`; pointed the backend Deployment's probes at it; added a separate nginx-only `/nginx-health` location (not proxied — avoids nginx's own pod being killed by a transient backend blip) and pointed the nginx Deployment's probes at that instead. | `34117af` |
| 20 | `tests/integration/test_auth_middleware.py` | `_NoopStorage` didn't implement `bucket_for`/`set_legal_hold` (see flag H below — promoted from flagged to fixed), causing 9 collection errors on every full-suite run. Implemented both; full suite is now 664 passed, 0 errors. | `41d51a6` |
| 21 | `docker/keycloak/kronos-realm.json` | **(flag A, promoted from flagged to fixed)** Step-up MFA was not actually conditional — every login forced mandatory TOTP regardless of requested `acr_values`; no `aal1` session could ever be issued. Root-caused by reading real Keycloak 26.2.0 source (`ConditionalLoaAuthenticator.matchCondition()`: with no prior LoA established, the level-2 condition always evaluates true). Fixed per Keycloak's own documented step-up pattern — added a first-level (`aal1`) conditional subflow containing the LoA(1) condition *and* the username/password form, ahead of the existing level-2/OTP subflow. Verified via real Admin REST API rebuild, then re-verified against the actual committed JSON file end-to-end (6/6 real PKCE logins: plain login → aal1, step-up login → aal2/real TOTP setup, repeat plain login for a now-TOTP-enrolled user → still aal1). Also standardized `docker-compose.test.yml` off Keycloak 26.0 onto 26.2 to match `docker-compose.dev.yml` and this fix's verified version, and re-confirmed the real compose service imports/health-checks cleanly. | *(this commit)* |

## 2. Bugs/gaps found and flagged, **not yet fixed**

| # | Component | Issue | Severity | Where found |
|---|---|---|---|---|
| B | `src/external/middleware/query_isolation.py` / `opensearch_isolation.py` | `QueryIsolationGuard`/`OpenSearchQueryBuilder` are dead code — zero real call sites in `src/` — despite `docs/subsystems/multi-tenancy.md` describing them as the "belt-and-braces" isolation layer. Needs a decision: wire them in for real, or remove them and correct the docs. | Medium | `poc/multi_tenancy/README.md` |
| C | OpenSearch Dashboards multi-tenancy | Design verified sound (`poc/opensearch_dashboards_tenancy/`), but production wiring (automated per-org tenant/role provisioning, Keycloak OIDC SSO for Dashboards) doesn't exist yet — only hand-provisioned in the PoC. | Medium | `poc/opensearch_dashboards_tenancy/README.md` |
| D | `docker/nginx/nginx.conf.template` `/silent-check-sso.html` | Real, documented nginx behavior: a location block with its own `add_header` doesn't inherit *any* `add_header` from the server level. This location's own CSP means it genuinely lacks `X-Frame-Options`/`X-Content-Type-Options`/HSTS. Low practical exposure (same-origin static file, own CSP already constrains framing) but confirms those headers were never actually verified globally. | Low | `poc/nginx/README.md` |
| E | `cases.py`'s Dashboards embed URL | Never specifies which index pattern Discover/Data Explorer should open (no `_a` app-state). Whether the real app falls back sensibly or shows nothing needs a live browser to observe — deferred to `poc/frontend_browser` (not yet done). | Medium (unverified, not confirmed broken) | `poc/dashboards_embed/README.md` |

## 3. New findings surfaced while compiling this document — **all now fixed** (see rows 16-20 above)

Findings F/G/H below were originally logged here as unfixed; all three (plus two more found in the process of actually fixing F) are now resolved — see rows 16-20 in section 1. Kept here for traceability of the original triage:

- **F** → fixed as row 16 (missing realm file).
- **G** → fixed as row 19 (missing health-check route).
- **H** → fixed as row 20 (`_NoopStorage` gap).
- **I** — lint/type debt — **still open**, not part of P0 (see task list): `ruff check src/` → 58 findings (mostly `N815` mixedCase — likely **intentional** camelCase Pydantic fields matching the frontend JSON contract, consistent with this branch's own name `fix/evidence-upload-camelcase`; the rest are `B008`/`B904`/`E501`). `mypy src/` → 187 findings across 16 files (missing type annotations, missing generic type args, a few `Any`-return leaks). Confirmed pre-existing — none of these files were touched by this verification pass's own edits.

## 4. Confirmed genuinely correct (no bugs found)

- MinIO Object Lock / WORM enforcement (`poc/minio/`)
- Celery ↔ Redis dispatch (`poc/celery_redis/`)
- Postgres audit hash-chain concurrency + tamper-detection (`poc/postgres/`)
- Real ClamAV EICAR scan through the full intake path (`poc/clamav/`)
- The four Celery beat tasks (`abort_orphan_uploads`, `abort_orphan_parses`, `auto_dispatch_received`, `anchor_audit_log`) against genuinely stale seeded rows (`poc/celery_beat/`)
- `cases.py`'s Dashboards embed URL's app path, RISON encoding, and `meta.index` handling, verified against the real pinned OpenSearch Dashboards 2.11.1 source (`poc/dashboards_embed/`)
- Frontend build: `npm install && npm run build` succeeds cleanly (`vite build`, 275ms), `npm run test` → 33/33 passed, `npm run lint` → 1 benign warning, 0 errors (checked while compiling this document)
- `docker compose -f docker/docker-compose.{dev,test,prod}.yml config` — all three parse without structural errors (only expected missing-`.env`-value warnings)
- `helm lint charts/kronos` — 0 charts failed (after fixing finding #15 above)

---

## 5. Task list — what's left to build the whole project cleanly

### P0 — blocks a real environment from actually starting — **DONE**
1. ~~Fix `docker-compose.test.yml`'s missing `realm-export.json`~~ — fixed (`ccb167d`); also fixed a self-introduced realm-import crash (row 17) and a broken Keycloak healthcheck (row 18) found while re-verifying this for real.
2. ~~Add a real health-check route to the FastAPI backend~~ — fixed (`34117af`): real `/healthz` on the backend, a separate nginx-only `/nginx-health` for nginx's own pod probe, both verified against real containers and the real Helm-rendered config.
3. ~~Fix `tests/integration/test_auth_middleware.py`'s `_NoopStorage`~~ — fixed (`41d51a6`). Full suite: **664 passed, 0 errors** (was 653 passed / 9 errors).

### P1 — real, open product/security gaps
4. ~~Make Keycloak's step-up MFA conditional on `acr_values`~~ (flag A) — **DONE**, see row 21 above and `poc/auth_flow/step_up_conditional_fix/`.
5. **Decide the fate of `QueryIsolationGuard`/`OpenSearchQueryBuilder`** (flag B) — wire them in as real belt-and-braces isolation, or delete them and correct `docs/subsystems/multi-tenancy.md`.
6. **Wire OpenSearch Dashboards multi-tenancy into production** (flag C) — automate per-org tenant + role provisioning (mirroring `scripts/provision_keycloak_org.sh`'s pattern) and real Keycloak OIDC SSO for Dashboards.

### P2 — lint/type debt (CLAUDE.md's own checklist, may gate CI)
7. **Ruff**: add a `per-file-ignores` rule for the intentional camelCase Pydantic response fields (don't rename them — that's the exact bug this branch exists to avoid reintroducing), then fix the remaining genuine `B008`/`B904`/`E501` findings (finding I).
8. **Mypy**: dedicated typing pass across the 16 affected files (finding I) — mostly missing annotations and generic type arguments, not structural issues.

### P3 — remaining verification work (not bugs — unfinished PoCs)
9. **`poc/evtx_opensearch`** — real `system.evtx` sample ingested into real OpenSearch (never run).
10. **`poc/frontend_browser`** — real Playwright pass: `keycloak-js` login + the React app + the Dashboards iframe embed. This would also resolve flag E (which index pattern Discover actually opens) by direct observation instead of static analysis.

---

*Cross-reference: `poc/README.md` (per-PoC index), `poc/opensearch_jwt/README.md` + `poc/keycloak_opensearch_dls/` (the full multi-tenancy DLS arc), `poc/nginx/README.md`, `poc/dashboards_embed/README.md`, `poc/celery_beat/README.md` for full captured-output detail behind every row above.*
