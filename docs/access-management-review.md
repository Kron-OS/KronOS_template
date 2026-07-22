# Access Management Review — KronOS

**Date:** 2026-06-29
**Scope:** Identity, authentication, authorization and tenant-isolation across **every application** in the KronOS stack (Keycloak, FastAPI backend, Celery workers, MinIO, KES, Vault, OpenSearch, OpenSearch Dashboards, tusd, Postgres, Redis).
**Method:** Source + configuration review, cross-checked against the **versioned** documentation of each tool (Keycloak 26.2, OpenSearch 2.13, MinIO/KES, Vault 1.17).

This document has three parts, as requested:

1. **Research** — how access is managed in each application today.
2. **Expected structure** — the target access-management design the project commits to (per `Project_Specifications.md` §5/§6 and `reviews/Part_5_Review.md`, `Part_6_Review.md`).
3. **Evaluation** — gap analysis with severity, version verification, and the fixes applied in this PR.

---

## 1. Research — current access model per application

| Application | Auth mechanism | Authorization model | Where configured |
|---|---|---|---|
| **Keycloak 26.2** | OIDC IdP (realm `kronos`) | Realm roles `org-admin` / `case-lead` / `analyst` / `read-only`; Organizations for multi-tenancy | `docker/keycloak/kronos-realm.json` |
| **FastAPI backend** | Bearer JWT, validated locally against Keycloak JWKS (`RS256`/`PS256`, no introspection) | `requires_role(...)` RBAC dependency + `TenantContext` (`org_id`) + step-up (RFC 9470, `aal2`) | `src/external/middleware/*` |
| **Celery workers** | Service-to-service; inherit backend env (DB, Redis, MinIO, Vault) | None of its own — trusts the broker | `docker/docker-compose.*.yml` |
| **MinIO** | Static access key / secret | Root credentials used by *all* clients | `docker-compose.*.yml`, `scripts/provision_buckets.sh` |
| **KES** | mTLS client identity | Policy `kronos-minio` scoped to `kronos-evidence*` keys | `docker/kes/kes-config.yml` |
| **Vault** | Token (dev) / AppRole (KES) | Transit engine `kronos-evidence` | `docker/docker-compose.prod.yml`, `docker/vault/*` |
| **OpenSearch 2.13** | HTTP basic (`admin`) | *(superseded — see note in §2.4)* generic DLS role (`kronos-generic-tenant`) templated on the flat JWT `org_id` claim | `src/adapter/opensearch/client.py`, `scripts/provision_keycloak_org.sh`, `docker/keycloak/kronos-realm.json` |
| **OpenSearch Dashboards** | (intended) OIDC via Keycloak `opensearch-dashboards` client | (intended) DLS-backed tenancy | realm JSON client + iframe embed in frontend |
| **Postgres / Redis** | Username/password | Single application role | `docker-compose.*.yml` |

### Application-layer access control (backend) — what is actually implemented

The backend access-control core is **well built** and matches its tool versions:

- **JWT validation** (`keycloak_auth.py`): JWKS-cached, algorithm allow-list (`RS256`/`PS256`), issuer + audience + exp/nbf verified, 30 s clock skew. No introspection round-trip. ✔
- **Tenant extraction** (`_extract_tenant`): reads the Keycloak **Organization** claim shaped as
  `{"<org-alias>": {"id": "<uuid>", ...}}`. This **matches the Keycloak 26.2 organization-membership mapper output** when `addOrganizationId=true` (verified against the 26.2 docs — see §3). ✔
- **RBAC** (`rbac.py`): `requires_role(*roles)` FastAPI dependency, 403 on missing role. ✔
- **Query isolation**: every Postgres repository scopes its own query by `org_id` in the `WHERE` clause (e.g. `PostgresCaseRepository.get_by_id`) — real, in the request path. OpenSearch isolation is enforced server-side via DLS on the flat JWT `org_id` claim (superseded design — see note in §2.4), not by an application-layer filter. `query_isolation.py`'s `QueryIsolationGuard` and `opensearch_isolation.py`'s `OpenSearchQueryBuilder` have **zero real call sites in `src/`** — they are unused scaffolding for a future direct backend search API that doesn't exist yet (correctly flagged as such, not as an active control, in `reviews/Static_Compliance_Pentest_Review.md` AUDIT-15). The OpenSearch DLS role body itself does use a **stringified** `dls` query, which is the **correct OpenSearch 2.13 Security API format** (verified). ✔
- **Step-up auth** (`step_up_auth.py`): RFC 9470 `insufficient_user_authentication` with `acr_values="aal2"`, one-time tickets, numeric ACR comparison. ✔

**Conclusion of research:** the *code* layer of access management is sound and version-correct. The defects are concentrated in the **deployment/configuration layer**, where the application's security assumptions are not actually satisfied by the infrastructure it runs on.

---

## 2. Expected structure — target access-management design

Derived from `Project_Specifications.md` §5 (Security & Compliance) / §6 (Identity) and the Part 5/6 reviews.

### 2.1 Identity & tenancy (Keycloak)
- One realm, Organizations = tenants, four realm roles. ✔ (already correct)
- Confidential clients hold secrets; **public** clients use PKCE and **never** enable Direct Access Grants (ROPC).
- Every defined client must correspond to a wired, used integration (no dangling clients).

### 2.2 Backend → dependency authentication
- The backend and Celery process must boot with a configuration that **exactly matches `src/config.py`** (a `pydantic-settings` model with **no defaults for required fields** — a missing var is a hard startup failure by design).
- The Keycloak JWT validator must be wired in **every** environment, or all authenticated requests fail closed.

### 2.3 Object storage least privilege (MinIO)
- **Per-service credentials**, not shared root:
  - `tusd` → write-only to the **upload/quarantine** bucket only.
  - backend → read/write evidence + quarantine buckets for its org scope.
  - root → break-glass only, never handed to a network-facing service.
- Evidence buckets remain WORM (Object Lock Compliance) + SSE-KMS via KES→Vault.

### 2.4 Timeline store isolation (OpenSearch + Dashboards)

> **Superseded (2026-07-22):** the per-org DLS role (`kronos-tenant-<org_id>`)
> design below was tried and found to require a nested `organization` JWT
> claim that OpenSearch's DLS templating cannot resolve. It was replaced
> with a single generic, org-agnostic role (`kronos-generic-tenant`)
> templated on a flat `org_id` claim, verified end-to-end against a real
> Keycloak 26.2 + OpenSearch 2.13 (including new orgs/members needing zero
> further OpenSearch-side provisioning). See `poc/opensearch_jwt/`,
> `poc/keycloak_opensearch_dls/`, and `docs/subsystems/multi-tenancy.md`
> for the current, accurate design; C-1/C-2 below describe the design that
> predates this fix.

- Security plugin **enabled** in any environment that holds real tenant data.
- Per-tenant **DLS role** (`kronos-tenant-<org_id>`) **plus a role-mapping** binding it to the OIDC `organization` subject. A DLS role with no `rolesmapping` is inert.
- The backend must connect as a **non-superuser** (superusers bypass DLS).
- Dashboards must authenticate via the Keycloak `opensearch-dashboards` OIDC client and inherit the same DLS, because the Timeline tab embeds Dashboards **directly in the browser**, which OpenSearchQueryBuilder (dead code — see §1 above) was never in the path for regardless.

### 2.5 KMS / secrets (Vault + KES)
- Production Vault runs as a **sealed server** with persistent storage and the `transit/` engine — **not** `-dev` mode (in-memory, auto-unsealed, root token).
- KES authenticates to Vault by AppRole; MinIO authenticates to KES by mTLS identity. ✔ (config shape correct)

---

## 3. Evaluation — gap analysis (version-verified)

Severity: **C**ritical / **H**igh / **M**edium / **L**ow.

### [C-1] OpenSearch Dashboards iframe bypasses all tenant isolation
- **Dev:** `docker-compose.dev.yml` sets `DISABLE_SECURITY_DASHBOARDS_PLUGIN=true` and `DISABLE_SECURITY_PLUGIN=true`.
- The frontend Timeline tab embeds Dashboards **in an iframe** (browser → `:5601` directly).
- With the security plugin disabled, that iframe can query **every** `kronos-*` index across **all** tenants. There is no backend-mediated filter in this path at all — `OpenSearchQueryBuilder` is dead code with zero real call sites (see §1 above), not a control that was merely bypassed here.
- The Keycloak `opensearch-dashboards` OIDC client exists in the realm but is **not wired** to anything.
- **Impact:** cross-tenant evidence-timeline disclosure — the most serious finding.
- **Remediation (documented; infra change, not auto-applied):** enable the OpenSearch & Dashboards security plugins, configure the OIDC `openid` authc domain against the existing client, provision DLS role-mappings, and have the backend connect as a non-superuser. This requires standing up the security plugin (certs, `securityadmin`) and is tracked as a follow-up because it cannot be validated safely in this template environment.

### [C-2] OpenSearch DLS is provisioned but never enforced
- `OpenSearchClient.ensure_tenant_role()` (since renamed `ensure_generic_tenant_role()` — see superseded note above) `PUT`s `/_plugins/_security/api/roles/...`. With `DISABLE_SECURITY_PLUGIN=true` that endpoint **does not exist** → the call 404s. In `docker-compose.prod.yml` OpenSearch has **no** security config at all (it references `./opensearch/opensearch.yml`, **which does not exist in the repo**).
- Even with the plugin on: the created role has **no `rolesmapping`**, so it binds to no user; and the backend connects as **`admin`** (superuser), which **bypasses DLS** entirely.
- The DLS query string itself is **correct** for OpenSearch 2.13 (the Security API expects `dls` as an escaped JSON string — verified against the 2.13 "Document-level security" / "API" docs), so the code is right; the environment is wrong.
- **Remediation:** same follow-up as C-1; the missing `docker/opensearch/opensearch.yml` and a non-superuser service account are the concrete artifacts to add.

### [H-1] Production backend & Celery cannot boot — env vars don't match `config.py`
`src/config.py` is a `pydantic-settings` model whose required fields have **no defaults** (intentional fail-fast). `Settings()` is instantiated at startup (`startup.py:35`) and at Celery import (`celery_app.py:21`). In `docker-compose.prod.yml` the backend/celery services:

| Required by `config.py` | Set in prod compose? |
|---|---|
| `OPENSEARCH_USERNAME`, `OPENSEARCH_PASSWORD` | ❌ missing |
| `KEYCLOAK_URL`, `KEYCLOAK_CLIENT_SECRET` | ❌ missing |
| `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND` | ❌ missing |
| `VAULT_URL` | ❌ set as `VAULT_ADDR` (wrong name) |
| `MINIO_ENDPOINT` = `minio:9000` (host:port) | ❌ set as `http://minio:9000` (scheme breaks `startup.py`, which prepends `http(s)://`) |
| `KEYCLOAK_ISSUER` / `KEYCLOAK_JWKS_URL` | ⚠ set but **not consumed** — the app derives the issuer from `KEYCLOAK_PUBLIC_URL` + `KEYCLOAK_REALM` |

**Impact:** `Settings()` raises `ValidationError` → backend and Celery crash on boot; and because `KEYCLOAK_URL` is unset, `app.state.keycloak_validator` is never registered, so even a booting backend would 500 every authenticated request (auth fails *open-to-error*, not gracefully). **Fixed in this PR** (see §4).

### [H-2] MinIO: shared root credentials, including for the upload front-door
- `backend`, `celery-worker`/`beat`, **and `tusd`** all use `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` (the superuser).
- `tusd` is the network-facing upload endpoint (`:1080`). A `tusd` compromise yields **full** object-store control, including the power to delete/alter WORM evidence and break chain-of-custody.
- No MinIO policies or service accounts are provisioned anywhere (`provision_buckets.sh` only creates buckets with root).
- **Remediation (documented):** create scoped MinIO service accounts (tusd = put-only on the upload bucket; backend = scoped to evidence/quarantine) and reference those keys instead of root. Provided as a concrete recommendation; not auto-applied because it requires a running MinIO to mint and verify the keys.

### [M-1] Keycloak `kronos-attest` is a public client with Direct Access Grants (ROPC)
- The realm defines `kronos-attest` as `publicClient: true` + `directAccessGrantsEnabled: true`.
- `kronos-attest` is, by its own code and docs (`kronos_attest/`, `src/cli/attest.py`), an **offline** verifier — it parses exported audit files and **never contacts Keycloak**.
- A public client with the password grant is dead config that only adds an ROPC credential-stuffing surface (OAuth 2.0 Security BCP deprecates ROPC).
- **Fixed in this PR:** `directAccessGrantsEnabled` set to `false` (see §4).

### [M-2] Production Vault runs in `-dev` mode
- `docker-compose.prod.yml` starts `hashicorp/vault:1.17` with `VAULT_DEV_ROOT_TOKEN_ID` / `VAULT_DEV_LISTEN_ADDRESS`. Dev-mode Vault is **in-memory, auto-unsealed, root-token, TLS-off** — unsuitable to hold the evidence master key that KES wraps DEKs against. On restart the `transit/` key is **lost**, which would render previously encrypted evidence undecryptable.
- **Remediation (documented + warning comment added):** run Vault as a sealed server with persistent storage; this PR adds an explicit warning in the compose file rather than an unverified server rewrite.

### [L-1] Realm ships plaintext client secrets / user passwords
- `kronos-backend-secret`, `opensearch-dashboards-secret` and dev user passwords live in the committed realm JSON. Acceptable for a *dev import*, but the file is the only realm definition and carries no "override in prod" guard. Documented; production must inject secrets and rotate.

### Version-verification summary
| Claim checked | Result |
|---|---|
| Keycloak 26.2 organization claim shape `{alias:{id}}` matches `_extract_tenant` | **Confirmed** — 26.2 org-membership mapper with `addOrganizationId=true` emits exactly this. Code is correct. |
| OpenSearch 2.13 Security API `dls` as escaped JSON string | **Confirmed** — `PUT _plugins/_security/api/roles/<name>` takes `dls` as a string. Code is correct. |
| OpenSearch superuser bypasses DLS | **Confirmed** — service must use a non-`admin` role for DLS to apply. |
| Vault `-dev` mode is in-memory/auto-unsealed | **Confirmed** — not for production KMS-of-record. |

---

## 4. Changes applied in this PR

Low-risk, statically-verifiable configuration corrections (the larger infra items in §3 are documented as tracked follow-ups because they need a running cluster to validate):

1. **`docker/docker-compose.prod.yml`** — backend & celery env vars realigned to the `config.py` contract:
   - added `OPENSEARCH_USERNAME/PASSWORD`, `KEYCLOAK_URL`, `KEYCLOAK_PUBLIC_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_CLIENT_ID`, `KEYCLOAK_CLIENT_SECRET`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`;
   - renamed `VAULT_ADDR` → `VAULT_URL`, added `VAULT_TOKEN` to celery;
   - fixed `MINIO_ENDPOINT` to host:port form + `MINIO_USE_TLS`;
   - removed the unused `KEYCLOAK_ISSUER`/`KEYCLOAK_JWKS_URL` pair;
   - added an explicit warning that Vault must not run in `-dev` mode and that MinIO/tusd must use scoped service accounts in production.

2. **`docker/keycloak/kronos-realm.json`** — `kronos-attest` client: `directAccessGrantsEnabled` → `false` (removes the unused ROPC surface on a public client).

3. **This document** — the access-management research, target structure, and evaluation.

### Not changed here (tracked follow-ups, need a live cluster to validate)
- C-1 / C-2: enable OpenSearch + Dashboards security plugin, add `docker/opensearch/opensearch.yml`, OIDC authc domain, DLS `rolesmapping`, non-superuser backend account.
- H-2: scoped MinIO service accounts for `tusd` and the backend.
- M-2: sealed production Vault server.

---

## 5. AUTH-001 remediation (2026-07-05) — `kronos-backend` service account de-scoped from realm-admin

**Finding (static compliance/pentest review, `reviews/Static_Compliance_Pentest_Review.md` AUTH-001):** the `service-account-kronos-backend` user was granted `realm-management: realm-admin` — full realm-wide administrative power (create/delete any client, any user, any role, read every realm setting) — for a service account that only ever needs to invite users, assign the four `org-admin`/`case-lead`/`analyst`/`read-only` realm roles, and add/remove Organization members.

**What changed in `docker/keycloak/kronos-realm.json`:**
- `service-account-kronos-backend`'s `realm-management` client roles are now `["manage-users", "view-users", "manage-realm", "view-realm"]` — still no `manage-clients`, `manage-authorization`, `manage-events`, `impersonation`, `create-client`, `view-clients`, `view-events`, or `query-*`. `manage-users`/`view-users` cover the plain `/users` endpoints (`POST /users`, `PUT/DELETE /users/{id}/role-mappings/realm`, `GET /users`, `GET /users?email=`).
- **Correction (2026-07-08, verified against a live Keycloak 26.2 instance):** the original version of this remediation assumed `manage-users`/`view-users` alone also covered the Organization endpoints (`GET/POST/DELETE /organizations/{id}/members`). That assumption was wrong — Keycloak models Organizations as realm-level configuration (alongside clients/identity-providers), so `OrganizationsResource` gates on the realm-scoped `manage-realm`/`view-realm` roles, not the user-scoped ones. Without them, every Organization member call (list, add, remove) returned 403, which broke the admin "manage users" page (member listing silently came back empty) and the invite flow (adding the new user to the org failed with 503) end-to-end. `manage-realm`/`view-realm` were added to restore that functionality on this Keycloak version.
- `kronos-backend`'s client now sets `authorizationServicesEnabled: true`, which is the prerequisite Keycloak flag for attaching Fine-Grained Admin Permissions (FGAP) once the deployment adopts Keycloak 26.7+. No `authorizationSettings` (resources/policies/permissions) block is populated in this static export — see "why this is a partial mitigation" below.

**Why this is only a partial mitigation (and what full remediation requires):**
Per `Project_Specifications.md` §6 and `reviews/Part_6_Review.md` §3.5/§5.7, the *complete* fix is Keycloak 26.7+'s FGAP V2 support for **Organizations as a resource type**, which lets a permission grant `manage` scope on *one specific Organization* to the service account — i.e. Keycloak itself refuses an Admin API call against a user in a different org. That requires:
1. Pinning Keycloak ≥ 26.7 (this realm currently targets the 26.6 interim, per `Part_6_Review.md` §3.5), and
2. A live Admin Console/API session to create the Organization-scoped permission, because FGAP resource/policy objects are assigned server-generated IDs at creation time — they cannot be hand-authored into a static realm-export JSON and re-imported deterministically (this is also why `AUTH-001`'s recommendation calls this "inherently a partial mitigation without live FGAP-on-Organizations").

Until then, the realm-level control is **coarse-grained least-privilege** (user and organization administration, not full realm admin) rather than **org-scoped** least-privilege. The org-scoping itself — rejecting an Admin API call whose target user is not a member of the caller's Organization — is enforced in the **application layer** instead: see `AUTH-003` remediation in `src/external/routes/admin.py` (`_assert_target_in_org` / the org-membership check added to `_assign_realm_role`, `_set_realm_role`, and `_find_user_by_email`). That check is the actual security boundary today; the Keycloak-side de-scoping from `realm-admin` to `manage-users`/`view-users`/`manage-realm`/`view-realm` is still defense-in-depth that shrinks the blast radius if the backend's own service credentials (or a bug in the application-layer check) are ever compromised — a compromised backend can no longer create/delete Keycloak clients, manage authorization/FGAP policies, or impersonate arbitrary users, but (same as before the org-scoping fix in `admin.py`) it can call `manage-users`/`manage-realm` endpoints across the whole realm; the app-layer check is what stops that from crossing org boundaries. `manage-realm` in particular means a compromised backend *can* now rewrite general realm settings (branding, brute-force/security-defenses config, token lifespans, etc.) — a real reduction from the previous `manage-users`-only blast radius, accepted here because Keycloak 26.2 has no narrower role that covers the Organizations API; revisit per the follow-up below.

**Follow-up tracked:** re-visit when the project pins Keycloak 26.7+ — replace the `manage-users`/`view-users`/`manage-realm`/`view-realm` client-role grant with an Organization-scoped FGAP V2 `manage` permission per `Part_6_Review.md` §5.7, provisioned via the Admin API (e.g. `charts/kronos/files/provision_keycloak_org.sh` or an equivalent bootstrap script) rather than the static realm export.
</content>
