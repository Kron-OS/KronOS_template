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
| **OpenSearch 2.13** | HTTP basic (`admin`) | Per-tenant DLS roles (`kronos-tenant-<org_id>`) + backend `OpenSearchQueryBuilder` org filter | `src/adapter/opensearch/client.py`, `src/external/middleware/opensearch_isolation.py` |
| **OpenSearch Dashboards** | (intended) OIDC via Keycloak `opensearch-dashboards` client | (intended) DLS-backed tenancy | realm JSON client + iframe embed in frontend |
| **Postgres / Redis** | Username/password | Single application role | `docker-compose.*.yml` |

### Application-layer access control (backend) — what is actually implemented

The backend access-control core is **well built** and matches its tool versions:

- **JWT validation** (`keycloak_auth.py`): JWKS-cached, algorithm allow-list (`RS256`/`PS256`), issuer + audience + exp/nbf verified, 30 s clock skew. No introspection round-trip. ✔
- **Tenant extraction** (`_extract_tenant`): reads the Keycloak **Organization** claim shaped as
  `{"<org-alias>": {"id": "<uuid>", ...}}`. This **matches the Keycloak 26.2 organization-membership mapper output** when `addOrganizationId=true` (verified against the 26.2 docs — see §3). ✔
- **RBAC** (`rbac.py`): `requires_role(*roles)` FastAPI dependency, 403 on missing role. ✔
- **Query isolation** (`query_isolation.py` + `opensearch_isolation.py`): every Postgres/OpenSearch access is forced through an `org_id` equality check / `bool.filter` term. The OpenSearch DLS role body uses a **stringified** `dls` query, which is the **correct OpenSearch 2.13 Security API format** (verified — see §3). ✔
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
- Security plugin **enabled** in any environment that holds real tenant data.
- Per-tenant **DLS role** (`kronos-tenant-<org_id>`) **plus a role-mapping** binding it to the OIDC `organization` subject. A DLS role with no `rolesmapping` is inert.
- The backend must connect as a **non-superuser** (superusers bypass DLS).
- Dashboards must authenticate via the Keycloak `opensearch-dashboards` OIDC client and inherit the same DLS, because the Timeline tab embeds Dashboards **directly in the browser**, bypassing the backend's `OpenSearchQueryBuilder`.

### 2.5 KMS / secrets (Vault + KES)
- Production Vault runs as a **sealed server** with persistent storage and the `transit/` engine — **not** `-dev` mode (in-memory, auto-unsealed, root token).
- KES authenticates to Vault by AppRole; MinIO authenticates to KES by mTLS identity. ✔ (config shape correct)

---

## 3. Evaluation — gap analysis (version-verified)

Severity: **C**ritical / **H**igh / **M**edium / **L**ow.

### [C-1] OpenSearch Dashboards iframe bypasses all tenant isolation
- **Dev:** `docker-compose.dev.yml` sets `DISABLE_SECURITY_DASHBOARDS_PLUGIN=true` and `DISABLE_SECURITY_PLUGIN=true`.
- The frontend Timeline tab embeds Dashboards **in an iframe** (browser → `:5601` directly).
- With the security plugin disabled, that iframe can query **every** `kronos-*` index across **all** tenants. The backend's `OpenSearchQueryBuilder` org filter is never in the path.
- The Keycloak `opensearch-dashboards` OIDC client exists in the realm but is **not wired** to anything.
- **Impact:** cross-tenant evidence-timeline disclosure — the most serious finding.
- **Remediation (documented; infra change, not auto-applied):** enable the OpenSearch & Dashboards security plugins, configure the OIDC `openid` authc domain against the existing client, provision DLS role-mappings, and have the backend connect as a non-superuser. This requires standing up the security plugin (certs, `securityadmin`) and is tracked as a follow-up because it cannot be validated safely in this template environment.

### [C-2] OpenSearch DLS is provisioned but never enforced
- `OpenSearchClient.ensure_tenant_role()` `PUT`s `/_plugins/_security/api/roles/...`. With `DISABLE_SECURITY_PLUGIN=true` that endpoint **does not exist** → the call 404s. In `docker-compose.prod.yml` OpenSearch has **no** security config at all (it references `./opensearch/opensearch.yml`, **which does not exist in the repo**).
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
</content>
