# Part 1 Review — Users, Teams, and Access Control

- **Date:** 2026-04-20
- **Spec section reviewed:** `Project_Specifications.md` §1
- **Tracking issues:** #1 (category), #7 (today's review)
- **Branch:** `claude/zen-cerf-A62p8`

---

## 1. What the spec currently says

The spec proposes:

1. A multi-tenant SaaS with **data segregation per team/organization**.
2. **RBAC with four roles** scoped per tenant: Org Admin, Case Lead, Analyst, Read-Only.
3. Every data object carries a `tenant_id` / `org_id` attribute, always re-checked on the backend.
4. OpenSearch isolation via **one index (or index prefix) per tenant/case**, e.g. `org1-case-*`, with Keycloak roles mapped 1-to-1 to OpenSearch roles.
5. Each user belongs to **one team at a time** (no multi-org users for v1).
6. Team administration is delegated to Keycloak (groups or custom model), wrapped by a thin admin UI that calls the Keycloak Admin REST API.
7. SSO via Keycloak — the JWT carries `org`, `roles`, plus identity.

---

## 2. Work already done in the repo

| Artifact                     | Status                                                                        |
| ---------------------------- | ----------------------------------------------------------------------------- |
| `Project_Specifications.md`  | Narrative description only, no data model, no diagrams                        |
| Code                         | None — template repository                                                    |
| Keycloak realm export        | None                                                                          |
| OpenSearch security config   | None                                                                          |
| Tests / CI                   | None                                                                          |

**Conclusion:** §1 is at the "intent / outline" stage. No implementation yet; the review has to focus on design feasibility.

---

## 3. Feasibility research (state of the art, 2026)

### 3.1 Keycloak multi-tenancy

The spec picks **single-realm + Keycloak Groups** to represent orgs. This was the standard community recipe until 2024, but the ecosystem has moved on:

- **Keycloak 26 (GA) ships the first-class `Organizations` feature.** Organizations were introduced as tech preview in 25 and are fully supported in 26.[^keycloak-orgs-blog][^skycloak-orgs] Each organization lives inside one realm, gets its own membership lifecycle, invitation flow, and — most importantly for us — produces a dedicated `organization` claim in the access token when the `organization` scope is requested.[^keycloak-orgs-medium]
- **Groups remain useful but address a different problem.** Groups express role/permission hierarchies; Organizations express tenant membership and auth routing. They compose rather than replace each other.[^phasetwo][^skycloak-orgs]
- **Realm-per-tenant does not scale.** Keycloak itself documents performance degradation beyond ~100 realms, and the operational cost of duplicating client/flow/theme configuration per tenant is significant.[^skycloak-mt][^phasetwo]
- **Regulatory data isolation caveat.** Organizations still share the realm user store. If a customer ever demands a hard "your user records must live in a separate database from mine" guarantee, only separate realms (or separate Keycloak installations) satisfy that.[^skycloak-orgs]

### 3.2 OpenSearch RBAC with Keycloak JWT

- The Security plugin can consume Keycloak-issued JWTs directly via the `openid` authentication domain, with a `roles_key` pointing at the JWT claim that holds roles.[^os-security-repo][^dev-to]
- **Known pitfall:** Keycloak's default realm-roles mapper emits the roles claim nested under `realm_access.roles`, which the Security plugin's `roles_key` does not walk. A widely used workaround is to add a **client scope mapper with "Multivalued" enabled and a flat claim name** (e.g. `roles`) — otherwise role mapping silently fails.[^os-security-issue-476][^forum-oidc-mapping]
- **Per-tenant index pattern (`org1-case-*`) is viable**, but naive "one index per case" explodes shard count. OpenSearch recommends ≤ 1 000 shards per 16 GB of heap and ≤ 30 000 shards per domain; small cases at 1 GB each would produce many near-empty shards with heavy metadata overhead.[^os-shards][^opster]
- **Dashboards multi-tenancy is an independent feature** (personal/private/global tenants for saved objects) and should not be conflated with the org isolation we want at the index level.[^os-mt-docs]

### 3.3 ISO 27001 Annex A / 2022 control mapping

- `A.5.15` / `A.9.1` (ISO 27001:2013 numbering) explicitly asks for RBAC with **least privilege** and logged access decisions — both successful and denied.[^dataguard-a9][^isms-a9]
- Forensic-grade audit trail of logons/logoffs is required; Keycloak's event listener will be enabled and streamed off the node.
- Separation of duties between Org Admin and Case Lead aligns with `A.5.3`.

---

## 4. Problems identified

### P1. The spec is already behind the Keycloak state-of-the-art
Using only Groups to represent orgs re-implements what the `Organizations` feature now provides natively (invites, membership, org-scoped login, org claim). Keeping the Groups-only design means we will write and maintain code that Keycloak 26+ ships for free, and we lose a standard `organization` JWT claim that OpenSearch and future integrations will expect.

### P2. No agreed data model
The spec talks about "tenant_id on every object" but never commits to: table schema, migration tool, how tenant_id is propagated through Celery tasks, how it is enforced in OpenSearch queries (document-level security vs index-per-tenant vs both).

### P3. Index topology is unspecified and likely to hit OpenSearch shard limits
"index-per-case" is mentioned casually. With small teams creating many short-lived cases, this produces a shard-count blow-up. We need an explicit strategy:
- **alias + template** per org,
- ILM/ISM rollover policy,
- reasonable default primary/replica counts (likely 1/1 for on-prem v1).

### P4. Role-to-permission matrix is prose, not a table
"Analyst can work on cases they are assigned to" — but "assigned" is not defined. There is no matrix mapping (role × verb × resource) → allow/deny, which is exactly what reviewers and auditors expect for ISO 27001.

### P5. `roles_key` JWT mapping gotcha not acknowledged
The spec assumes "Keycloak roles map 1-to-1". In practice, the default claim path (`realm_access.roles`) is not consumed by OpenSearch Security's `roles_key` without an explicit flat/multivalued mapper. If we skip this, all OpenSearch calls will be unauthenticated or collapse to the default role.

### P6. Single-org-per-user is fine for v1 but there is no migration story
The spec says "no multi-org users for v1" but does not plan how to extend the schema (e.g. join table `user_org_role`) without a disruptive migration later.

### P7. Org-Admin actions against Keycloak Admin API are not isolated
An Org Admin calling a backend that then hits the Keycloak Admin API is a privilege-escalation hotspot: we must scope the backend's Keycloak service account to only the orgs (Organizations) the caller actually administers, not grant it realm-wide admin.

### P8. Audit logging coverage is vague
§1 mentions logging "denied requests"; no commitment to format, storage, immutability, or how it flows into the existing Chain-of-Custody log defined in §2.

---

## 5. Plan to reach the objective — detailed

### 5.1 Identity model (Keycloak)

1. **Single realm** `kronos`.
2. **Adopt the `Organizations` feature** (Keycloak ≥ 26) to represent each customer tenant. Each Organization holds:
   - a stable `id` (UUID) — this becomes the authoritative `org_id`,
   - a human `alias` used in OpenSearch index names (`kronos-${alias}-case-${case_id}`),
   - its own invite flow and (optionally) its own identity provider.
3. **Four realm roles**: `org-admin`, `case-lead`, `analyst`, `read-only`. Roles are *global definitions*; scoping is provided by the `organization` claim in the token.
4. **Client scopes:**
   - Request the built-in `organization` scope → token carries an `organization` claim with the tenant's `id` + `alias`.[^keycloak-orgs-medium]
   - Add a custom client scope `kronos-roles` with a **Multivalued** Realm-Role mapper flattened to the top-level `roles` claim (mandatory workaround for OpenSearch Security `roles_key`).[^os-security-issue-476]
5. **Token lifetime:** access 15 min, refresh 24 h with rotation + reuse detection. (Revision of the spec's "12–24 h access token" which is too long.)
6. **Service accounts:**
   - `kronos-backend` client_credentials account, scoped to read-only on the Keycloak Admin API, with a fine-grained permission per Organization (requires `Admin Fine Grained Permissions` feature) so it can only list/invite users within an Organization that the calling Org Admin belongs to.

### 5.2 Application data model (SQL)

```sql
CREATE TABLE org (
  id          UUID PRIMARY KEY,      -- matches Keycloak Organization.id
  alias       TEXT UNIQUE NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  retention_days INT NOT NULL DEFAULT 365
);

CREATE TABLE app_user (
  id          UUID PRIMARY KEY,      -- matches Keycloak user sub
  org_id      UUID NOT NULL REFERENCES org(id),
  email       CITEXT UNIQUE NOT NULL,
  role        TEXT NOT NULL CHECK (role IN ('org-admin','case-lead','analyst','read-only')),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE case_ (
  id          UUID PRIMARY KEY,
  org_id      UUID NOT NULL REFERENCES org(id),
  name        TEXT NOT NULL,
  lead_user_id UUID REFERENCES app_user(id),
  created_at  TIMESTAMPTZ NOT NULL,
  UNIQUE(org_id, name)
);

CREATE TABLE case_member (
  case_id     UUID REFERENCES case_(id) ON DELETE CASCADE,
  user_id     UUID REFERENCES app_user(id) ON DELETE CASCADE,
  role        TEXT NOT NULL CHECK (role IN ('case-lead','analyst','read-only')),
  PRIMARY KEY (case_id, user_id)
);
```

- Every query is pre-scoped by `org_id` through a **middleware** that injects `SET app.current_org = :org_id` so we can later enable **Postgres Row-Level Security** without touching queries. (v1: enforced in the ORM; v2: RLS enabled.)
- `case_member` keeps Case-Lead / Analyst / Read-Only mapping *per case*, decoupled from the top-level realm role (which only says "what this user is allowed to be").

### 5.3 Permission matrix (authoritative)

| Verb / Resource           | org-admin | case-lead (of case) | analyst (member) | read-only (member) |
| ------------------------- | :-------: | :-----------------: | :--------------: | :----------------: |
| Create case               |     ✔     |          ✔          |         ✘        |          ✘         |
| Assign members            |     ✔     |          ✔          |         ✘        |          ✘         |
| Upload evidence           |     ✔     |          ✔          |         ✔        |          ✘         |
| Read evidence metadata    |     ✔     |          ✔          |         ✔        |          ✔         |
| Download original file    |     ✔     |          ✔          |     ✔ (logged)   |      ✘ (v1)        |
| Search timeline (OS)      |     ✔     |          ✔          |         ✔        |          ✔         |
| Delete case/evidence      |     ✔     |          ✔          |         ✘        |          ✘         |
| Manage org users          |     ✔     |          ✘          |         ✘        |          ✘         |
| View audit log            |     ✔     |        ✔ (own)      |         ✘        |          ✘         |

Encoded as a decorator/policy layer on top of FastAPI (or equivalent) and, in parallel, as OpenSearch roles (see 5.4).

### 5.4 OpenSearch topology & role mapping

1. **Index naming:** `kronos-{org_alias}-case-{case_id}-{yyyymm}`.
2. **Write path:** an **alias** `kronos-{org_alias}-case-{case_id}` plus an **ISM rollover** policy (size 30 GB or 30 days) — avoids the shard explosion documented in [^os-shards].
3. **Template:** 1 primary / 1 replica for on-prem v1, `codec: best_compression`, `refresh_interval: 30s` (acceptable for forensic workloads).
4. **Security roles** (defined in `roles.yml`, mapped from JWT in `roles_mapping.yml`):

   | OpenSearch role            | Index pattern                 | Allowed actions |
   | -------------------------- | ----------------------------- | --------------- |
   | `kronos_org_admin`         | `kronos-{alias}-*`            | read/write/manage |
   | `kronos_case_lead`         | `kronos-{alias}-case-*`       | read/write |
   | `kronos_analyst`           | `kronos-{alias}-case-*`       | read, limited write (annotations) |
   | `kronos_read_only`         | `kronos-{alias}-case-*`       | read |

   Mapping is driven by **both** the `roles` claim *and* the `organization.alias` claim — we use `dls` (document-level security) as a defence-in-depth filter on `tenant_id`.
5. **JWT ingestion config** (`config.yml`):
   ```yaml
   openid_auth_domain:
     http_authenticator:
       type: openid
       config:
         openid_connect_url: https://keycloak/realms/kronos/.well-known/openid-configuration
         subject_key: preferred_username
         roles_key: roles           # flat claim, mandated by mapper workaround [^os-security-issue-476]
   ```

### 5.5 API boundaries (FastAPI sketch)

- `POST /orgs` — platform-admin only (rare).
- `POST /orgs/{id}/users` — Org Admin of that org; proxied to Keycloak Admin API using a *per-org* token acquired through Admin Fine Grained Permissions.
- `POST /cases` — Org Admin or Case Lead.
- `POST /cases/{id}/members` — Org Admin, or the case's own Case Lead.
- Every route runs through:
  1. JWT signature verification (JWKS cached for 10 min).
  2. `org_claim_guard(request, resource.org_id)` — denies cross-tenant access.
  3. `role_guard({allowed_roles})` — denies role mismatch.
  4. Audit write (`who`, `when`, `action`, `resource`, `decision`, `ip`).

### 5.6 Auditing / logging

- All access decisions (allow and deny) serialized as JSON into a **append-only Postgres table** `audit_log` (plus mirrored to an OpenSearch `kronos-audit-*` index with DLS restricting each org to its own rows).
- Schema re-used verbatim by §2 (Chain-of-Custody) — one canonical log format for the whole platform.
- Nightly cron: signed SHA-256 tree root of the day's log stored in `audit_log_anchor` (prep for §5 tamper resistance).

### 5.7 Incremental milestones

| Milestone | Content | Exit criterion |
| --------- | ------- | -------------- |
| M1.1 | Keycloak realm export + Organizations + `kronos-roles` scope | `curl` against `/token` returns JWT with both `organization` and flat `roles` claims |
| M1.2 | Postgres schema + migration tool (Alembic/Atlas) | `pytest` creates org, user, case with RLS off |
| M1.3 | FastAPI guard middleware + permission matrix tests | 100 % branch coverage of permission matrix |
| M1.4 | OpenSearch templates + `roles.yml` + mapping | CI test: analyst of orgA gets HTTP 403 on `kronos-orgB-case-*` |
| M1.5 | Org-admin UI (users CRUD) calling Keycloak Admin API | Manual E2E with two orgs, no cross-tenant leak |
| M1.6 | Audit log + daily anchor job | Audit entry exists for every allow/deny observed in M1.3 E2E tests |

Each milestone lands as its own PR referencing issue #1.

---

## 6. Open questions for the reviewer

1. Do we commit to **Keycloak ≥ 26** (Organizations feature) or stay on the older Groups-only model?
2. Is **single-realm multi-tenant** acceptable or do we already have customers that require hard user-store isolation (→ realm-per-customer)?
3. On-prem sizing: how many orgs, how many concurrent cases? Answer drives M1.4 ISM policy defaults.
4. Should Read-Only users be allowed to download the original evidence file (currently denied in v1 in the matrix above)?
5. Should audit log be mirrored to OpenSearch (easier search, but ties retention to OS cluster) or kept Postgres-only (immutable, slower to query)?

---

## 7. Next-day plan

Tomorrow's review should target **Part 2 — Evidence Intake and Chain of Custody**. The §1 audit-log schema defined above is a prerequisite and will be reused there.

---

## References

[^keycloak-orgs-blog]: [Support for Customer Identity and Access Management (CIAM) and Multi-tenancy — keycloak.org](https://www.keycloak.org/2024/06/announcement-keycloak-organizations)
[^skycloak-orgs]: [Multitenancy in Keycloak Using the Organizations Feature — Skycloak](https://skycloak.io/blog/multitenancy-in-keycloak-using-the-organizations-feature/)
[^skycloak-mt]: [Keycloak Multi-Tenancy: A Complete Guide — Skycloak](https://skycloak.io/blog/the-ultimate-best-guide-on-keycloak-multi-tenancy-part-1/)
[^keycloak-orgs-medium]: [Exploring Keycloak 26: Introducing the Organization Feature for Multi-Tenancy — A. Koserwal, Medium](https://medium.com/keycloak/exploring-keycloak-26-introducing-the-organization-feature-for-multi-tenancy-fb5ebaaf8fe4)
[^phasetwo]: [Understanding Multi-Tenancy Options in Keycloak — Phase Two](https://phasetwo.io/blog/multi-tenancy-options-keycloak/)
[^os-security-repo]: [opensearch-project/security — GitHub](https://github.com/opensearch-project/security)
[^dev-to]: [Connecting OpenSearch to Keycloak — DEV Community](https://dev.to/mikeyglitz/connecting-opensearch-to-keycloak-34ak)
[^os-security-issue-476]: [`roles_key` from Keycloak JWT tokens are ignored with openid_auth_domain — issue #476](https://github.com/opensearch-project/security/issues/476)
[^forum-oidc-mapping]: [Role mappings not working when using OIDC — OpenSearch forum](https://forum.opensearch.org/t/role-mappings-not-working-when-using-oidc/10594)
[^os-mt-docs]: [OpenSearch Dashboards multi-tenancy — docs](https://docs.opensearch.org/latest/security/multi-tenancy/multi-tenancy-config/)
[^os-shards]: [Optimize OpenSearch index shard sizes — opensearch.org](https://opensearch.org/blog/optimize-opensearch-index-shard-size/)
[^opster]: [OpenSearch Max Shards Per Node Exceeded — Opster](https://opster.com/guides/opensearch/opensearch-basics/opensearch-max-shards-per-node-exceeded/)
[^dataguard-a9]: [ISO 27001 Annex A.9 — Access Control, DataGuard](https://www.dataguard.com/blog/iso-27001-annex-a.9-access-control/)
[^isms-a9]: [ISO 27001 Annex A.9: Access Control — ISMS.online](https://www.isms.online/iso-27001/annex-a-9-access-control/)
