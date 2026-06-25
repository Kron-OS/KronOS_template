# Multi-Tenancy and Identity Subsystem

Covers Keycloak Organizations, JWT validation, RBAC, and OpenSearch isolation.

## Keycloak Topology

Single realm `kronos`. Tenants are **Keycloak 26+ Organizations** — not Groups.

- Each Organization has a stable `id` (UUID) = `org_id` throughout the platform.
- Each Organization has a human `alias` = the component used in index names and bucket names.
- Groups may exist for sub-grouping within an org but are never the tenancy boundary.
- Realm-per-tenant is **rejected** (Keycloak performance degrades beyond ~100 realms).

## Token Claim Shape (Canonical)

```json
{
  "iss": "https://idp.kronos.example/realms/kronos",
  "aud": ["kronos-backend"],
  "sub": "9c7f4e1a-...",
  "preferred_username": "alice@acme.example",
  "roles": ["analyst"],
  "organization": { "acme": { "id": "0f2c1f1c-..." } },
  "acr": "aal1",
  "amr": ["pwd"],
  "exp": 1750008900
}
```

- `roles` is a **flat, top-level array** — produced by the `kronos-roles` client scope with a Multivalued Realm-Role mapper. Never rely on `realm_access.roles` (OpenSearch Security's `roles_key` cannot walk nested paths).
- `organization` is a **map keyed by alias**. For v1 the backend reads the first entry. The shape is multi-org-ready for v2.
- `acr` is `"aal1"` (password) or `"aal2"` (password + WebAuthn/TOTP after step-up).

## Session Lifetimes

| Setting | Value |
|---|---|
| Access token | **15 minutes** |
| Refresh token | 24 hours (rotation + reuse detection) |
| SSO session idle | 2 hours |
| SSO session max | 24 hours |
| MFA required for `org-admin` | Yes (`acr=aal2`) |

## Clients

| Client | Type | Notes |
|---|---|---|
| `kronos-spa` | public, PKCE | No client secret; redirect to `https://app.kronos.example/*` |
| `kronos-backend` | confidential, client-credentials | Secret in Vault; FGAP V2 scoped to caller's Org |
| `opensearch-dashboards` | confidential, Auth Code | Secret in Vault; backchannel logout URL set |
| `kronos-attest` | confidential, client-credentials | Read-only audit role |

## Backend JWT Validation Pipeline

1. Extract Bearer token. Reject unauthenticated requests at gateway.
2. JWKS cache: `(iss, kid)` → key, TTL 10 min. On `kid` miss: re-fetch once, then fail.
3. Verify `alg ∈ {RS256, PS256}` — **never accept `alg=none`**.
4. Verify `iss`, `aud`, `exp`, `nbf`, `typ=Bearer`.
5. Decode `org_id` from `organization[*].id`, `roles`, `acr`.
6. Check permission matrix. If `required_acr > token.acr` → return `401 insufficient_user_authentication`.
7. Write `audit_log` row for every access decision (allow and deny).

## Step-Up Auth (RFC 9470)

When the backend returns `401 insufficient_user_authentication`:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="aal2"
```

The SPA calls `keycloak.login({ acrValues: 'aal2', prompt: 'login' })` and replays the request.

Actions requiring `aal2`: `evidence.delete`, `evidence.legal_hold.*`, any `org-admin` action.

## RBAC Permission Matrix

| Action / Resource | org-admin | case-lead (of case) | analyst (member) | read-only |
|---|:---:|:---:|:---:|:---:|
| Create case | ✔ | ✔ | ✘ | ✘ |
| Assign members | ✔ | ✔ | ✘ | ✘ |
| Upload evidence | ✔ | ✔ | ✔ | ✘ |
| Read evidence metadata | ✔ | ✔ | ✔ | ✔ |
| Download original file | ✔ | ✔ | ✔ (logged) | ✘ |
| Search timeline (OS) | ✔ | ✔ | ✔ | ✔ |
| Delete case/evidence | ✔ | ✔ | ✘ | ✘ |
| Manage org users | ✔ | ✘ | ✘ | ✘ |
| View audit log | ✔ | ✔ (own) | ✘ | ✘ |

## OpenSearch Isolation

Primary: per-org index naming `kronos-{org_alias}-case-{case_id}-{yyyymm}`.

Belt-and-braces: DLS on `kronos.tenant_id` in every OpenSearch role.

One OS Dashboards tenant per org (`kronos-{org_alias}`) — not one per case (would explode `.kibana_*` shard count).

Per-case filtering uses a locked URL parameter on `kronos.case_id` injected by the SPA.

## Query Isolation Enforcement

Every Postgres query must include `org_id` in the WHERE clause. Every OpenSearch query must include `org_alias` in the index pattern. The `TenantContext` extracted from the JWT is the authoritative source for both.
