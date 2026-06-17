# Part 6 Review — Identity, Authorization, and Single Sign-On (SSO)

- **Date:** 2026-06-16
- **Spec section reviewed:** `Project_Specifications.md` §6
- **Tracking issues:** #6 (category), #19 (today's review)
- **Branch:** `claude/zen-cerf-42v73y`

---

## 1. What the spec currently says

§6 is the oldest, unmodified narrative in the document. It still reads as a v0 sketch and has been overtaken on almost every concrete decision by the §1, §2, §4 and §5 reviews. Today's job is to lift §6 into a coherent integration spec that consumes those decisions rather than restating them or — worse — contradicting them.

What §6 currently proposes:

1. **Keycloak as the IdP**, deployed on-prem in a container.
2. **One realm**, with **Clients** for (a) the Web App / API and (b) OpenSearch Dashboards (OIDC RP via the OpenSearch Security plugin).
3. **Realm Roles**: `org-admin`, `case-lead`, `analyst`, `read-only`.
4. **Tenant model = Keycloak Groups** ("create a Group for each team … map a group membership into the token as a claim").
5. **Token settings**: access-token lifetime "12 h or a day", SSO Session Max 24 h, refresh-token rotation on.
6. **SSO flow**: redirect → login → ID + Access JWT.
7. **API authorization**: backend fetches Keycloak's JWKS, verifies RS256, checks `org` + `roles` on every call.
8. **OpenSearch Security**: `openid` auth domain in `config.yml`; `roles_key: roles`; references `cht42/opensearch-keycloak`.
9. **Role mapping**: 1-to-1 between Keycloak roles and OpenSearch roles; per-org index wildcards.
10. **Keycloak audit**: login + admin events enabled.

What is **already pinned elsewhere** and contradicts §6:

| Concern                              | §6 says                                  | Authoritative decision                                                                                                       |
| ------------------------------------ | ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Tenant model                         | Single realm + **Groups**                | §1: single realm + **Keycloak 26 Organizations** (Groups are *secondary*, not the tenancy boundary).                          |
| Access-token lifetime                | "12 h or a day"                          | §1: **15 min** access tokens; refresh-rotation with reuse detection; SSO Session Max 24 h.                                    |
| Roles claim layout                   | "set `roles_key` to `roles`" (implicit)  | §1: dedicated **`kronos-roles` client scope** with Realm-Role mapper, multivalued, top-level `roles` claim (OS `roles_key`-safe). |
| Token validation                     | Backend "checks roles"                   | §1: backend guard checks **`org_id` + permission matrix**, not just role names.                                              |
| OS Dashboards SSO                    | "Dashboards redirects to Keycloak"       | §4: OS Dashboards in an **iframe**, OIDC auth domain **first** in `config.yml`, `subject_key: preferred_username`.            |
| Per-case scoping                     | "index wildcards per org"                | §4: **one OS Dashboards tenant per org**, per-case scoping via locked URL filter on `kronos.case_id`, DLS belt-and-braces.     |
| Service-account permissions          | "calls Keycloak Admin REST API"          | §1: scoped via **Admin Fine-Grained Permissions** to the caller's Organization(s) only — never realm-wide admin.              |
| Audit destination                    | "Keycloak events enabled"                | §5: Keycloak events → **Wazuh SIEM** via the OpenSearch sink.                                                                 |

**Conclusion:** §6 is not wrong, it's stale. The reviews already moved every meaningful decision elsewhere; §6 needs to be re-cast as the **integration contract** that ties them together end-to-end: realm import, client manifests, mappers, the OS Dashboards OIDC handshake, the backend's JWT-validation pipeline, the SIEM event sink, and the federation hooks left out so far (LDAP/SAML upstream IdPs, MFA / step-up, backchannel logout).

---

## 2. Work already done in the repo

| Artifact                                                                          | Status                                                                                                |
| --------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `Project_Specifications.md` §6                                                    | Original v0 narrative, **not refreshed** by any prior review                                          |
| Keycloak realm export (JSON) — clients, scopes, roles, mappers                    | Not started                                                                                           |
| `opensearch_security/config.yml` snippet for the OIDC auth domain                 | Pattern referenced (`cht42/opensearch-keycloak`); no Kron-OS-specific YAML committed                  |
| `opensearch_dashboards.yml` snippet for the OIDC RP settings                      | Not started                                                                                           |
| Backend JWT-validation middleware (JWKS fetch, `kid`, `iss`, `aud`, `exp`, RBAC)  | Not started — design pinned by §1, no code                                                            |
| Keycloak event-listener → Wazuh sink                                              | Strategy pinned by §5 (Wazuh), wiring not specified                                                   |
| LDAP / SAML upstream IdP brokering (federation)                                   | Not started — flagged as the biggest open item in the §5 next-day plan                                |
| MFA / step-up authentication (ACR-based)                                          | §5 lists "mandatory MFA for org-admin" (A.8.5) but no flow                                            |
| OIDC backchannel logout                                                           | Not started                                                                                           |
| Session-lifetime hand-off table (access / refresh / SSO idle / SSO max / OS sess) | Partial — §1 sets access 15 min + SSO 24 h; nothing for the OS Dashboards / OS session pair           |

**Conclusion:** §6 is the integration glue, and the glue is still entirely on paper. The risk of drift between the (good) decisions in §1/§4/§5 and the (stale) wording in §6 grows with every passing review — we need to lock the integration contract now.

---

## 3. Feasibility research (state of the art, 2026)

### 3.1 Keycloak 26 Organizations — claim shape

Organizations is a stable first-class feature in Keycloak 26. When the `organization` scope is requested on a login, the token contains an `organization` claim that names the org(s) the user belongs to, **using the org alias as the key**, with attributes as sub-fields.[^kc-orgs-26][^skycloak-orgs] Example claim shape (Keycloak 26.6):

```jsonc
{
  "sub": "9c7f…",
  "preferred_username": "alice@acme.example",
  "organization": {
    "acme": { "id": "0f2c1f1c-…" }    // alias → { id, optional attributes }
  },
  "roles": ["analyst"]                 // flat, via the kronos-roles client scope (§1)
}
```

- Since 26.x users **can be members of multiple organizations** and tokens reflect all of them.[^kc-orgs-26][^skycloak-orgs] For Kron-OS v1 we still constrain this to a single org per user (§1), but the token shape must already accept the plural form — otherwise we re-write the backend the day we accept multi-org users.
- The org `id` (UUID) is the authoritative `org_id`. The `alias` is the human-readable index-name component (`kronos-{org_alias}-case-*`, per §1).
- The `organization` scope is **optional** at the realm level by default and added to clients by default — we will request it on every Kron-OS login.[^kc-orgs-26]
- **Organization Groups** (April 2026) give per-org hierarchical groups without naming clashes between orgs. We don't need them in v1 (the role set is small), but the existence of the feature confirms that Groups are the right *secondary* tool inside an org, not the tenancy boundary.[^kc-org-groups]

### 3.2 OpenSearch Security OIDC auth domain — the `roles_key` trap

The `cht42/opensearch-keycloak` reference confirms the minimal wiring:[^cht42-cfg][^cht42-dash]

```yaml
# opensearch-security/config.yml (excerpt)
authc:
  openid_auth_domain:
    http_enabled: true
    transport_enabled: true
    order: 0                       # MUST be first (challenge: false)
    http_authenticator:
      type: openid
      challenge: false
      config:
        openid_connect_url: https://idp.kronos.example/realms/kronos/.well-known/openid-configuration
        subject_key: preferred_username
        roles_key: roles           # MUST match the flat, multivalued claim from §1
    authentication_backend:
      type: noop
```

```yaml
# opensearch_dashboards.yml (excerpt)
opensearch_security.auth.type: openid
opensearch_security.openid.connect_url: https://idp.kronos.example/realms/kronos/.well-known/openid-configuration
opensearch_security.openid.client_id: opensearch-dashboards
opensearch_security.openid.client_secret: <vault://transit/kronos/os-dashboards-client-secret>
opensearch_security.openid.base_redirect_url: https://app.kronos.example/dashboards
opensearch_security.openid.scope: "openid profile email roles organization"
```

- The OIDC auth domain **must be `order: 0`** with `challenge: false`; basic auth (for internal probes) goes after.[^os-jwt][^os-troubleshoot] If `basic_internal_auth_domain` is first, browser requests get a 401-Basic prompt instead of the OIDC redirect.
- `roles_key` cannot walk the default nested `realm_access.roles` path — the §1 `kronos-roles` client scope flattens roles to a top-level `roles` claim specifically to satisfy this.[^cht42-cfg][^os-jwt]
- `subject_key: preferred_username` is the right choice for Kron-OS audit trails. We do **not** use `sub` because the UUID is meaningless to a human reading an audit row, and Wazuh correlation across Keycloak / MinIO / OS / backend is easier on `preferred_username`.
- Nested-claim support for `subject_key` was tracked as an open feature in 2025 ([opensearch-project/security#5430][^os-issue-nested]) — until it lands, the flat shape is mandatory.

### 3.3 Backend JWT validation — JWKS cache, `kid`, rotation

- The backend validates each Bearer token using Keycloak's JWKS endpoint. The JWKS is cached on the backend; on a signature-verification failure with a known `kid`, the backend re-fetches once before declaring the token invalid.[^skycloak-jwt][^skycloak-jwks]
- Keycloak rotation: add a new key provider with higher priority; new tokens are signed with the new `kid` immediately, old keys stay in the JWKS endpoint until existing tokens expire.[^skycloak-jwks][^kc-key-rotation] The backend handles rotation transparently as long as the cache TTL is short enough (≤ 10 min) and the "re-fetch on miss" path is wired.
- Mandatory claim checks: `iss` must equal `https://idp.kronos.example/realms/kronos`, `aud` must include the backend's client_id, `exp` not past, `typ=Bearer`, and `alg=RS256` (or `ES256` once we rotate to ECDSA; **never** accept `alg=none`).[^skycloak-jwt-best]
- Token introspection (`/protocol/openid-connect/token/introspect`) is **not** used per request — it would add a Keycloak round-trip to every backend call. We rely on JWKS-local validation + short (15 min) access-token lifetime + refresh-token reuse detection for revocation.

### 3.4 SPA token storage — PKCE + HttpOnly refresh cookie

- The 2026 consensus for OIDC SPAs: **Authorization Code + PKCE** (no client secret), **access token in memory**, **refresh token in an HttpOnly + Secure + SameSite=Strict cookie** scoped to the backend origin.[^codercops-2026][^auth0-rt][^owasp-oauth2]
- Refresh-token **rotation** is on, with reuse detection (any second use of a previously consumed refresh token revokes the chain). This matches the §1 decision and is independently the 2026 baseline.[^auth0-rt][^codercops-2026]
- Practical wiring with Keycloak: `keycloak-js` v26 + PKCE; the SPA proxies refresh through the backend (`POST /auth/refresh`) which talks to Keycloak's token endpoint and rewrites the refresh token into the HttpOnly cookie. `keycloak-js`'s default "refresh token in localStorage" mode is **rejected** — localStorage is XSS-readable.

### 3.5 Service-account permissions — FGAP v2 + Organizations

- Before FGAP v2, granting an external service account the right to manage users inside one organization required `manage-realm` — i.e. the keys to the kingdom.[^kc-fgap-orgs][^kc-fgap-26-2]
- Keycloak 26.7.0 (May 2026) introduces **Organizations as an FGAP resource type**, with `manage` and `view` scopes per organization. The Kron-OS backend's Keycloak service account is bound to a permission whose resource is *the caller's organization* and whose scope is `manage`. The backend can therefore invite users, assign roles, and create groups *only* inside the Organization it represents.[^kc-fgap-orgs]
- Until 26.7 lands in our pin, the interim is the Authorization Services Policy on the `realm-management` client scoped via the `users` resource and a Group/Org membership policy — slower (~200 ms per call, as reported in issue #31519) but correct.[^kc-admin-slow]

### 3.6 LDAP / Active Directory federation

- Keycloak ships an LDAP/AD User Storage Provider out of the box; `LDAPS` mandatory, bind account managed in Vault, sync policy = weekly full + hourly changed.[^elest-fed][^young-ldap][^skycloak-ldap]
- **Edit mode** decision: `READ_ONLY` when AD/LDAP is the source of truth (the common enterprise case for Kron-OS, since clients keep their own directory), `UNSYNCED` during migrations.[^young-ldap]
- Federated users land in the realm under the federation provider; **mapping a federated user into a Kron-OS Organization is non-trivial** — Keycloak's Identity Provider Mapper now supports auto-assigning federated users to organization groups based on external claims (April 2026).[^kc-org-groups] For v1 we use a manual "add to organization on first login" workflow (Authentication Flow Required Action), and revisit auto-assignment when 26.7 is in.

### 3.7 SAML upstream IdP brokering

- Keycloak brokers SAML 2.0 IdPs out of the box; both SP-init and IdP-init flows; the inbound SAML assertion is mapped to Keycloak user/session attributes which then flow into the OIDC token Kron-OS consumes.[^phasetwo-broker][^skycloak-saml-bridge]
- A practical use case for Kron-OS: a managed-service customer arrives with Azure AD / Okta SAML; Keycloak federates upstream, the analyst experience inside the SPA is unchanged, and the Kron-OS Organization is bound to the IdP via an IdP Mapper that sets `organization` from a SAML attribute (e.g. `tenantId`).
- **Caveat:** IdP-initiated SAML with a `RelayState` that names a downstream OIDC client requires a Keycloak SPI; the **Phase Two `idp-initiated-relaystate`** extension is the reference and is reusable as-is.[^phasetwo-saml-okta]

### 3.8 Step-up authentication — ACR + MFA / passkeys

- OAuth 2.0 Step-Up Authentication (RFC 9470) lets the backend respond with `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="aal2"` for sensitive actions. The SPA replays the auth request with `acr_values=aal2`; Keycloak runs the second-factor flow; the new token's `acr` claim reflects the upgraded level.[^embesozzi-stepup][^kc-acr]
- Keycloak supports **WebAuthn / passkeys** as a first-class 2FA factor; passkey *autofill* (Conditional UI) is still an SPI add-on as of Keycloak 26.6.[^embesozzi-stepup][^embesozzi-workshop]
- For Kron-OS v1, the policy is:
  - `aal1` (password) for read-only and analyst sessions.
  - `aal2` (password + WebAuthn or TOTP) required for `org-admin`, for any `evidence.delete`, and for any `legal_hold.set|cleared`.
  - The backend's permission check is `permission_matrix[action] ∧ token.acr ≥ required_acr[action]`; step-up is triggered on the backend, not silently inside the SPA.

### 3.9 OIDC Backchannel Logout

- When an `org-admin` revokes a user, Keycloak fires an OIDC Backchannel Logout to every registered RP (backend, OS Dashboards) carrying a `logout_token` (JWT) the RP must verify.[^kc-bcl][^kc-logout-endpoint]
- Known gotchas (Keycloak 26.x):
  - The "Sign out all sessions" UI path does not always fire backchannel logout for every active client session — track [keycloak/keycloak#27342].[^kc-bcl-issue-27342]
  - An IdP alias containing a dot breaks the broker-user-ID lookup — avoid dots in our IdP aliases.[^kc-bcl-issue-42209]
  - There is no Admin REST API today to *enable* a client's backchannel logout URL; it must be set in the realm export JSON.[^kc-bcl-issue-45761]
- For Kron-OS we configure the backend client and the `opensearch-dashboards` client with `backchannel.logout.url` set; the backend invalidates its in-memory session cache and the OS Dashboards security plugin terminates the user's session.

### 3.10 Keycloak event-listener → Wazuh SIEM

- Keycloak has a built-in **event-listener SPI**; the community `keycloak-siem-spi` plugin emits one JSON-per-event line ready for ingestion.[^siem-spi][^yashpatel-wazuh]
- The Kron-OS wiring:
  1. Enable login + admin events in the realm; persist for 30 d in the Keycloak DB as defence-in-depth.
  2. Add a JSON event listener that writes to stdout in the canonical Wazuh format.
  3. Wazuh agent on the Keycloak host tails the log and forwards alerts into `wazuh-alerts-*` (§5).
  4. Custom Wazuh rule pack: failed logins, admin role grants, user deletions, IdP additions, `org-admin` impersonation, password resets out of hours.

### 3.11 Session lifetimes — end-to-end table

| Setting                              | Value (v1)            | Source                                                                       |
| ------------------------------------ | --------------------- | ---------------------------------------------------------------------------- |
| Access-token lifetime                | **15 min**            | §1; mitigates the cost of revocation latency without JWKS introspection.     |
| Refresh-token lifetime               | 24 h                  | Matches SSO session max; rotation on; reuse-detection on.                    |
| SSO session idle                     | 2 h                   | Analyst working session; below 24 h max.                                     |
| SSO session max                      | 24 h                  | §1.                                                                          |
| OS Dashboards session                | Aligned to OIDC token | OS Security validates each request against the JWT; no separate cookie max.   |
| Refresh-token rotation               | On                    | §1; OWASP 2026 baseline.                                                     |
| Refresh-token reuse detection        | On (full chain revoke)| §1.                                                                          |
| MFA (`acr=aal2`) for `org-admin`     | Required              | A.8.5; this review §3.8.                                                     |

---

## 4. Problems identified

### P1. §6 still names Groups, not Organizations, as the tenancy boundary
The text contradicts the §1 decision (Keycloak 26 Organizations). Anyone reading §6 first will implement a broken multi-tenancy.

### P2. §6 still proposes "12 h or a day" access tokens
The §1 decision is **15 min** with refresh-rotation. The spec is internally inconsistent and the longer lifetime is a hard "no" against §5 (revocation latency, mTLS-but-stolen-token risk).

### P3. `roles_key` pitfall is not mentioned in §6
The §1 fix (dedicated `kronos-roles` client scope with a multivalued realm-role mapper) is the *whole* reason OpenSearch Security finds the roles. §6 should reproduce the wiring or at least reference it; otherwise the OS Dashboards integration will fail silently with empty role mappings.

### P4. Service-account permissions are wide open
§6 says the backend "calls Keycloak's Admin REST API" with no constraint. Without FGAP-v2 scoping to the caller's Organization, a compromised backend = full realm takeover. The §1 decision committed to FGAP — §6 must show how.

### P5. No federation story
LDAP / Active Directory / SAML upstream IdPs are absent. Every enterprise prospect will ask for one. We can defer the *implementation* but not the *design*: pick brokering (Keycloak) over federation-of-realms (rejected).

### P6. No MFA / step-up plan
§5 lists "mandatory MFA for org-admin" (A.8.5) as a one-liner. The actual flow (ACR-based step-up, WebAuthn / TOTP factor, which actions trigger which level) is undefined and must live in §6.

### P7. No backchannel-logout plan
Revoking a fired analyst with no logout propagation leaves stale OS Dashboards sessions until token expiry. With 15-min access tokens that window is short, but the design must be explicit, especially because Keycloak's UI "sign out all" path is known to miss callbacks.

### P8. No Keycloak → Wazuh event sink wired
§5 said "Keycloak events go to Wazuh". §6 must say *how*: event-listener SPI, JSON format, Wazuh decoder, custom rules.

### P9. Session-lifetime table is split across reviews
§1 holds the access/refresh/SSO numbers; §4 holds OS Dashboards iframe/session; §6 should pull them together in one normative table so a reader does not have to triangulate.

### P10. No JWT validation pipeline spec for the backend
JWKS cache TTL, `kid` re-fetch on miss, `alg`-allowlist, claims-required list — all consensus 2026 patterns, none enumerated in §6.

### P11. No client-manifest list
We will have at least three OIDC clients (`kronos-spa`, `kronos-backend`, `opensearch-dashboards`), each with its own grant types, redirect URIs, default scopes, and post-logout URLs. None of this is currently in the spec.

### P12. Keycloak version pin is missing
We've assumed 26.6.x throughout the reviews; without a pin (and a CVE-watch policy aligned with §5's patch SLA) the integration matrix is unverifiable.

---

## 5. Plan to reach the objective — detailed

### 5.1 Realm topology

```
realm: kronos
├─ clients
│  ├─ kronos-spa             (public, PKCE, no secret, redirect=https://app.kronos.example/*)
│  ├─ kronos-backend         (confidential, client-credentials grant for Admin API)
│  ├─ opensearch-dashboards  (confidential, OIDC RP for OS Security)
│  └─ kronos-attest          (confidential, used by the §5 verifier CLI when run online; otherwise PAT)
├─ organizations             (Keycloak 26 Organizations — one per tenant)
│  ├─ acme                   (alias=acme, id=…)
│  └─ globex                 (alias=globex, id=…)
├─ realm roles
│  ├─ org-admin
│  ├─ case-lead
│  ├─ analyst
│  └─ read-only
├─ client scopes
│  ├─ kronos-roles           (Realm-Role mapper, multivalued, claim=roles, top-level)
│  ├─ organization           (built-in optional scope, requested on every login)
│  └─ openid profile email   (standard)
└─ authentication flows
   ├─ browser (with Conditional MFA: required if request includes acr_values=aal2 or user has role org-admin)
   ├─ direct grant (disabled for kronos-spa, allowed for service tooling only)
   └─ registration: disabled at realm level — invite-only, driven by backend
```

### 5.2 Client manifests (excerpt)

| Client                  | Type          | Flow             | Scopes (default)                          | Notes                                                                              |
| ----------------------- | ------------- | ---------------- | ----------------------------------------- | ---------------------------------------------------------------------------------- |
| `kronos-spa`            | public        | Auth Code + PKCE | `openid profile email roles organization` | redirect=`https://app.kronos.example/*`; post-logout=`/login`; **no client secret** |
| `kronos-backend`        | confidential  | client-credentials + token exchange | `roles organization`            | client secret in Vault; FGAP scope = `view-users`/`manage-users` of caller's Org   |
| `opensearch-dashboards` | confidential  | Auth Code        | `openid profile email roles organization` | client secret in Vault; backchannel logout URL set; logout URL `/dashboards/auth/logout` |
| `kronos-attest`         | confidential  | client-credentials | `openid roles`                          | used by `kronos-attest verify --online`; read-only audit role                       |

The clients land in a Helm-rendered Keycloak realm export (`realm-kronos.json`) checked into infra; secrets are rendered via Vault Agent at deploy time.

### 5.3 Token claim shape (canonical example)

```jsonc
{
  "iss": "https://idp.kronos.example/realms/kronos",
  "aud": ["kronos-backend"],
  "sub": "9c7f4e1a-…",
  "preferred_username": "alice@acme.example",
  "given_name": "Alice", "family_name": "Doe",
  "email": "alice@acme.example", "email_verified": true,
  "roles": ["analyst"],
  "organization": {
    "acme": { "id": "0f2c1f1c-…" }
  },
  "acr": "aal1",                       // upgrades to "aal2" on step-up
  "amr": ["pwd"],                       // ["pwd","webauthn"] after step-up
  "exp": 1750008900, "iat": 1750008000
}
```

The backend extracts `org_id = token.organization[*].id` (first entry for v1; loop over keys for v2 multi-org), `org_alias = key`, `roles = token.roles`, then evaluates the §1 permission matrix.

### 5.4 OpenSearch Security wiring (normative YAML)

```yaml
# opensearch-security/config.yml
_meta:
  type: "config"
  config_version: 2
config:
  dynamic:
    authc:
      openid_auth_domain:
        http_enabled: true
        transport_enabled: true
        order: 0
        http_authenticator:
          type: openid
          challenge: false
          config:
            openid_connect_url: https://idp.kronos.example/realms/kronos/.well-known/openid-configuration
            subject_key: preferred_username
            roles_key: roles
            jwt_clock_skew_tolerance_seconds: 30
        authentication_backend:
          type: noop
      basic_internal_auth_domain:
        http_enabled: true
        transport_enabled: true
        order: 1
        http_authenticator:
          type: basic
          challenge: true
        authentication_backend:
          type: internal
```

```yaml
# opensearch-security/roles_mapping.yml
kronos_org_admin:
  backend_roles: ["org-admin"]
kronos_case_lead:
  backend_roles: ["case-lead"]
kronos_analyst:
  backend_roles: ["analyst"]
kronos_read_only:
  backend_roles: ["read-only"]
```

```yaml
# opensearch_dashboards.yml
opensearch_security.auth.type: openid
opensearch_security.openid.connect_url: https://idp.kronos.example/realms/kronos/.well-known/openid-configuration
opensearch_security.openid.client_id: opensearch-dashboards
opensearch_security.openid.client_secret: ${KEYCLOAK_DASHBOARDS_SECRET}
opensearch_security.openid.base_redirect_url: https://app.kronos.example/dashboards
opensearch_security.openid.scope: "openid profile email roles organization"
opensearch_security.openid.logout_url: https://idp.kronos.example/realms/kronos/protocol/openid-connect/logout
opensearch_security.cookie.secure: true
opensearch_security.cookie.isSameSite: Lax
opensearch_security.multitenancy.enabled: true
opensearch_security.multitenancy.tenants.preferred: ["Private", "Global"]
```

### 5.5 Backend JWT validation pipeline

1. **Extract Bearer.** Reject unauthenticated requests at the gateway.
2. **JWKS lookup.** In-memory cache keyed by `(iss, kid)`; TTL 10 min; on `kid` miss, re-fetch JWKS once, then fail.
3. **Verify.** `alg ∈ {RS256, PS256}` (never `none`); `iss == https://idp.kronos.example/realms/kronos`; `aud` contains `kronos-backend`; `exp > now - 30s`; `nbf <= now + 30s`.
4. **Decode claims.** `org_id` from `organization[*].id`; `roles` from top-level `roles`; `acr` from claim; `preferred_username` for audit.
5. **Authorisation.** Look up `(verb, resource, role, acr)` in the §1 permission matrix; if `required_acr > token.acr`, return `401 insufficient_user_authentication` with `acr_values` hint (RFC 9470).
6. **Audit.** Write `audit_log` row per §1 with `who=preferred_username, when=now, action, resource, decision, ip`.

### 5.6 SPA OIDC wiring (`keycloak-js` v26)

- `init({ onLoad: 'check-sso', pkceMethod: 'S256', responseMode: 'fragment', useNonce: true, checkLoginIframe: false })`.
- Access token kept in memory (`keycloak.token`); refresh handled by a backend proxy `POST /auth/refresh`, which talks to Keycloak's token endpoint and rewrites the refresh token into an HttpOnly + Secure + SameSite=Strict cookie scoped to `/auth`.
- Silent refresh every (`token.exp - now - 60s`) seconds; on refresh failure, redirect to Keycloak login (preserves `returnTo`).
- Step-up: on `401 insufficient_user_authentication`, the SPA calls `keycloak.login({ acrValues: 'aal2', prompt: 'login' })` and replays the original request.

### 5.7 Service-account scope — FGAP v2

- Backend service account `kronos-backend` has **no realm-wide role**.
- For each Organization, a FGAP V2 permission grants `kronos-backend` the `manage` scope on the Organization resource matching the inbound caller's `org_id`.
- The backend rejects any Admin API call whose target user does not belong to the caller's Org *before* dispatching the call (defence-in-depth even if FGAP later misconfigures).
- Until 26.7 is pinned, we use the Authorization Services policy on `realm-management` with a "Group membership" policy mapping; rationalised to FGAP V2 once we pin 26.7.

### 5.8 Federation — LDAP / AD / SAML upstream

- **LDAP/AD:** built-in User Storage Provider, `READ_ONLY` edit mode, LDAPS only, bind credential in Vault. First-login mapper assigns the new user to the Organization derived from a configurable LDAP attribute (default: `o` or `department`).
- **SAML upstream IdP:** add via Identity Brokering; per-IdP mapper sets `organization` from a SAML attribute (e.g. Azure AD `tid`).
- **OIDC upstream IdP:** same brokering pattern (e.g. customer's Okta tenant); claim mapper translates the upstream claim into the Kron-OS `organization` shape.
- **Auto-assign to Org:** in 26.6 we use a Required Action "Confirm Organization" on first login (manual approval); in 26.7+ we use the new IdP-mapper auto-assignment.

### 5.9 MFA and step-up

| Action / role                                  | Required ACR |
| ---------------------------------------------- | :----------: |
| Login (any user)                               | `aal1`       |
| `evidence.upload`, `evidence.download` (analyst)| `aal1`       |
| `evidence.delete`                              | `aal2`       |
| `evidence.legal_hold.set` / `.cleared`         | `aal2`       |
| Any `org-admin` action                         | `aal2`       |
| Backend service account                        | n/a (no MFA on machine creds; mitigated by FGAP + Vault rotation) |

- WebAuthn (passkey) is the **preferred** second factor; TOTP (OATH) is the fallback for users without a roaming-authenticator-capable device.
- Enrolment: an org-admin enables WebAuthn for new users at invitation time; the first login forces enrolment if the user has no factor and the role requires it.

### 5.10 Backchannel logout

- Every client (`kronos-spa`, `kronos-backend`, `opensearch-dashboards`) sets `backchannel.logout.url`:
  - `kronos-backend` → `POST https://api.kronos.example/auth/backchannel-logout` — invalidates server-side session cache + revokes refresh-token chain.
  - `opensearch-dashboards` → the OS Security plugin's built-in endpoint.
  - `kronos-spa` does not register one (it has no server-side session); the backend's invalidation is the source of truth, SPA re-authenticates on next request.
- IdP aliases avoid dots (workaround for [keycloak/keycloak#42209][^kc-bcl-issue-42209]).
- Realm export JSON sets `backchannel.logout.session.required: true` for all confidential clients (workaround for [keycloak/keycloak#45761][^kc-bcl-issue-45761]).

### 5.11 Keycloak → Wazuh event sink

- Realm settings → Events → Save Events on for login + admin, retention 30 d.
- Event listener `jboss-logging` set to JSON output; or deploy `keycloak-siem-spi` plugin if the JSON-line shape is preferred.
- Wazuh agent on the Keycloak host tails the structured log; custom Wazuh decoder pack `kronos-keycloak.xml`.
- Detection rules:
  - 5 failed logins in 5 min for one user → medium.
  - Any `client.create` / `client.update` outside the GitOps deploy window → high.
  - Any `user.deletion` not preceded by an `audit_log` `user.purge` from the backend → high.
  - `org-admin` grant outside change window → high.
  - IdP added/modified → critical (potential federation tampering).

### 5.12 Logging / audit hand-off

- Every login (success or failure), every token issuance, and every admin event lands in the unified `audit_log` (§1) via a thin "Keycloak admin webhook → backend `/internal/admin/audit-event`" path, *plus* the SIEM sink (5.11). The `audit_log` row covers tenant traceability; the Wazuh sink covers detection and tamper-resistant cold archive (§5).

### 5.13 Milestones

| Milestone | Content                                                                                                            | Exit criterion                                                                                                |
| --------- | ------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------- |
| M6.1      | Realm export `realm-kronos.json` checked in: clients, roles, scopes, `kronos-roles` mapper, `organization` scope    | `kcadm.sh` import on a clean Keycloak gives a working OIDC login for a seed `org-admin`                       |
| M6.2      | Backend JWT-validation middleware + JWKS cache + `kid` re-fetch + claim validation                                  | Unit tests cover happy path + `alg=none` rejection + `kid` rotation + `aud` mismatch + `acr` insufficiency    |
| M6.3      | OpenSearch Security OIDC auth domain + `roles_mapping.yml` + Dashboards OIDC RP config                              | Browser SSO into Dashboards works without a second prompt; roles populated; per-tenant DLS enforced           |
| M6.4      | SPA `keycloak-js` PKCE wiring + backend `/auth/refresh` HttpOnly cookie proxy                                       | No access or refresh token visible to JS in DevTools; XSS sandbox test cannot steal credentials               |
| M6.5      | LDAP federation provider + first-login Org-mapping required action                                                  | A user in an external LDAP can log in and is auto-assigned to the right Kron-OS Organization                  |
| M6.6      | SAML upstream IdP broker + Azure AD test tenant                                                                     | An Azure AD user lands in Kron-OS with the right `organization` claim                                         |
| M6.7      | ACR / step-up on `evidence.delete` and `legal_hold.*` (RFC 9470)                                                    | Backend correctly issues `insufficient_user_authentication`; SPA replays with `acr_values=aal2` and succeeds  |
| M6.8      | WebAuthn factor enrolled and required for `org-admin`                                                               | A new `org-admin` cannot complete first login without enrolling a passkey                                     |
| M6.9      | OIDC Backchannel Logout wired for backend + Dashboards                                                              | Revoking a user from Keycloak terminates her Dashboards session within 30 s                                   |
| M6.10     | Keycloak event listener → Wazuh sink + custom decoder + rule pack                                                   | Sample failed-login burst triggers a Wazuh alert in < 60 s                                                     |
| M6.11     | FGAP V2 scoping of `kronos-backend` to the caller's Organization                                                    | Backend's Admin API call against a *different* org returns `403` from Keycloak                                |
| M6.12     | Session-lifetime hand-off table committed to §6 + verified end-to-end                                               | Auditor table reproduced from a fresh login; numbers match across SPA, backend, Dashboards, OS               |

Each milestone lands as its own PR referencing issue #6.

---

## 6. Open questions for the reviewer

1. **Keycloak version pin** — 26.6.2 (current GA at review time) or wait for 26.7 (FGAP-V2 Organizations)?
2. **Refresh-token transport** — HttpOnly cookie proxied via backend (preferred, §5.6) vs. `keycloak-js`'s default localStorage path (rejected here — confirm).
3. **WebAuthn vs TOTP** — passkey-only for `org-admin`, or always offer TOTP fallback?
4. **Step-up scope** — limit `aal2` to `evidence.delete` / `legal_hold.*` (this review's default), or extend to every `case.delete` and every `members.assign`?
5. **LDAP edit mode** — `READ_ONLY` (this review's default) or `UNSYNCED` for v1 to allow partial in-Keycloak attributes?
6. **First-login Org assignment** — manual required action (26.6) or wait for 26.7 IdP-mapper auto-assignment before shipping federation?
7. **Backchannel logout target shape** — backend endpoint vs. embed the OS Dashboards plugin's own URL? (We've picked both.)
8. **Keycloak audit retention in the IdP DB** — 30 d (this review) or longer? Wazuh + cold archive already give us 7 y per §5; do we keep the IdP DB lean?
9. **Service-account interim before FGAP V2 Orgs** — Authorization Services policy (slow) vs. one Keycloak Organization-scoped service account per Org (faster but more secrets to rotate)?
10. **`organization` claim shape evolution** — single-org for v1 but token shape already multi-org-ready. Confirm the backend reads it as a map and picks the first entry rather than hard-coding.
11. **SAML upstream — IdP-init vs SP-init** — accept IdP-init via Phase Two's `RelayState` SPI in v1, or SP-init only?
12. **Token-exchange grant** — needed for delegated calls (backend on behalf of user to a downstream service) or out of scope for v1?

---

## 7. Next-day plan

Part 6 is the last numbered section in `Project_Specifications.md` today. Tomorrow's run should:

1. **Open a new top-level §7 — Operations and Deployment** (CI/CD, IaC, Helm/Terraform, environments, on-call). Most of §5's milestones implicitly depend on it.
2. **Cross-section audit pass.** Walk the spec end-to-end now that every numbered section has been reviewed, look for unresolved cross-references (e.g. M6.5 ↔ §5 Vault secret store; M6.4 ↔ §4 Uppy cookie path) and either pin them or open a tracking issue.
3. **Open-question grand triage.** Each `§N Open questions` block now totals ~50 items; group by *blocking M1.x* vs *defer to v2* and produce a single `OPEN_QUESTIONS.md` so the project lead has one list to walk.

---

## References

[^kc-orgs-26]: [Multitenancy in Keycloak Using the Organizations Feature — Skycloak](https://skycloak.io/blog/multitenancy-in-keycloak-using-the-organizations-feature/)
[^skycloak-orgs]: [Keycloak Multi-Tenancy with Organizations: The Complete Guide for SaaS — KeycloakPro](https://keycloakpro.com/blog/keycloak-multi-tenancy-organizations-guide)
[^kc-org-groups]: [Organization Groups: Structure Your Organizations with Hierarchical Group Management — Keycloak blog, Apr 2026](https://www.keycloak.org/2026/04/org-groups)
[^cht42-cfg]: [cht42/opensearch-keycloak — config.yml (OpenSearch Security OIDC auth domain)](https://github.com/cht42/opensearch-keycloak/blob/main/config.yml)
[^cht42-dash]: [cht42/opensearch-keycloak — opensearch-dashboards.yml (OIDC RP settings)](https://github.com/cht42/opensearch-keycloak/blob/main/opensearch-dashboards.yml)
[^os-jwt]: [OpenSearch — JSON Web Token authentication backend](https://docs.opensearch.org/latest/security/authentication-backends/jwt/)
[^os-troubleshoot]: [OpenSearch — Troubleshoot OpenID Connect](https://docs.opensearch.org/latest/troubleshoot/openid-connect/)
[^os-issue-nested]: [opensearch-project/security #5430 — Support subject key in a nested claim within JWT](https://github.com/opensearch-project/security/issues/5430)
[^skycloak-jwt]: [Keycloak Token Validation for APIs — Skycloak](https://skycloak.io/blog/keycloak-token-validation-for-apis/)
[^skycloak-jwks]: [Understanding JWKS: JSON Web Key Sets Explained — Skycloak](https://skycloak.io/blog/understanding-jwks-json-web-key-sets-explained/)
[^kc-key-rotation]: [Key Rotation — keycloak-nodejs-connect (DeepWiki)](https://deepwiki.com/keycloak/keycloak-nodejs-connect/4.2-key-rotation)
[^skycloak-jwt-best]: [JWT Token Validation Best Practices — Skycloak docs](https://skycloak.io/docs/tutorials/jwt-validation-best-practices/)
[^codercops-2026]: [OAuth 2.0 and PKCE: The Web Auth Patterns Every SPA Developer Needs in 2026 — CODERCOPS](https://www.codercops.com/blog/oauth2-pkce-jwt-web-auth-2026)
[^auth0-rt]: [What Are Refresh Tokens and How to Use Them Securely — Auth0](https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/)
[^owasp-oauth2]: [OAuth2 Cheat Sheet — OWASP](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
[^kc-fgap-orgs]: [Fine-Grained Admin Permissions for Organizations — Keycloak blog, May 2026](https://www.keycloak.org/2026/05/org-fgap)
[^kc-fgap-26-2]: [Achieving Fine-Grained Admin Permissions with Keycloak 26.2 — Keycloak blog](https://www.keycloak.org/2025/05/fgap-kc-26-2)
[^kc-admin-slow]: [Admin API extremely slow with service account and fine-grained authorization `view-users` — keycloak/keycloak #31519](https://github.com/keycloak/keycloak/issues/31519)
[^elest-fed]: [What is the User Storage Federation in Keycloak — elest.io](https://blog.elest.io/what-is-the-user-storage-federation-in-keycloak/)
[^young-ldap]: [Keycloak LDAP / Active Directory Integration — A Practical Guide to User Federation — youngju.dev, Jun 2026](https://www.youngju.dev/blog/devops/2026-06-12-keycloak-ldap-active-directory-federation.en)
[^skycloak-ldap]: [Keycloak LDAP User Federation Explained — Skycloak](https://skycloak.io/blog/keycloak-ldap-user-federation-explained/)
[^phasetwo-broker]: [Keycloak as an Identity Provider Broker (IdP) — Phase Two](https://phasetwo.io/docs/keycloak/idp/)
[^skycloak-saml-bridge]: [Bridging IdP-Initiated SAML to OIDC with Keycloak — Skycloak](https://skycloak.io/blog/bridging-idp-initiated-saml-to-oidc-with-keycloak/)
[^phasetwo-saml-okta]: [Keycloak SAML Identity Provider (IdP) Initiated Flow with Okta — Phase Two](https://phasetwo.io/blog/keycloak-saml-identity-provider-idp-initiated-flow-with-okta/)
[^embesozzi-stepup]: [Keycloak Step-Up and Multi-factor Authentication (MFA) for Web Apps and API — Martin Besozzi](https://embesozzi.medium.com/keycloak-step-up-authentication-for-web-and-api-3ef4c9f25d42)
[^embesozzi-workshop]: [Keycloak Workshop for Step-Up with MFA Biometrics Authentication (Passkeys) — Martin Besozzi](https://embesozzi.medium.com/keycloak-workshop-for-step-up-with-mfa-biometrics-authentication-passkeys-b7020ea9ae1b)
[^kc-acr]: [Keycloak 21 ACR Claim — Level of Authentication — Nivas Ganesan](https://medium.com/@nivas.ganesan/keycloak-21-acr-claim-level-of-authentication-743c3bd68596)
[^kc-bcl]: [Keycloak — LogoutEndpoint Javadoc (backchannel logout)](https://www.keycloak.org/docs-api/latest/javadocs/org/keycloak/protocol/oidc/endpoints/LogoutEndpoint.html)
[^kc-logout-endpoint]: [Keycloak Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/index.html)
[^kc-bcl-issue-27342]: [OIDC: Backchannel logout not being called when using Sign out all Sessions in Keycloak — keycloak/keycloak #27342](https://github.com/keycloak/keycloak/issues/27342)
[^kc-bcl-issue-42209]: [OIDC backchannel logout is broken if the Identity Provider alias contains a dot — keycloak/keycloak #42209](https://github.com/keycloak/keycloak/issues/42209)
[^kc-bcl-issue-45761]: [Configure OIDC Backchannel Logout for clients via Admin REST API — keycloak/keycloak #45761](https://github.com/keycloak/keycloak/issues/45761)
[^siem-spi]: [lspaulucio/keycloak-siem-spi — custom Keycloak event listener that sends events to an external SIEM](https://github.com/lspaulucio/keycloak-siem-spi)
[^yashpatel-wazuh]: [Monitoring Keycloak Events in Wazuh — A Complete, Working Integration Guide — Yash Patel](https://yashpateld22d.medium.com/monitoring-keycloak-events-in-wazuh-a-complete-working-integration-guide-a669817dc018)
