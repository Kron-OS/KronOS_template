# Step 2 research: how to get a flat `org_id` claim out of Keycloak 26.2

**Not yet built/run — this is source-verified research only (Section F.2
step 2), pinning the exact approach before step 3 (a real Keycloak PoC).**

## Version pinned

`quay.io/keycloak/keycloak:26.2` (repo's own dev/prod compose files). Read
the real source at GitHub tag `26.2.0` (patch releases 26.2.1-26.2.16 exist
too; the mapper classes below are structural/config-driven, not the kind of
thing that changes patch-to-patch, so 26.2.0 is representative).

## Why the existing `oidc-organization-membership-mapper` can't do this

Read the actual mapper source:
`services/src/main/java/org/keycloak/organization/protocol/mappers/oidc/OrganizationMembershipMapper.java`
at tag `26.2.0`
(https://raw.githubusercontent.com/keycloak/keycloak/26.2.0/services/src/main/java/org/keycloak/organization/protocol/mappers/oidc/OrganizationMembershipMapper.java).

`resolveValue()`:
```java
if (!OIDCAttributeMapperHelper.isMultivalued(model)) {
    return organizations.get(0).getAlias();   // flat, but ALIAS only
}
Map<String, Map<String, Object>> value = new HashMap<>();
for (OrganizationModel o : organizations) {
    ...
    Map<String, Object> claims = new HashMap<>();
    if (isAddOrganizationId(model)) claims.put(OAuth2Constants.ORGANIZATION_ID, o.getId());  // "id", nested
    ...
    value.put(o.getAlias(), claims);          // keyed by alias -> nested map
}
```
`getEffectiveModel()` additionally **forces** `addOrganizationId=false` and
`addOrganizationAttributes=false` whenever `multivalued=false`. So there are
exactly two modes, and neither gives what's needed:
- `multivalued=false` → flat claim, but it's the org **alias** string, never the id.
- `multivalued=true` + `addOrganizationId=true` → the id exists, but nested
  one level inside a per-alias map (`{"<alias>": {"id": "<uuid>"}}` —
  matches what `poc/opensearch_jwt/README.md` result #2 already found
  unusable for DLS templating).

There is no configuration of this mapper that emits the org **id** as a
top-level flat claim. This isn't a config gap to work around — it's a hard
constraint of the shipped mapper class.

## Two theoretically-possible flat-id mechanisms, both rejected

1. **Script-based protocol mapper** (`oidc-script-based-protocol-mapper`,
   `ScriptBasedOIDCProtocolMapper.java`) — could read
   `session.getProvider(OrganizationProvider.class)` (or, more likely, the
   already-injected `organization` claim) and re-emit a flat field. Rejected:
   gated behind `Profile.Feature.SCRIPTS`, a `Type.PREVIEW` feature
   (`common/src/main/java/org/keycloak/common/Profile.java`) that is
   **disabled by default** and requires `--features=scripts` at Keycloak
   startup; and its execution path
   (`services/.../scripting/DefaultScriptingProvider.java`) resolves a
   `javax.script.ScriptEngine` via `ScriptEngineManager` by MIME type —
   Nashorn was removed from the JDK years ago, and the official Keycloak
   Quarkus distribution does not bundle a replacement JS engine by default.
   Untested whether it would even find an engine in this image; even if it
   did, enabling arbitrary server-side script execution as a preview
   feature for a compliance-focused forensic platform is a bad trade for
   what's otherwise a one-line config problem.
2. **Custom Java SPI protocol mapper** (a new class implementing
   `ProtocolMapper`/`OIDCAccessTokenMapper`, packaged as a provider JAR,
   deployed into the Keycloak image's `providers/` dir) — real, would work,
   but is genuine custom software (new build/deploy pipeline for the
   Keycloak image, a JAR to maintain and re-test on every Keycloak upgrade)
   for a problem standard Keycloak already solves without it (see below).
   Rejected as disproportionate.

## The verified, standard mechanism: User Attribute mapper

`services/src/main/java/org/keycloak/protocol/oidc/mappers/UserAttributeMapper.java`
(`PROVIDER_ID = "oidc-usermodel-attribute-mapper"`) — the exact same
built-in mapper type this repo's own `kronos-realm.json` doesn't yet use for
this purpose, but does already trust for other flat claims structurally
(the realm's `kronos-roles`/`kronos-sub` client scopes use sibling built-in
mappers `oidc-usermodel-realm-role-mapper` / `oidc-sub-mapper`, same
"flat, built-in, no custom code" category).

`setClaim()`:
```java
String attributeName = mappingModel.getConfig().get(ProtocolMapperUtils.USER_ATTRIBUTE);
Collection<String> attributeValue = KeycloakModelUtils.resolveAttribute(user, attributeName, aggregateAttrs);
if (attributeValue == null) return;
OIDCAttributeMapperHelper.mapClaim(token, mappingModel, attributeValue);
```
Reads a plain Keycloak user attribute and maps it straight onto the token
claim — flat, scalar, when `claim.name` has no dots and `multivalued=false`
(confirmed against the same `OIDCAttributeMapperHelper.mapClaim()` helper
the repo's existing `roles`/`sub` mappers already use correctly).

### The concrete plan for step 3

1. Extend `scripts/provision_keycloak_org.sh`'s existing member-linking loop
   (it already calls `POST .../organizations/{id}/members` once per
   membership) to also `PUT /admin/realms/{realm}/users/{id}` with
   `{"attributes": {"org_id": ["<the org's real uuid>"]}}` — one more field
   write in a call site that already runs per membership change, not a new
   trigger point, and never touches OpenSearch.
2. Add a new protocol mapper to `docker/keycloak/kronos-realm.json`'s
   client scope config: `protocolMapper: "oidc-usermodel-attribute-mapper"`,
   `config: {"user.attribute": "org_id", "claim.name": "org_id",
   "jsonType.label": "String", "multivalued": "false", ...}`.
3. Re-run `poc/opensearch_jwt/option_a_flat_claim/`'s real OpenSearch
   role+DLS setup, but with a **real Keycloak-issued** token carrying this
   new flat `org_id` claim in place of the hand-signed test JWTs — this is
   step 3 of the original plan.

Known gap this introduces (not fixed here, flag for step 3/5): the
attribute is only ever set on membership *add*; no code path clears it on
removal yet. Same category of gap as `provision_keycloak_org.sh`'s existing
member-add-only design (no removal handling there either) — worth folding
into whichever change addresses that, not a new problem this introduces.

## Sources
- https://raw.githubusercontent.com/keycloak/keycloak/26.2.0/services/src/main/java/org/keycloak/organization/protocol/mappers/oidc/OrganizationMembershipMapper.java
- https://raw.githubusercontent.com/keycloak/keycloak/26.2.0/services/src/main/java/org/keycloak/protocol/oidc/mappers/UserAttributeMapper.java
- https://raw.githubusercontent.com/keycloak/keycloak/26.2.0/services/src/main/java/org/keycloak/protocol/oidc/mappers/ScriptBasedOIDCProtocolMapper.java
- https://raw.githubusercontent.com/keycloak/keycloak/26.2.0/common/src/main/java/org/keycloak/common/Profile.java
- https://raw.githubusercontent.com/keycloak/keycloak/26.2.0/core/src/main/java/org/keycloak/OAuth2Constants.java
