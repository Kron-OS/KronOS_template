# PoC: fixing the step-up MFA conditional flow (P1, task #38)

## The bug (from `poc/auth_flow/README.md`, real finding #1)

Every real login through the shipped `browser-stepup` flow was forced
through mandatory TOTP setup/entry, regardless of the requested
`acr_values` — including plain logins that requested `aal1` or nothing at
all. There was no way to obtain a plain `aal1` session at all.

## Root cause (confirmed by reading real Keycloak 26.2.0 source)

`ConditionalLoaAuthenticator.matchCondition()`
(`services/src/main/java/org/keycloak/authentication/authenticators/
conditional/ConditionalLoaAuthenticator.java`, tag `26.2.0`):

```java
if (currentAuthenticationLoa < Constants.MINIMUM_LOA) {
    return true;
}
```

The shipped realm had exactly one `conditional-level-of-authentication`
condition, configured for level 2, gating the OTP subflow. With nothing
in the flow ever establishing a *baseline* LoA first, `currentAuthenticationLoa`
is always "no level attained yet" for every session — so this check always
evaluates true and the OTP subflow always runs, independent of what
`acr_values` was actually requested.

## The fix (per Keycloak's own documented step-up pattern)

Official docs, `docs/documentation/server_admin/topics/authentication/
flows.adoc`, `[[_step-up-flow]]` section (fetched from the real GitHub repo,
not the JS-rendered docs site): a step-up flow needs a **first** CONDITIONAL
subflow ("1st Condition Flow") containing BOTH the LoA condition (level 1)
AND the actual `Username Password Form`, as sibling executions in the same
subflow — not the condition alone. A **second** sibling CONDITIONAL subflow
(level 2) then gates the OTP form as before. The level-1 condition's own
evaluation always succeeds (level 1 is the default baseline), so the
password form always runs; but critically, having gone through it means
`currentAuthenticationLoa` is now genuinely `1` by the time the level-2
condition runs — so *that* condition can correctly compare `1 < 2` only
when the caller actually asked for `aal2`.

Built and verified this exact structure via the real Keycloak Admin REST
API against a live container (`POST .../executions/flow`, `POST
.../executions/execution`, `PUT .../executions`, `POST .../config`,
`POST .../raise-priority`) before touching any JSON file, per CLAUDE.md
§F.2. Once verified, applied the identical structural change to
`docker/keycloak/kronos-realm.json` directly (`browser-stepup forms` now
routes through a new `browser-stepup level1` subflow — LoA(1) +
username-password-form — before the pre-existing `browser-stepup
conditional-mfa` subflow), and copied that fixed file into this directory
as `kronos-realm-poc.json` so the PoC verifies the actual shipped artifact,
not a hand-diverged copy.

One regression hit along the way: the new subflow's `description` field
was 275 characters, over Keycloak's own `AUTHENTICATION_FLOW.DESCRIPTION`
`VARCHAR(255)` limit (H2/`dev-mem`-backed) — the same class of
self-introduced bug as bug #17 in `docs/verification-pass-findings.md`,
this time on a different table. Shortened to fit.

## What this PoC does

`run_poc.py` uses the real, unmodified `auth_helpers.py` from `../`
(shared with the original `poc/auth_flow/` PoC — the same real scripted
PKCE + TOTP "browser", no password grant, no hand-minted tokens), extended
with an `acr_values` parameter, against a real Keycloak 26.2 container
importing `kronos-realm-poc.json` (byte-identical to the real
`docker/keycloak/kronos-realm.json`).

Three real, end-to-end checks:

1. Plain login, no `acr_values` — must NOT trigger any TOTP page; token's
   `acr` claim must be `aal1`.
2. Step-up login, `acr_values=aal2`, user has no TOTP credential yet — must
   go through real `CONFIGURE_TOTP` setup; token's `acr` claim must be
   `aal2`.
3. Regression check: the SAME user, now WITH a TOTP credential, logging in
   again with no `acr_values` — must NOT be forced through OTP entry just
   because a credential exists; token's `acr` claim must still be `aal1`.

## Result: 6/6 passed

See `output.txt` for the full captured run against the actual
`docker/keycloak/kronos-realm.json` file (copied here byte-for-byte),
imported into a fresh, real Keycloak 26.2 container.

Also independently re-verified: the real `docker/docker-compose.test.yml`
service definition (Keycloak 26.2, standardized to match
`docker-compose.dev.yml` per current instruction — the test compose
previously pinned 26.0) was brought up for real via
`docker compose -f docker-compose.test.yml -p kronos-poc-verify up -d
keycloak`, reported Docker-healthcheck `healthy`, and served
`/realms/kronos/.well-known/openid-configuration` with a real `200`. Torn
down afterward (`docker compose down -v`); no stray `kronos-poc-*`
containers remain.

## How to run

```bash
poc/auth_flow/step_up_conditional_fix/run_poc.sh
```

Boots a throwaway `kronos-poc-stepupfix-keycloak` container (Keycloak
26.2, removed and recreated each run) importing `kronos-realm-poc.json`,
then runs `run_poc.py` against it.
