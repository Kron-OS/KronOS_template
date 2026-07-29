# PoC: real scripted PKCE auth flow + real step-up (aal2) end-to-end

## What this actually does

A real scripted "browser" (`auth_helpers.py`) drives the genuine OIDC
Authorization Code + PKCE flow against a real Keycloak 26.2 — no password
grant, no hand-minted tokens: build `code_verifier`/`code_challenge`, GET
the real `/auth` endpoint, parse and submit the real login form, handle
Keycloak's real `CONFIGURE_TOTP`/OTP-entry pages (computing real TOTP codes
with `pyotp`), follow the real redirect chain, and exchange the real
authorization code for real tokens. Then the real FastAPI app, a real
Postgres, and a real MinIO are used to create a case + evidence and drive
the real `DELETE /api/evidence/{id}` step-up flow.

Two scripting-environment quirks hit and worked around (not application
bugs — documented in `auth_helpers.py`): Python's `http.cookiejar` mangles
bare hostnames like `localhost` (use `127.0.0.1`), and Keycloak marks
session cookies `Secure=True` even over plain dev-mode HTTP (a real browser
would just use HTTPS; this scripted client bypasses that one check).

## Real finding #1 (fixed — see `step_up_conditional_fix/`): step-up MFA was not actually conditional

`docs/subsystems/multi-tenancy.md` documents the design explicitly: `acr`
is `"aal1"` (password only) for normal use, elevating to `"aal2"` only
after an explicit step-up (WebAuthn/TOTP) for sensitive actions. The
realm's `browser-stepup conditional-mfa` flow is supposed to implement
exactly this via a `conditional-level-of-authentication` executor
(`loa-condition-level: "2"`) gating an `auth-otp-form`.

**Confirmed empirically: it is not conditional at all.** Every real login
attempt — with `acr_values=aal2`, `acr_values=aal1`, no `acr_values` at
all, and the OIDC `claims` parameter form (`{"id_token":{"acr":{"essential
":true,"values":["aal1"]}}}`) — was identically forced through mandatory
TOTP setup/entry. There is no way to obtain a plain aal1 session through
this realm as configured; every successful login token carries `acr:
"aal2"`. This is a severe functional and security-design bug: any user
without an authenticator device could never log in at all, and the
platform's entire two-tier trust model (only require MFA for genuinely
sensitive operations) doesn't exist in practice — everything is
unconditionally MFA-gated.

**Root-caused and fixed in `step_up_conditional_fix/`.** Reading Keycloak
26.2's actual source (`ConditionalLoaAuthenticator.matchCondition()`)
showed the real cause: with only a single level=2 condition in the flow,
there is no prior LoA established in the session, so the authenticator's
own `currentAuthenticationLoa < Constants.MINIMUM_LOA` check always fires
true — it doesn't matter what `acr_values` was requested, the condition
that's supposed to gate OTP always evaluates to "yes, require it." The
official Keycloak step-up pattern (`server_admin/topics/authentication/
flows.adoc`, `_step-up-flow` section) fixes this with a *first* conditional
subflow (level=1) that establishes the baseline LoA via the actual
username/password form nested inside the condition, before the existing
level=2/OTP subflow runs. Rebuilt via the real Admin REST API, verified
empirically (6/6 real PKCE logins), then ported into the real
`docker/keycloak/kronos-realm.json` and re-verified there directly — see
`step_up_conditional_fix/README.md` for the full account.

At the time this PoC was first written, the bug above meant it wasn't
possible to exercise the negative "aal1 token attempts a step-up-gated
action" path against a real, live-issued token — the platform couldn't
issue one. `StepUpAuth.assert_acr`'s rejection logic was already covered
by `tests/unit/middleware/test_step_up_auth.py` with fabricated
`TenantContext` objects, which is legitimate per CLAUDE.md B.5 for that
class in isolation; it just couldn't be re-verified end-to-end through a
real Keycloak session here.

## Real finding #2 (fixed): the step-up ticket issuance endpoint never existed

`DELETE /api/evidence/{id}`'s own docstring says: "Clients must first
obtain a step-up ticket via `POST /api/step-up/ticket` (requires aal2 JWT)
and pass it in the `X-Step-Up-Ticket` header." `StepUpAuth.issue_ticket()`
exists and is fully implemented — but `grep -rn "issue_ticket" src/`
found only its own definition. No route file, no registration in
`fastapi_app.py`'s 6 `include_router()` calls. **There was no way for any
client to ever legitimately obtain a step-up ticket — evidence deletion
was completely unreachable via the real API**, confirmed empirically:
`DELETE /api/evidence/{id}` correctly 401s without a ticket (RFC 9470
challenge), but the documented remedy endpoint didn't exist.

**Fixed**: added `src/external/routes/step_up.py` (`POST
/api/step-up/ticket`, requiring `assert_acr(aal2)` itself before minting a
ticket — matching `StepUpAuth`'s own docstring precondition) and
registered it in `fastapi_app.py`.

## Full checklist — 11/11 passed after the fix

- Real PKCE + TOTP login produced a real, valid, 3-part signed JWT
- Real case + evidence created via the real API with the real token
- `DELETE` without a ticket → 401 with the real RFC 9470
  `WWW-Authenticate: Bearer error="insufficient_user_authentication"` header
- `POST /api/step-up/ticket` → **201, a real ticket** (was a 404 before
  the fix — the endpoint didn't exist)
- `DELETE` with the real ticket → passes the step-up layer (409 Conflict
  for an unrelated, correct reason: Object Lock retention hasn't expired —
  not another 401, confirming the auth gate itself was satisfied)
- Replaying the same (already-consumed) ticket → 401, "Step-up ticket is
  invalid or already used"

Full unit suite still green after the fix (see session log for count).
