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

## Real finding #1 (severe, documented — needs a Keycloak flow expert, not a blind fix): step-up MFA is not actually conditional

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

**Not blindly fixed here.** Root-causing exactly why Keycloak's
`conditional-level-of-authentication` authenticator isn't reading the
requested ACR level correctly requires either Keycloak's own debug-level
authentication SPI logging or focused expertise with this specific
authenticator's internals — guessing at a fix to realm.json's flow wiring
risks landing a worse misconfiguration (e.g. silently disabling MFA
altogether) without being able to verify the fix is actually correct.
Flagging clearly for dedicated follow-up rather than papering over it.

One consequence of this bug for this PoC's own scope: it's not possible to
exercise the negative "aal1 token attempts a step-up-gated action" path
against a real, live-issued token — the platform cannot currently issue
one. `StepUpAuth.assert_acr`'s rejection logic is already covered by
`tests/unit/middleware/test_step_up_auth.py` with fabricated
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
