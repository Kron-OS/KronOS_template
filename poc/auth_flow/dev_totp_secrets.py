"""Real, registered TOTP secrets for this dev Keycloak realm's seed users.

DEV-ONLY. These are throwaway credentials for the isolated
docker-compose.dev.yml Keycloak realm (kronos-realm.json's own seeded
admin/analyst/case-lead accounts, passwords already plaintext in that same
file and in poc/auth_flow/auth_helpers.py's own docstrings) -- not real
secrets, not tied to any external service. Registered via a real
Keycloak Admin REST API credential reset + CONFIGURE_TOTP completion
(see poc/auth_flow/auth_helpers.py's real_browser_login), not fabricated.

Usage:

    import sys
    sys.path.insert(0, "poc/auth_flow")
    import auth_helpers
    from dev_totp_secrets import ADMIN_TOTP_SECRET

    tokens, _, mfa_path = auth_helpers.real_browser_login(
        "admin", "DevAdmin#2026", totp_secret=ADMIN_TOTP_SECRET,
        state="...", acr_values="aal2",
    )
    # mfa_path == "otp_entry", tokens["access_token"]'s acr claim == "aal2"

If a future session finds this secret no longer works (e.g. the Keycloak
dev-mode volume was reset), re-register it: DELETE the user's existing
`otp` credential via the Admin REST API
(`/admin/realms/kronos/users/{id}/credentials/{credId}`), PUT
`requiredActions: ["CONFIGURE_TOTP"]` on the user, then call
`real_browser_login(..., totp_secret=None)` once -- the second tuple
element is the new secret; update this file with it.

IMPORTANT: also update `frontend/e2e/stepup.ts`'s own `ADMIN_TOTP_SECRET`
constant to the same value -- it is a separate copy (Playwright can't
import this Python module) and drifting the two silently breaks every
step-up-gated Playwright spec with "Invalid authenticator code" failures
that look like flakiness but aren't. This happened once already.
"""

ADMIN_TOTP_SECRET = "I5ZFIUZVHBVXIQ3HIVXDEMKEKJXHIZCK"
