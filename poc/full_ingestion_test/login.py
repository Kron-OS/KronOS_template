"""Real scripted PKCE login against the live dev-stack Keycloak
(https://kronos.local:8443), reusing poc/auth_flow/auth_helpers.py's
real_browser_login. kronos.local is the sole authorized domain for this
app (docs/lan-dev-access.md) -- KC, REDIRECT_URI, and CA trust are all
overridden below to match; every other constant (realm, client_id) matches
the real kronos-realm.json / docker-compose.dev.yml.

Real, reproduced finding this depends on (poc/tls_lan_https/README.md):
Keycloak's login form always POSTs to the single pinned KC_HOSTNAME origin
regardless of where the flow started -- starting anywhere else loses the
session-restart cookie across that domain jump ("Restart login cookie not
found", a real 400). Every client must start at the exact same canonical
origin; see frontend/src/keycloak.ts's resolveKeycloakUrl() for the same
fix applied to the real frontend.

Prints the access token to stdout (last line) so callers can capture it; all
other diagnostics go to stderr.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth_flow"))

import auth_helpers  # noqa: E402

auth_helpers.KC = "https://kronos.local:8443"
# Must be an origin Keycloak's kronos-frontend client actually allows
# (docker/keycloak/kronos-realm.json's redirectUris -- kronos.local only).
auth_helpers.REDIRECT_URI = "https://kronos.local/cases"
# Real, reproduced regression fix (poc/tls_lan_https/): the login form
# lives on an HTTPS origin signed by the stack's own step-ca, which needs
# to be trusted or httpx raises CERTIFICATE_VERIFY_FAILED.
auth_helpers.trust_dev_stack_step_ca()

if __name__ == "__main__":
    tokens, new_secret, mfa_path = auth_helpers.real_browser_login(
        "case-lead",
        "DevCaseLead#2026",
        totp_secret=None,
        state="full-ingestion-test-1",
    )
    payload = auth_helpers.decode_jwt_payload(tokens["access_token"])
    print(f"mfa_path={mfa_path}", file=sys.stderr)
    print(f"new_secret={new_secret}", file=sys.stderr)
    print(f"token claims: {json.dumps(payload, indent=2)}", file=sys.stderr)
    print(tokens["access_token"])
