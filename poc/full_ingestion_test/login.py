"""Real scripted PKCE login against the live dev-stack Keycloak (localhost:8080),
reusing poc/auth_flow/auth_helpers.py's real_browser_login. Only the KC base
URL differs from that PoC (dev stack publishes Keycloak on localhost:8080, not
the PoC's own throwaway 18082); every other constant (realm, client_id,
redirect_uri) matches the real kronos-realm.json / docker-compose.dev.yml.

Must use "localhost", NOT "127.0.0.1" (unlike the PoC this borrows from):
confirmed by real run that dev Keycloak's KC_HOSTNAME is pinned to the literal
string "http://localhost:8080" (docker-compose.dev.yml, needed for a separate
refresh-token issuer-stability fix), so every login-form "action" URL Keycloak
renders is hardcoded to host "localhost" regardless of which host the initial
GET was sent to. Starting the flow on 127.0.0.1 sets session cookies for
domain 127.0.0.1, which then aren't resent on the POST to the "localhost"
form action, producing a real "Restart login cookie not found" error --
reproduced once, fixed by switching the whole flow to "localhost".

Prints the access token to stdout (last line) so callers can capture it; all
other diagnostics go to stderr.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "auth_flow"))

import auth_helpers  # noqa: E402

auth_helpers.KC = "http://localhost:8080"

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
