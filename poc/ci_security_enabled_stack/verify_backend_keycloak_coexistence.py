#!/usr/bin/env python3
"""PoC-local (not shipped) verification: real proof that kronos-backend's
own Keycloak JWT-validation config and the security-stack's own DLS-role
Keycloak provisioning (keycloak-init, provision_ci_org_b.py) coexist
correctly against the SAME real, security-enabled Keycloak realm.

Why this exists (Gap Audit Milestone GGGG, docs/GAP_AUDIT_2026-08-28_MILESTONE_GGGG.md):
`security-stack` (docker-compose.test.yml) never booted kronos-backend, so
"both real Keycloak consumers coexist" was asserted by two separate,
never-jointly-exercised job definitions (this job's own
test_security_enabled_stack.py exercises DLS/OpenSearch directly;
frontend-e2e-smoke's login.spec.ts exercises kronos-backend's JWT
validation, but against a DIFFERENT job/stack instance). Neither run ever
proved the two configs are mutually compatible in the SAME running stack.

Real, not simulated -- and real design pivot along the way, kept honest
here rather than silently smoothed over: the original plan was a real
user password-grant login (mirroring poc/keycloak_opensearch_dls/'s own
established pattern). That's now genuinely blocked: `python3 -c` against
this exact realm confirms NO client has `directAccessGrantsEnabled: true`
(docker/keycloak/kronos-realm.json) -- Resource Owner Password
Credentials was disabled at some point after that earlier PoC was
written. A real PKCE/browser flow was the alternative, but that needs
Keycloak's login FORM to be reachable at the pinned KC_HOSTNAME
(kronos.local:8443), which would mean bringing nginx+TLS+/etc/hosts
scaffolding into this job too -- duplicating frontend-e2e-smoke's own
setup for a narrower question than "does the whole browser flow work"
(that's already covered there).

Instead: a real `client_credentials` grant for kronos-backend's OWN
service account (`serviceAccountsEnabled: true` in the realm, the same
mechanism seed_second_org.py/seed_detection.py already use for Keycloak
Admin API calls) -- then a real authenticated call to kronos-backend
itself. Empirically confirmed (not assumed) this produces a real, SPECIFIC
401 -- "JWT audience claim missing or does not include 'kronos-backend'"
-- not a connection error or a generic auth failure. Reading
src/external/middleware/keycloak_auth.py confirms why this is real
positive proof, not a false pass: that exact message only fires AFTER
`_resolve_key()` successfully fetches JWKS (real network reachability),
`jwt.decode()` successfully verifies the signature, and `verify_iss`
successfully matches the issuer -- the audience check runs last, and is
kronos-backend's own already-known, deliberately-handled edge case
(AUTH-009's own comment names this exact scenario: "the kronos-backend
service-account token itself"). A JWKS-unreachable, signature, or issuer
failure would raise a DIFFERENT, distinguishable error message
("JWT signature validation failed" / "JWT claims invalid") -- so this
script asserts on the SPECIFIC audience-mismatch message, not just any
401, to make sure a real regression in JWKS reachability or issuer
config doesn't silently pass as "expected."

Required env: KC_BASE (default http://localhost:8080), BACKEND_BASE
(default http://localhost:8000), KEYCLOAK_CLIENT_SECRET (default
"kronos-backend-secret", matching this profile's own already-shipped
value).
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

KC_BASE = os.environ.get("KC_BASE", "http://localhost:8080")
BACKEND_BASE = os.environ.get("BACKEND_BASE", "http://localhost:8000")
KC_REALM = "kronos"
CLIENT_ID = "kronos-backend"
CLIENT_SECRET = os.environ.get("KEYCLOAK_CLIENT_SECRET", "kronos-backend-secret")

_EXPECTED_MESSAGE_FRAGMENT = "JWT audience claim missing or does not include"


def log(msg: str) -> None:
    print(f"[verify_backend_keycloak_coexistence] {msg}", file=sys.stderr)


def client_credentials_grant() -> str:
    url = f"{KC_BASE}/realms/{KC_REALM}/protocol/openid-connect/token"
    body = urllib.parse.urlencode(
        {
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "client_credentials",
        }
    ).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=15) as resp:
        payload = json.loads(resp.read())
    return payload["access_token"]


def call_backend(token: str) -> tuple[int, str]:
    req = urllib.request.Request(f"{BACKEND_BASE}/api/cases", method="GET")
    req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def main() -> None:
    log(f"real client_credentials grant for {CLIENT_ID!r} against {KC_BASE}")
    token = client_credentials_grant()
    log(f"got a real access token ({len(token)} chars) from this job's own Keycloak")

    log(f"real authenticated GET {BACKEND_BASE}/api/cases (kronos-backend's own port, no nginx)")
    status, body = call_backend(token)
    log(f"kronos-backend responded {status}: {body[:300]}")

    if status != 401:
        raise SystemExit(
            f"Expected a real 401 (the known audience-mismatch case for a "
            f"service-account token -- see this script's own module docstring), "
            f"got {status}. This is a real, unexpected result, not the documented "
            f"edge case: {body[:500]}"
        )
    if _EXPECTED_MESSAGE_FRAGMENT not in body:
        raise SystemExit(
            f"Got a 401, but NOT the specific audience-mismatch message this "
            f"script asserts on -- this could mean the JWKS fetch, signature, or "
            f"issuer check failed instead (a real coexistence break between "
            f"kronos-backend's Keycloak config and this job's keycloak-init "
            f"provisioning), not the expected, benign audience-only rejection. "
            f"Real body: {body[:500]}"
        )
    log(
        "PASS: kronos-backend's own JWT validator successfully fetched JWKS, "
        "verified the signature, and matched the issuer against this job's own "
        "real, security-enabled Keycloak realm -- only the (expected, benign) "
        "audience check rejected the service-account token. Both real Keycloak "
        "consumers confirmed to coexist correctly in this exact stack."
    )


if __name__ == "__main__":
    main()
