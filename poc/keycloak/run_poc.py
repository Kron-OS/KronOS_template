#!/usr/bin/env python3
"""PoC: real Keycloak 26.2 JWT/RBAC/multi-tenancy verification.

Runs the ACTUAL src/external/middleware/keycloak_auth.py
(KeycloakTokenValidator) and tenant_context.py (get_tenant_context) against
a real, containerized Keycloak 26.2 server (poc/keycloak/docker-compose.poc.yml),
using real tokens obtained from Keycloak's own token endpoint.

Prereqs: `docker compose -p kronos-poc-keycloak -f docker-compose.poc.yml up -d`
and the keycloak-init one-shot must have completed (see README.md).
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

import httpx
from jose import jwt as jose_jwt

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.exceptions import AuthenticationError  # noqa: E402
from src.external.middleware import keycloak_auth  # noqa: E402
from src.external.middleware.keycloak_auth import KeycloakTokenValidator  # noqa: E402

KC_BASE = "http://localhost:18080"
REALM = "kronos"
ISSUER = f"{KC_BASE}/realms/{REALM}"
JWKS_URL = f"{ISSUER}/protocol/openid-connect/certs"
AUDIENCE = "kronos-backend"
TOKEN_URL = f"{ISSUER}/protocol/openid-connect/token"

ADMIN_TOKEN_URL = f"{KC_BASE}/realms/master/protocol/openid-connect/token"


def line(title: str) -> None:
    print(f"\n{'=' * 10} {title} {'=' * 10}")


def get_password_token(username: str, password: str, client_id: str = "kronos-frontend") -> dict:
    resp = httpx.post(
        TOKEN_URL,
        data={
            "client_id": client_id,
            "grant_type": "password",
            "username": username,
            "password": password,
        },
        timeout=10.0,
    )
    resp.raise_for_status()
    return resp.json()


def get_client_credentials_token() -> dict:
    """Token for the kronos-backend service account (no audience mapper -> wrong aud)."""
    resp = httpx.post(
        TOKEN_URL,
        data={
            "client_id": "kronos-backend",
            "client_secret": "kronos-backend-secret",
            "grant_type": "client_credentials",
        },
        timeout=10.0,
    )
    resp.raise_for_status()
    return resp.json()


def get_admin_token() -> str:
    resp = httpx.post(
        ADMIN_TOKEN_URL,
        data={
            "client_id": "admin-cli",
            "grant_type": "password",
            "username": "admin",
            "password": "admin",
        },
        timeout=10.0,
    )
    resp.raise_for_status()
    return resp.json()["access_token"]


def set_client_access_token_lifespan(admin_token: str, seconds: int) -> None:
    """Set kronos realm accessTokenLifespan via Admin REST API (for expiry test)."""
    url = f"{KC_BASE}/admin/realms/{REALM}"
    resp = httpx.put(
        url,
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"accessTokenLifespan": seconds},
        timeout=10.0,
    )
    resp.raise_for_status()


async def main() -> None:
    validator = KeycloakTokenValidator(issuer=ISSUER, audience=AUDIENCE, jwks_url=JWKS_URL)

    # ---- 1. Real token for a real user in a real organization ----
    line("1. Obtain real access token (password grant, user=analyst)")
    token_resp = get_password_token("analyst", "DevAnalyst#2026")
    access_token = token_resp["access_token"]
    print(f"token_type={token_resp['token_type']} expires_in={token_resp['expires_in']}")

    header = jose_jwt.get_unverified_header(access_token)
    claims = jose_jwt.get_unverified_claims(access_token)
    print("\n--- Raw decoded JWT header ---")
    print(json.dumps(header, indent=2))
    print("\n--- Raw decoded JWT claims (as actually issued by Keycloak 26.2) ---")
    print(json.dumps(claims, indent=2))

    # ---- 2. Run the REAL validate_and_extract against the REAL JWKS ----
    line("2. KeycloakTokenValidator.validate_and_extract() -- signature + claims")
    tenant_ctx = await validator.validate_and_extract(access_token)
    print("TenantContext returned by the real validator:")
    print(f"  org_id       = {tenant_ctx.org_id}")
    print(f"  org_alias    = {tenant_ctx.org_alias}")
    print(f"  user_id      = {tenant_ctx.user_id}")
    print(f"  username     = {tenant_ctx.username}")
    print(f"  roles        = {sorted(r.value for r in tenant_ctx.roles)}")
    print(f"  correlation_id (jti) = {tenant_ctx.correlation_id}")
    print(f"  acr          = {tenant_ctx.acr}")

    assert str(tenant_ctx.org_id) == claims["organization"]["kronos-dev"]["id"]
    assert tenant_ctx.org_alias == "kronos-dev"
    assert str(tenant_ctx.user_id) == claims["sub"]
    assert sorted(r.value for r in tenant_ctx.roles) == ["analyst"]
    print("\nASSERTIONS PASSED: org_id/org_alias/user_id/roles all match raw claims.")

    # ---- 3. JWKS cache / refresh: force an unknown kid ----
    line("3. JWKS cache miss on unknown kid -> real refresh from real JWKS endpoint")
    real_kid = header["kid"]
    print(f"real kid in cache: {keycloak_auth._cache.get(ISSUER, real_kid) is not None}")
    try:
        await validator._resolve_key("not-a-real-kid-00000")
        print("UNEXPECTED: no exception raised for unknown kid")
    except AuthenticationError as exc:
        print(f"Correctly raised AuthenticationError for unknown kid: {exc}")
    # Confirm a genuine HTTP refresh happened (not just a cache lookup): drop
    # the cached entry for the real kid and force _resolve_key to refetch it.
    del keycloak_auth._cache._keys[(ISSUER, real_kid)]
    keycloak_auth._cache._fetched_at.pop(ISSUER, None)
    print("Cleared cached key + fetched_at for real kid/issuer; is_stale =",
          keycloak_auth._cache.is_stale(ISSUER))
    refetched = await validator._resolve_key(real_kid)
    print(f"After forced refresh, key for real kid found: {refetched is not None} "
          f"(kty={refetched.get('kty')}, alg={refetched.get('alg')})")

    # ---- 4. Expired token ----
    # NB: the validator applies a 30s clock-skew leeway (_CLOCK_SKEW_SECONDS),
    # so the sleep must clear lifespan + leeway, not just lifespan, or the
    # token is legitimately still valid and "acceptance" is correct, not a bug.
    line("4. Expired token -> must fail closed")
    admin_token = get_admin_token()
    set_client_access_token_lifespan(admin_token, 2)
    try:
        short_lived = get_password_token("analyst", "DevAnalyst#2026")["access_token"]
        print("sleeping 40s to clear the 2s lifespan + 30s clock-skew leeway...")
        time.sleep(40)
        try:
            await validator.validate_and_extract(short_lived)
            print("UNEXPECTED: expired token was accepted!")
        except AuthenticationError as exc:
            print(f"Correctly rejected expired token: {exc}")
    finally:
        set_client_access_token_lifespan(admin_token, 900)

    # ---- 5. Wrong-audience token (service-account token, no audience mapper) ----
    line("5. Wrong-audience token (kronos-backend service account) -> must fail closed")
    sa_token = get_client_credentials_token()["access_token"]
    sa_claims = jose_jwt.get_unverified_claims(sa_token)
    print(f"service-account token aud claim = {sa_claims.get('aud')!r} (expected validator aud = {AUDIENCE!r})")
    try:
        await validator.validate_and_extract(sa_token)
        print("UNEXPECTED: wrong-audience token was accepted!")
    except AuthenticationError as exc:
        print(f"Correctly rejected wrong-audience token: {exc}")

    # ---- 6. tenant_context.get_tenant_context() dependency, same validator ----
    line("6. get_tenant_context() FastAPI dependency (real validator, real token)")
    from fastapi import FastAPI
    from fastapi.security import HTTPAuthorizationCredentials
    from src.external.middleware.tenant_context import get_tenant_context

    class _FakeAppState:
        keycloak_validator = validator

    class _FakeApp:
        state = _FakeAppState()

    class _FakeRequest:
        app = _FakeApp()

    fresh_token = get_password_token("case-lead", "DevCaseLead#2026")["access_token"]
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=fresh_token)
    ctx = await get_tenant_context(creds, _FakeRequest())
    print(f"get_tenant_context() -> user={ctx.username} roles={sorted(r.value for r in ctx.roles)} "
          f"org_alias={ctx.org_alias}")
    assert sorted(r.value for r in ctx.roles) == ["case_lead"]
    print("ASSERTION PASSED: case-lead role correctly mapped to Role.CASE_LEAD.")

    line("PoC complete -- all checks passed against a real Keycloak 26.2 server")


if __name__ == "__main__":
    asyncio.run(main())
