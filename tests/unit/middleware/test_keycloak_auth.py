"""Unit tests for KeycloakTokenValidator."""

from __future__ import annotations

import time
import uuid
from typing import Any
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt

from src.domain.user import Role
from src.exceptions import AuthenticationError
from src.external.middleware.keycloak_auth import (
    KeycloakTokenValidator,
    _cache,
    _extract_tenant,
    _JwksCache,
    _map_roles,
)

# ---------------------------------------------------------------------------
# Helpers: RSA key pair for signing test tokens
# ---------------------------------------------------------------------------

_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_PUBLIC_KEY = _PRIVATE_KEY.public_key()
_KID = "test-kid-1"
_ISSUER = "https://idp.test/realms/kronos"
_AUDIENCE = "kronos-backend"


def _jwk_from_public_key() -> dict[str, Any]:
    """Return a minimal JWK dict that jose can use to verify RS256 tokens."""
    from jose.backends import RSAKey

    pem = _PUBLIC_KEY.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    jwk_data = RSAKey(pem, "RS256").public_key().to_dict()
    return {"kid": _KID, "kty": "RSA", "use": "sig", "alg": "RS256", **jwk_data}


def _make_claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    org_id = str(uuid.uuid4())
    user_id = str(uuid.uuid4())
    claims: dict[str, Any] = {
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "sub": user_id,
        "preferred_username": "alice@acme.example",
        "roles": ["analyst"],
        "organization": {"acme": {"id": org_id}},
        "acr": "aal1",
        "jti": str(uuid.uuid4()),
        "exp": now + 3600,
        "nbf": now - 5,
        "iat": now,
    }
    claims.update(overrides)
    return claims


def _sign_token(claims: dict[str, Any], kid: str = _KID, alg: str = "RS256") -> str:
    pem = _PRIVATE_KEY.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return jwt.encode(claims, pem, algorithm=alg, headers={"kid": kid})


@pytest.fixture(autouse=True)
def prime_jwks_cache() -> None:
    """Pre-populate the module-level cache with our test public key."""
    jwk = _jwk_from_public_key()
    _cache.update(_ISSUER, {"keys": [jwk]})


# ---------------------------------------------------------------------------
# Tests: _JwksCache
# ---------------------------------------------------------------------------


def test_cache_is_stale_initially() -> None:
    cache = _JwksCache()
    assert cache.is_stale("https://idp.test")


def test_cache_not_stale_after_update() -> None:
    cache = _JwksCache()
    cache.update("https://idp.test", {"keys": []})
    assert not cache.is_stale("https://idp.test")


def test_cache_returns_key_by_issuer_and_kid() -> None:
    cache = _JwksCache()
    key = {"kid": "k1", "kty": "RSA"}
    cache.update("https://idp.test", {"keys": [key]})
    assert cache.get("https://idp.test", "k1") is not None
    assert cache.get("https://idp.test", "missing") is None


# ---------------------------------------------------------------------------
# Tests: _map_roles
# ---------------------------------------------------------------------------


def test_map_roles_known_values() -> None:
    result = _map_roles(["org-admin", "analyst", "read-only"])
    assert Role.ORG_ADMIN in result
    assert Role.ANALYST in result
    assert Role.READ_ONLY in result


def test_map_roles_unknown_ignored() -> None:
    result = _map_roles(["super-god", "analyst"])
    assert len(result) == 1
    assert result[0] == Role.ANALYST


def test_map_roles_empty() -> None:
    assert _map_roles([]) == []


# ---------------------------------------------------------------------------
# Tests: _extract_tenant
# ---------------------------------------------------------------------------


def test_extract_tenant_happy_path() -> None:
    org_id = uuid.uuid4()
    user_id = uuid.uuid4()
    claims = _make_claims(
        sub=str(user_id),
        organization={"acme": {"id": str(org_id)}},
        roles=["case-lead", "analyst"],
        acr="aal2",
    )
    tenant = _extract_tenant(claims)
    assert tenant.org_id == org_id
    assert tenant.user_id == user_id
    assert tenant.org_alias == "acme"
    assert Role.CASE_LEAD in tenant.roles
    assert Role.ANALYST in tenant.roles
    assert tenant.acr == "aal2"


def test_extract_tenant_missing_organization() -> None:
    with pytest.raises(AuthenticationError, match="organization"):
        _extract_tenant({"sub": str(uuid.uuid4()), "organization": {}})


def test_extract_tenant_invalid_org_id() -> None:
    with pytest.raises(AuthenticationError, match="org_id"):
        _extract_tenant(
            {
                "sub": str(uuid.uuid4()),
                "organization": {"acme": {"id": "not-a-uuid"}},
            }
        )


def test_extract_tenant_missing_sub() -> None:
    org_id = uuid.uuid4()
    with pytest.raises(AuthenticationError, match="sub"):
        _extract_tenant({"organization": {"acme": {"id": str(org_id)}}})


# ---------------------------------------------------------------------------
# Tests: KeycloakTokenValidator.validate_and_extract
# ---------------------------------------------------------------------------


@pytest.fixture
def validator() -> KeycloakTokenValidator:
    return KeycloakTokenValidator(
        issuer=_ISSUER,
        audience=_AUDIENCE,
        jwks_url="https://idp.test/.well-known/jwks.json",
    )


@pytest.mark.asyncio
async def test_validator_happy_path(validator: KeycloakTokenValidator) -> None:
    token = _sign_token(_make_claims())
    tenant = await validator.validate_and_extract(token)
    assert tenant.org_alias == "acme"
    assert Role.ANALYST in tenant.roles


@pytest.mark.asyncio
async def test_validator_rejects_alg_none(validator: KeycloakTokenValidator) -> None:
    """alg=none must always be rejected, even with a valid payload."""
    claims = _make_claims()
    # Manually build a token with alg=none (unsigned).
    import base64
    import json

    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    none_token = f"{header}.{payload}."
    with pytest.raises(AuthenticationError, match="algorithm"):
        await validator.validate_and_extract(none_token)


@pytest.mark.asyncio
async def test_validator_rejects_expired_token(validator: KeycloakTokenValidator) -> None:
    expired_claims = _make_claims(exp=int(time.time()) - 7200)
    token = _sign_token(expired_claims)
    with pytest.raises(AuthenticationError, match="expired"):
        await validator.validate_and_extract(token)


@pytest.mark.asyncio
async def test_validator_rejects_wrong_audience(validator: KeycloakTokenValidator) -> None:
    claims = _make_claims(aud="wrong-backend")
    token = _sign_token(claims)
    with pytest.raises(AuthenticationError):
        await validator.validate_and_extract(token)


@pytest.mark.asyncio
async def test_validator_rejects_wrong_issuer(validator: KeycloakTokenValidator) -> None:
    claims = _make_claims(iss="https://evil.example/realms/kronos")
    token = _sign_token(claims)
    with pytest.raises(AuthenticationError):
        await validator.validate_and_extract(token)


@pytest.mark.asyncio
async def test_validator_refreshes_on_unknown_kid(validator: KeycloakTokenValidator) -> None:
    """On unknown kid the validator must re-fetch JWKS before failing."""
    claims = _make_claims()
    token = _sign_token(claims, kid="unknown-kid")

    jwk = _jwk_from_public_key()
    new_jwks = {"keys": [dict(jwk, kid="unknown-kid")]}

    async def _fake_fetch(*args: Any, **kwargs: Any) -> None:
        _cache.update(_ISSUER, new_jwks)

    with patch.object(validator, "_refresh_jwks", side_effect=_fake_fetch):
        tenant = await validator.validate_and_extract(token)
    assert tenant is not None


@pytest.mark.asyncio
async def test_validator_raises_on_bad_token(validator: KeycloakTokenValidator) -> None:
    with pytest.raises(AuthenticationError):
        await validator.validate_and_extract("not.a.jwt")
