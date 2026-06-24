"""KeycloakTokenValidator: validates JWTs issued by Keycloak using cached JWKS."""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

import httpx
from jose import JWTError, jwt
from jose.exceptions import ExpiredSignatureError, JWTClaimsError

from src.domain.user import Role, TenantContext
from src.exceptions import AuthenticationError

logger = logging.getLogger(__name__)

_ALLOWED_ALGORITHMS = frozenset({"RS256", "PS256"})
_JWKS_TTL_SECONDS = 600  # 10 minutes
_CLOCK_SKEW_SECONDS = 30

_ROLE_MAP: dict[str, Role] = {
    "org-admin": Role.ORG_ADMIN,
    "case-lead": Role.CASE_LEAD,
    "analyst": Role.ANALYST,
    "read-only": Role.READ_ONLY,
}


class _JwksCache:
    """In-memory JWKS cache keyed by (issuer, kid), with TTL-based staleness."""

    def __init__(self) -> None:
        self._keys: dict[tuple[str, str], dict[str, Any]] = {}
        self._fetched_at: dict[str, float] = {}

    def is_stale(self, issuer: str) -> bool:
        fetched = self._fetched_at.get(issuer)
        if fetched is None:
            return True
        return time.monotonic() - fetched >= _JWKS_TTL_SECONDS

    def update(self, issuer: str, jwks: dict[str, Any]) -> None:
        for key_data in jwks.get("keys", []):
            kid: str = key_data.get("kid", "")
            self._keys[(issuer, kid)] = key_data
        self._fetched_at[issuer] = time.monotonic()

    def get(self, issuer: str, kid: str) -> dict[str, Any] | None:
        return self._keys.get((issuer, kid))


_cache = _JwksCache()


class KeycloakTokenValidator:
    """Validates Keycloak JWTs and extracts TenantContext.

    Fetches JWKS from the discovery endpoint; caches for 10 minutes.
    On an unknown kid the cache is refreshed once before failing.
    Token introspection is never used — validation is done locally via JWKS.
    """

    def __init__(self, issuer: str, audience: str, jwks_url: str) -> None:
        self._issuer = issuer
        self._audience = audience
        self._jwks_url = jwks_url

    async def validate_and_extract(self, token: str) -> TenantContext:
        """Validate *token* and return a TenantContext.

        Raises:
            AuthenticationError: if the token is invalid, expired, or malformed.
        """
        try:
            header = jwt.get_unverified_header(token)
        except JWTError as exc:
            raise AuthenticationError(f"Malformed JWT header: {exc}") from exc

        alg = header.get("alg", "")
        if alg not in _ALLOWED_ALGORITHMS:
            raise AuthenticationError(
                f"JWT algorithm '{alg}' is not permitted; allowed: {sorted(_ALLOWED_ALGORITHMS)}"
            )

        kid: str = header.get("kid", "")
        key_data = await self._resolve_key(kid)

        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key_data,
                algorithms=list(_ALLOWED_ALGORITHMS),
                audience=self._audience,
                issuer=self._issuer,
                options={
                    "leeway": _CLOCK_SKEW_SECONDS,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iss": True,
                    "verify_aud": True,
                },
            )
        except ExpiredSignatureError as exc:
            raise AuthenticationError("JWT has expired") from exc
        except JWTClaimsError as exc:
            raise AuthenticationError(f"JWT claims invalid: {exc}") from exc
        except JWTError as exc:
            raise AuthenticationError(f"JWT signature validation failed: {exc}") from exc

        return _extract_tenant(claims)

    async def _resolve_key(self, kid: str) -> dict[str, Any]:
        """Return key from cache, refreshing once on stale cache or unknown kid."""
        if _cache.is_stale(self._issuer):
            await self._refresh_jwks()

        key_data = _cache.get(self._issuer, kid)
        if key_data is None:
            await self._refresh_jwks()
            key_data = _cache.get(self._issuer, kid)

        if key_data is None:
            raise AuthenticationError(f"No JWKS key found for kid='{kid}'")
        return key_data

    async def _refresh_jwks(self) -> None:
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(self._jwks_url, timeout=10.0)
                resp.raise_for_status()
                _cache.update(self._issuer, resp.json())
        except AuthenticationError:
            raise
        except Exception as exc:
            raise AuthenticationError(
                f"Failed to fetch JWKS from {self._jwks_url}: {exc}"
            ) from exc


def _extract_tenant(claims: dict[str, Any]) -> TenantContext:
    """Map validated JWT claims to a TenantContext."""
    organization: dict[str, Any] = claims.get("organization", {})
    if not organization:
        raise AuthenticationError("JWT is missing the 'organization' claim")

    org_alias, org_info = next(iter(organization.items()))
    try:
        org_id = uuid.UUID(org_info["id"])
    except (KeyError, ValueError, TypeError) as exc:
        raise AuthenticationError(
            f"Invalid org_id in JWT organization claim: {exc}"
        ) from exc

    try:
        user_id = uuid.UUID(claims["sub"])
    except (KeyError, ValueError) as exc:
        raise AuthenticationError(f"Invalid or missing 'sub' claim: {exc}") from exc

    roles = _map_roles(claims.get("roles", []))
    jti: str = claims.get("jti") or str(uuid.uuid4())
    acr: str = claims.get("acr", "aal1")

    return TenantContext(
        org_id=org_id,
        org_alias=org_alias,
        user_id=user_id,
        username=claims.get("preferred_username", "unknown"),
        roles=frozenset(roles),
        correlation_id=jti,
        acr=acr,
    )


def _map_roles(raw: list[str]) -> list[Role]:
    """Map JWT role strings (hyphen-separated) to Role enum values."""
    result: list[Role] = []
    for r in raw:
        mapped = _ROLE_MAP.get(r)
        if mapped is not None:
            result.append(mapped)
        else:
            logger.debug("keycloak_auth: unknown role '%s' ignored", r)
    return result
