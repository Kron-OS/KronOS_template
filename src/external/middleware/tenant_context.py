"""FastAPI dependency that validates a Bearer token and returns TenantContext."""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from src.domain.user import TenantContext
from src.exceptions import AuthenticationError

logger = logging.getLogger(__name__)

_bearer = HTTPBearer(auto_error=True)


def _get_validator(request: Request) -> Any:
    validator = getattr(request.app.state, "keycloak_validator", None)
    if validator is None:
        raise RuntimeError(
            "KeycloakTokenValidator not registered in app.state.keycloak_validator"
        )
    return validator


async def get_tenant_context(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(_bearer)],
    request: Request,
) -> TenantContext:
    """Validate the Bearer JWT and return the authenticated TenantContext.

    Replaces the Phase 2 header-based placeholder.  The JWT is validated
    against Keycloak JWKS; no introspection round-trip is made per request.
    """
    from src.external.middleware.keycloak_auth import KeycloakTokenValidator  # noqa: PLC0415

    validator: KeycloakTokenValidator = _get_validator(request)
    try:
        return await validator.validate_and_extract(credentials.credentials)
    except AuthenticationError as exc:
        logger.warning("jwt_validation_failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
