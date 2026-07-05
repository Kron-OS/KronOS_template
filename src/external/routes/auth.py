"""Auth proxy routes — token refresh via HttpOnly cookie."""

from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/refresh")
async def refresh_token(request: Request) -> JSONResponse:
    """Proxy a Keycloak token refresh.

    Reads ``refresh_token`` from the HttpOnly cookie this same endpoint sets
    — the steady-state path used for every silent refresh and for resuming a
    session after a page reload (AUTH-002/FE-2).

    AUTH-002 bootstrap path: immediately after a *fresh* keycloak-js login,
    the SPA holds a refresh token in memory but the HttpOnly cookie hasn't
    been set yet (this endpoint has never been called). For that one-time
    handoff only, a JSON body ``{"refresh_token": "..."}`` is accepted as a
    fallback when no cookie is present, so the SPA can establish the cookie
    without ever writing the token to any Web Storage itself. A request that
    already carries the cookie always uses the cookie, ignoring any body.
    """
    refresh_tok = request.cookies.get("refresh_token")
    if not refresh_tok:
        try:
            body = await request.json()
        except ValueError:
            body = None
        if isinstance(body, dict):
            candidate = body.get("refresh_token")
            refresh_tok = candidate if isinstance(candidate, str) else None
    if not refresh_tok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token cookie",
        )

    from src.config import Settings  # noqa: PLC0415

    settings = Settings()
    token_url = (
        f"{settings.keycloak_url}/realms/{settings.keycloak_realm}"
        f"/protocol/openid-connect/token"
    )

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                token_url,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_tok,
                    "client_id": settings.keycloak_client_id,
                    "client_secret": settings.keycloak_client_secret.get_secret_value(),
                },
            )
    except httpx.HTTPError as exc:
        logger.warning("keycloak_refresh_unreachable", extra={"error": str(exc)})
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auth service unreachable",
        ) from exc

    if resp.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token refresh failed",
        )

    data = resp.json()
    response = JSONResponse({"access_token": data["access_token"]})
    response.set_cookie(
        "refresh_token",
        data["refresh_token"],
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=int(data.get("refresh_expires_in", 1800)),
    )
    return response
