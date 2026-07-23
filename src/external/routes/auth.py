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
    the SPA holds a refresh token in memory but the HttpOnly cookie may not
    reflect it yet, so a JSON body ``{"refresh_token": "..."}`` is also
    accepted. The cookie is tried first when present (it's usually right,
    and avoids parsing a body that's almost never sent), but if Keycloak
    rejects it — or it's absent entirely — a body token is tried as a
    fallback rather than failing outright. Without this fallback, a stale
    cookie (e.g. left over from before a Keycloak restart, or any other way
    a refresh token stops being valid) could never self-heal: every fresh
    keycloak-js login would still hand its brand-new refresh token to this
    endpoint via the body, but the endpoint would ignore it solely because
    *some* cookie — even a permanently invalid one — was present, so the
    HttpOnly cookie would stay wedged on the dead token forever and every
    subsequent refresh would 401.
    """
    cookie_tok = request.cookies.get("refresh_token")

    body_tok: str | None = None
    try:
        body = await request.json()
    except ValueError:
        body = None
    if isinstance(body, dict):
        candidate = body.get("refresh_token")
        body_tok = candidate if isinstance(candidate, str) else None

    if not cookie_tok and not body_tok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token cookie",
        )

    from src.config import Settings  # noqa: PLC0415

    settings = Settings()  # type: ignore[call-arg]  # BaseSettings: real values come from env vars
    token_url = (
        f"{settings.keycloak_url}/realms/{settings.keycloak_realm}"
        f"/protocol/openid-connect/token"
    )

    async def _redeem(token: str) -> httpx.Response | None:
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                return await client.post(
                    token_url,
                    data={
                        "grant_type": "refresh_token",
                        "refresh_token": token,
                        "client_id": settings.keycloak_spa_client_id,
                    },
                )
        except httpx.HTTPError as exc:
            logger.warning("keycloak_refresh_unreachable", extra={"error": str(exc)})
            return None

    resp = await _redeem(cookie_tok) if cookie_tok else None
    if (resp is None or resp.status_code != 200) and body_tok and body_tok != cookie_tok:
        resp = await _redeem(body_tok)

    if resp is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auth service unreachable",
        )
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
