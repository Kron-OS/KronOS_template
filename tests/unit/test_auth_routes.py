"""Unit tests for the /auth/refresh HttpOnly-cookie token-refresh proxy."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.external.routes.auth import router


class _FakeSecret:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_secret_value(self) -> str:
        return self._value


class _FakeSettings:
    keycloak_url = "https://idp.test"
    keycloak_realm = "kronos"
    keycloak_client_id = "kronos-backend"
    keycloak_client_secret = _FakeSecret("backend-secret")
    keycloak_spa_client_id = "kronos-frontend"


class _FakeAsyncClient:
    """Stand-in for httpx.AsyncClient used by refresh_token."""

    def __init__(
        self, response: httpx.Response | None = None, error: Exception | None = None
    ) -> None:
        self._response = response
        self._error = error

    async def __aenter__(self) -> _FakeAsyncClient:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False

    async def post(self, *_args: Any, **_kwargs: Any) -> httpx.Response:
        if self._error is not None:
            raise self._error
        assert self._response is not None
        return self._response


def _app(monkeypatch: pytest.MonkeyPatch, fake_client: _FakeAsyncClient) -> FastAPI:
    monkeypatch.setattr("src.config.Settings", lambda: _FakeSettings())
    monkeypatch.setattr("src.external.routes.auth.httpx.AsyncClient", lambda **_kw: fake_client)
    app = FastAPI()
    app.include_router(router)
    return app


def _keycloak_success_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "access_token": "new-access-token",
            "refresh_token": "new-refresh-token",
            "refresh_expires_in": 1800,
        },
        request=httpx.Request("POST", "https://idp.test/token"),
    )


def test_refresh_uses_cookie_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_client = _FakeAsyncClient(response=_keycloak_success_response())
    app = _app(monkeypatch, fake_client)
    client = TestClient(app)

    resp = client.post("/auth/refresh", cookies={"refresh_token": "existing-refresh-token"})
    assert resp.status_code == 200
    assert resp.json() == {"access_token": "new-access-token"}
    assert resp.cookies.get("refresh_token") == "new-refresh-token"


def test_refresh_accepts_bootstrap_body_when_no_cookie(monkeypatch: pytest.MonkeyPatch) -> None:
    # AUTH-002: the one-time post-login handoff, before the HttpOnly cookie
    # has ever been set.
    fake_client = _FakeAsyncClient(response=_keycloak_success_response())
    app = _app(monkeypatch, fake_client)
    client = TestClient(app)

    resp = client.post("/auth/refresh", json={"refresh_token": "bootstrap-refresh-token"})
    assert resp.status_code == 200
    assert resp.json() == {"access_token": "new-access-token"}
    assert resp.cookies.get("refresh_token") == "new-refresh-token"


def test_refresh_returns_401_with_no_cookie_and_no_body(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_client = _FakeAsyncClient(response=_keycloak_success_response())
    app = _app(monkeypatch, fake_client)
    client = TestClient(app)

    resp = client.post("/auth/refresh")
    assert resp.status_code == 401


def test_refresh_returns_401_with_malformed_body_and_no_cookie(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_client = _FakeAsyncClient(response=_keycloak_success_response())
    app = _app(monkeypatch, fake_client)
    client = TestClient(app)

    resp = client.post(
        "/auth/refresh", content=b"not-json", headers={"Content-Type": "application/json"}
    )
    assert resp.status_code == 401


def test_cookie_takes_precedence_over_body(monkeypatch: pytest.MonkeyPatch) -> None:
    # If a cookie is present, the body must be ignored entirely (no reason
    # to even parse it, and no ambiguity about which refresh token is used).
    captured: dict[str, Any] = {}

    class _CapturingClient(_FakeAsyncClient):
        async def post(self, *args: Any, **kwargs: Any) -> httpx.Response:
            captured["data"] = kwargs.get("data")
            return await super().post(*args, **kwargs)

    fake_client = _CapturingClient(response=_keycloak_success_response())
    app = _app(monkeypatch, fake_client)
    client = TestClient(app)

    resp = client.post(
        "/auth/refresh",
        cookies={"refresh_token": "cookie-token"},
        json={"refresh_token": "body-token"},
    )
    assert resp.status_code == 200
    assert captured["data"]["refresh_token"] == "cookie-token"


def test_refresh_returns_401_when_keycloak_rejects(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_client = _FakeAsyncClient(
        response=httpx.Response(
            400,
            json={"error": "invalid_grant"},
            request=httpx.Request("POST", "https://idp.test/token"),
        )
    )
    app = _app(monkeypatch, fake_client)
    client = TestClient(app)

    resp = client.post("/auth/refresh", cookies={"refresh_token": "expired-token"})
    assert resp.status_code == 401


def test_refresh_returns_503_when_keycloak_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_client = _FakeAsyncClient(error=httpx.ConnectError("connection refused"))
    app = _app(monkeypatch, fake_client)
    client = TestClient(app)

    resp = client.post("/auth/refresh", cookies={"refresh_token": "some-token"})
    assert resp.status_code == 503
