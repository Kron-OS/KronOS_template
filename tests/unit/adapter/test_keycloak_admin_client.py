"""Unit tests for HttpxKeycloakAdminClient (mocked httpx, roadmap M7/H2).

Mirrors test_detector_provisioner.py's own httpx-mocking idiom. Response
shapes asserted here (204/404 on session revocation, 200/404 on org
membership) were independently confirmed against the real, live Keycloak
26.2.5 dev-stack container first -- see poc/containment_approval_gate/.
"""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.adapter.keycloak.admin_client import HttpxKeycloakAdminClient
from src.exceptions import KeycloakAdminError


def _resp(status_code: int, json_body: object = None, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body
    resp.text = text
    return resp


def _make_client(request_side_effect, post_side_effect) -> MagicMock:
    client = AsyncMock()
    client.request.side_effect = request_side_effect
    client.post.side_effect = post_side_effect
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    return client


def _token_resp() -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"access_token": "real-looking-fake-token", "expires_in": 60}
    resp.raise_for_status.return_value = None
    return resp


class TestHttpxKeycloakAdminClientListSessions:
    @pytest.mark.asyncio
    async def test_returns_real_shaped_sessions(self) -> None:
        user_id = uuid.uuid4()

        async def request(method, url, **kwargs):  # type: ignore[no-untyped-def]
            assert method == "GET"
            assert url.endswith(f"/users/{user_id}/sessions")
            return _resp(
                200,
                [
                    {
                        "id": "sess-1",
                        "username": "analyst",
                        "userId": str(user_id),
                        "ipAddress": "192.168.5.13",
                        "start": 1786026144000,
                    }
                ],
            )

        async def post(*args, **kwargs):  # type: ignore[no-untyped-def]
            return _token_resp()

        with patch("httpx.AsyncClient", return_value=_make_client(request, post)):
            client = HttpxKeycloakAdminClient(
                "http://localhost:8080", "kronos", "kronos-backend", "secret"
            )
            sessions = await client.list_user_sessions(user_id)

        assert len(sessions) == 1
        assert sessions[0].session_id == "sess-1"
        assert sessions[0].ip_address == "192.168.5.13"

    @pytest.mark.asyncio
    async def test_non_200_raises_keycloak_admin_error(self) -> None:
        async def request(method, url, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(500, text="internal error")

        async def post(*args, **kwargs):  # type: ignore[no-untyped-def]
            return _token_resp()

        with patch("httpx.AsyncClient", return_value=_make_client(request, post)):
            client = HttpxKeycloakAdminClient(
                "http://localhost:8080", "kronos", "kronos-backend", "secret"
            )
            with pytest.raises(KeycloakAdminError):
                await client.list_user_sessions(uuid.uuid4())

    @pytest.mark.asyncio
    async def test_malformed_entry_fails_loudly(self) -> None:
        """Mirrors TestHttpxKeycloakAdminClientListOrganizations's own
        test_malformed_entry_fails_loudly (Gap Audit Milestone VV: this
        sibling "iterate an admin API list response" method previously had
        no equivalent guard, so a missing field raised a raw, unhelpful
        KeyError instead of a clean KeycloakAdminError)."""

        async def request(method, url, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(200, [{"id": "sess-1"}])  # missing userId/username

        async def post(*args, **kwargs):  # type: ignore[no-untyped-def]
            return _token_resp()

        with patch("httpx.AsyncClient", return_value=_make_client(request, post)):
            client = HttpxKeycloakAdminClient(
                "http://localhost:8080", "kronos", "kronos-backend", "secret"
            )
            with pytest.raises(KeycloakAdminError):
                await client.list_user_sessions(uuid.uuid4())


class TestHttpxKeycloakAdminClientRevokeSession:
    @pytest.mark.asyncio
    async def test_204_is_a_real_success(self) -> None:
        async def request(method, url, **kwargs):  # type: ignore[no-untyped-def]
            assert method == "DELETE"
            return _resp(204)

        async def post(*args, **kwargs):  # type: ignore[no-untyped-def]
            return _token_resp()

        with patch("httpx.AsyncClient", return_value=_make_client(request, post)):
            client = HttpxKeycloakAdminClient(
                "http://localhost:8080", "kronos", "kronos-backend", "secret"
            )
            await client.revoke_session("sess-1")  # must not raise

    @pytest.mark.asyncio
    async def test_404_already_gone_is_not_an_error(self) -> None:
        """Confirmed against the real Keycloak 26.2.5: DELETE on an
        already-revoked session returns 404 with the upstream's own literal
        {"error":"Sesssion not found"} body -- a legitimate terminal
        outcome, not a KronOS-side failure."""

        async def request(method, url, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(404, {"error": "Sesssion not found"})

        async def post(*args, **kwargs):  # type: ignore[no-untyped-def]
            return _token_resp()

        with patch("httpx.AsyncClient", return_value=_make_client(request, post)):
            client = HttpxKeycloakAdminClient(
                "http://localhost:8080", "kronos", "kronos-backend", "secret"
            )
            await client.revoke_session("sess-already-gone")  # must not raise

    @pytest.mark.asyncio
    async def test_403_fails_loudly_not_silently(self) -> None:
        async def request(method, url, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(403, text="forbidden")

        async def post(*args, **kwargs):  # type: ignore[no-untyped-def]
            return _token_resp()

        with patch("httpx.AsyncClient", return_value=_make_client(request, post)):
            client = HttpxKeycloakAdminClient(
                "http://localhost:8080", "kronos", "kronos-backend", "secret"
            )
            with pytest.raises(KeycloakAdminError):
                await client.revoke_session("sess-1")


class TestHttpxKeycloakAdminClientOrgMembership:
    @pytest.mark.asyncio
    async def test_200_means_member(self) -> None:
        async def request(method, url, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(200, {"id": "u1"})

        async def post(*args, **kwargs):  # type: ignore[no-untyped-def]
            return _token_resp()

        with patch("httpx.AsyncClient", return_value=_make_client(request, post)):
            client = HttpxKeycloakAdminClient(
                "http://localhost:8080", "kronos", "kronos-backend", "secret"
            )
            assert await client.is_org_member(uuid.uuid4(), uuid.uuid4()) is True

    @pytest.mark.asyncio
    async def test_404_means_not_a_member(self) -> None:
        async def request(method, url, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(404, {"error": "HTTP 404 Not Found"})

        async def post(*args, **kwargs):  # type: ignore[no-untyped-def]
            return _token_resp()

        with patch("httpx.AsyncClient", return_value=_make_client(request, post)):
            client = HttpxKeycloakAdminClient(
                "http://localhost:8080", "kronos", "kronos-backend", "secret"
            )
            assert await client.is_org_member(uuid.uuid4(), uuid.uuid4()) is False

    @pytest.mark.asyncio
    async def test_other_status_fails_loudly(self) -> None:
        async def request(method, url, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(500, text="boom")

        async def post(*args, **kwargs):  # type: ignore[no-untyped-def]
            return _token_resp()

        with patch("httpx.AsyncClient", return_value=_make_client(request, post)):
            client = HttpxKeycloakAdminClient(
                "http://localhost:8080", "kronos", "kronos-backend", "secret"
            )
            with pytest.raises(KeycloakAdminError):
                await client.is_org_member(uuid.uuid4(), uuid.uuid4())


class TestHttpxKeycloakAdminClientOrganizationAlias:
    """Response shapes here (200 with a real ``alias`` field, 404
    ``{"errorMessage":"Organization not found."}``) were independently
    confirmed against the real, live Keycloak 26.2 dev-stack container
    first, using the same ``kronos-backend`` service-account credentials
    ``is_org_member`` already uses in production -- see
    poc/autonomous_detection_pipeline/README.md."""

    @pytest.mark.asyncio
    async def test_200_returns_the_real_alias(self) -> None:
        org_id = uuid.uuid4()

        async def request(method, url, **kwargs):  # type: ignore[no-untyped-def]
            assert method == "GET"
            assert url.endswith(f"/organizations/{org_id}")
            return _resp(
                200,
                {
                    "id": str(org_id),
                    "name": "KronOS Dev",
                    "alias": "kronos-dev",
                    "enabled": True,
                },
            )

        async def post(*args, **kwargs):  # type: ignore[no-untyped-def]
            return _token_resp()

        with patch("httpx.AsyncClient", return_value=_make_client(request, post)):
            client = HttpxKeycloakAdminClient(
                "http://localhost:8080", "kronos", "kronos-backend", "secret"
            )
            alias = await client.get_organization_alias(org_id)

        assert alias == "kronos-dev"

    @pytest.mark.asyncio
    async def test_404_returns_none(self) -> None:
        async def request(method, url, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(404, {"errorMessage": "Organization not found."})

        async def post(*args, **kwargs):  # type: ignore[no-untyped-def]
            return _token_resp()

        with patch("httpx.AsyncClient", return_value=_make_client(request, post)):
            client = HttpxKeycloakAdminClient(
                "http://localhost:8080", "kronos", "kronos-backend", "secret"
            )
            assert await client.get_organization_alias(uuid.uuid4()) is None

    @pytest.mark.asyncio
    async def test_other_status_fails_loudly(self) -> None:
        async def request(method, url, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(500, text="boom")

        async def post(*args, **kwargs):  # type: ignore[no-untyped-def]
            return _token_resp()

        with patch("httpx.AsyncClient", return_value=_make_client(request, post)):
            client = HttpxKeycloakAdminClient(
                "http://localhost:8080", "kronos", "kronos-backend", "secret"
            )
            with pytest.raises(KeycloakAdminError):
                await client.get_organization_alias(uuid.uuid4())

    @pytest.mark.asyncio
    async def test_200_with_empty_alias_fails_loudly_not_silently(self) -> None:
        """A real org always has a non-empty alias (confirmed live) -- an
        empty one on a 200 is a genuinely unexpected upstream shape, must
        not be treated the same as a legitimate 404 "no such org"."""

        async def request(method, url, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(200, {"id": "u1", "name": "Weird Org", "alias": ""})

        async def post(*args, **kwargs):  # type: ignore[no-untyped-def]
            return _token_resp()

        with patch("httpx.AsyncClient", return_value=_make_client(request, post)):
            client = HttpxKeycloakAdminClient(
                "http://localhost:8080", "kronos", "kronos-backend", "secret"
            )
            with pytest.raises(KeycloakAdminError):
                await client.get_organization_alias(uuid.uuid4())


class TestHttpxKeycloakAdminClientListOrganizations:
    @pytest.mark.asyncio
    async def test_returns_real_shaped_organizations(self) -> None:
        org_id = uuid.uuid4()

        async def request(method, url, **kwargs):  # type: ignore[no-untyped-def]
            assert method == "GET"
            assert url.endswith("/organizations")
            return _resp(
                200,
                [{"id": str(org_id), "name": "KronOS Dev", "alias": "kronos-dev"}],
            )

        async def post(*args, **kwargs):  # type: ignore[no-untyped-def]
            return _token_resp()

        with patch("httpx.AsyncClient", return_value=_make_client(request, post)):
            client = HttpxKeycloakAdminClient(
                "http://localhost:8080", "kronos", "kronos-backend", "secret"
            )
            organizations = await client.list_organizations()

        assert len(organizations) == 1
        assert organizations[0].org_id == org_id
        assert organizations[0].alias == "kronos-dev"

    @pytest.mark.asyncio
    async def test_non_200_raises_keycloak_admin_error(self) -> None:
        async def request(method, url, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(500, text="boom")

        async def post(*args, **kwargs):  # type: ignore[no-untyped-def]
            return _token_resp()

        with patch("httpx.AsyncClient", return_value=_make_client(request, post)):
            client = HttpxKeycloakAdminClient(
                "http://localhost:8080", "kronos", "kronos-backend", "secret"
            )
            with pytest.raises(KeycloakAdminError):
                await client.list_organizations()

    @pytest.mark.asyncio
    async def test_malformed_entry_fails_loudly(self) -> None:
        async def request(method, url, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(200, [{"id": "not-a-uuid", "alias": "x"}])

        async def post(*args, **kwargs):  # type: ignore[no-untyped-def]
            return _token_resp()

        with patch("httpx.AsyncClient", return_value=_make_client(request, post)):
            client = HttpxKeycloakAdminClient(
                "http://localhost:8080", "kronos", "kronos-backend", "secret"
            )
            with pytest.raises(KeycloakAdminError):
                await client.list_organizations()


class TestHttpxKeycloakAdminClientTokenHandling:
    @pytest.mark.asyncio
    async def test_token_fetch_failure_raises_keycloak_admin_error(self) -> None:
        async def post(*args, **kwargs):  # type: ignore[no-untyped-def]
            raise httpx.ConnectError("connection refused")

        with patch("httpx.AsyncClient", return_value=_make_client(AsyncMock(), post)):
            client = HttpxKeycloakAdminClient(
                "http://localhost:8080", "kronos", "kronos-backend", "secret"
            )
            with pytest.raises(KeycloakAdminError):
                await client.list_user_sessions(uuid.uuid4())
