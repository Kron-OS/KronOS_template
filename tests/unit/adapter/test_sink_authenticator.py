"""Unit tests for SinkAuthenticator implementations (roadmap R1, SS4 design
constraint #2).

``OAuth2ClientCredentialsAuthenticator`` is the only implementation that
makes a real outbound call -- mocked here (httpx) mirroring
test_ticketing_system.py's own idiom; its real token-caching behavior
(one real fetch across two pushes) is independently proven for real
against a real local token endpoint in
poc/integration_sink_foundation/. Every other authenticator is pure,
in-process logic with no external dependency to mock.
"""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.adapter.integration_sink.sink_authenticator import (
    ApiKeyTupleAuthenticator,
    MtlsAuthenticator,
    NullAuthenticator,
    OAuth2ClientCredentialsAuthenticator,
    StaticTokenAuthenticator,
)
from src.exceptions import IntegrationSinkError


def _resp(status_code: int, json_body: object = None, text: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body
    resp.text = text
    return resp


def _make_client(post_side_effect) -> MagicMock:  # type: ignore[no-untyped-def]
    client = AsyncMock()
    client.post.side_effect = post_side_effect
    client.__aenter__.return_value = client
    client.__aexit__.return_value = False
    return client


class TestNullAuthenticator:
    @pytest.mark.asyncio
    async def test_prepare_returns_no_headers_no_cert(self) -> None:
        params = await NullAuthenticator().prepare()
        assert params.headers == {}
        assert params.cert is None
        assert params.verify is True


class TestStaticTokenAuthenticator:
    def test_requires_non_empty_token(self) -> None:
        with pytest.raises(ValueError):
            StaticTokenAuthenticator("")

    @pytest.mark.asyncio
    async def test_default_scheme_is_bearer(self) -> None:
        params = await StaticTokenAuthenticator("tok123").prepare()
        assert params.headers == {"Authorization": "Bearer tok123"}

    @pytest.mark.asyncio
    async def test_custom_scheme_matches_splunk_hec_real_header_shape(self) -> None:
        # Splunk HEC's real documented header is literally
        # "Authorization: Splunk <token>" (roadmap SS0), not Bearer.
        params = await StaticTokenAuthenticator("tok123", scheme="Splunk").prepare()
        assert params.headers == {"Authorization": "Splunk tok123"}

    @pytest.mark.asyncio
    async def test_empty_scheme_omits_scheme_prefix(self) -> None:
        params = await StaticTokenAuthenticator("tok123", scheme="").prepare()
        assert params.headers == {"Authorization": "tok123"}

    @pytest.mark.asyncio
    async def test_custom_header_name(self) -> None:
        params = await StaticTokenAuthenticator("tok123", header_name="X-Api-Key").prepare()
        assert params.headers == {"X-Api-Key": "Bearer tok123"}

    @pytest.mark.asyncio
    async def test_verify_defaults_to_true(self) -> None:
        params = await StaticTokenAuthenticator("tok123").prepare()
        assert params.verify is True

    @pytest.mark.asyncio
    async def test_verify_override_surfaced_on_params(self) -> None:
        params = await StaticTokenAuthenticator("tok123", verify=False).prepare()
        assert params.verify is False

    @pytest.mark.asyncio
    async def test_same_value_returned_every_call_no_per_call_state(self) -> None:
        auth = StaticTokenAuthenticator("tok123")
        first = await auth.prepare()
        second = await auth.prepare()
        assert first.headers == second.headers


class TestApiKeyTupleAuthenticator:
    def test_requires_non_empty_key_id_and_api_key(self) -> None:
        with pytest.raises(ValueError):
            ApiKeyTupleAuthenticator("", "key")
        with pytest.raises(ValueError):
            ApiKeyTupleAuthenticator("id", "")

    @pytest.mark.asyncio
    async def test_encodes_id_and_key_as_base64_apikey_header(self) -> None:
        params = await ApiKeyTupleAuthenticator("myid", "mykey").prepare()
        expected = f"ApiKey {base64.b64encode(b'myid:mykey').decode()}"
        assert params.headers == {"Authorization": expected}


class TestMtlsAuthenticator:
    @pytest.mark.asyncio
    async def test_returns_cert_and_verify_no_headers(self) -> None:
        params = await MtlsAuthenticator(("cert.pem", "key.pem"), verify="/ca.pem").prepare()
        assert params.headers == {}
        assert params.cert == ("cert.pem", "key.pem")
        assert params.verify == "/ca.pem"

    @pytest.mark.asyncio
    async def test_single_combined_pem_path(self) -> None:
        params = await MtlsAuthenticator("combined.pem").prepare()
        assert params.cert == "combined.pem"
        assert params.verify is True


class TestOAuth2ClientCredentialsAuthenticator:
    @pytest.mark.asyncio
    async def test_first_prepare_fetches_a_real_token(self) -> None:
        async def post(url, data, **kwargs):  # type: ignore[no-untyped-def]
            assert url == "https://idp.invalid/token"
            assert data["grant_type"] == "client_credentials"
            assert data["client_id"] == "cid"
            assert data["client_secret"] == "secret"
            return _resp(200, {"access_token": "tok-1", "expires_in": 3600})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            auth = OAuth2ClientCredentialsAuthenticator(
                "https://idp.invalid/token", "cid", "secret"
            )
            params = await auth.prepare()

        assert params.headers == {"Authorization": "Bearer tok-1"}
        assert auth.real_token_fetch_count == 1

    @pytest.mark.asyncio
    async def test_cached_token_reused_across_calls_no_second_fetch(self) -> None:
        call_count = {"n": 0}

        async def post(url, data, **kwargs):  # type: ignore[no-untyped-def]
            call_count["n"] += 1
            return _resp(200, {"access_token": f"tok-{call_count['n']}", "expires_in": 3600})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            auth = OAuth2ClientCredentialsAuthenticator(
                "https://idp.invalid/token", "cid", "secret"
            )
            first = await auth.prepare()
            second = await auth.prepare()

        assert first.headers == second.headers == {"Authorization": "Bearer tok-1"}
        assert auth.real_token_fetch_count == 1
        assert call_count["n"] == 1

    @pytest.mark.asyncio
    async def test_expired_token_triggers_a_real_refetch(self) -> None:
        call_count = {"n": 0}

        async def post(url, data, **kwargs):  # type: ignore[no-untyped-def]
            call_count["n"] += 1
            # expires_in shorter than the refresh margin (30s) -- the very
            # next prepare() must treat it as already-expired and refetch.
            return _resp(200, {"access_token": f"tok-{call_count['n']}", "expires_in": 1})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            auth = OAuth2ClientCredentialsAuthenticator(
                "https://idp.invalid/token", "cid", "secret"
            )
            first = await auth.prepare()
            second = await auth.prepare()

        assert first.headers == {"Authorization": "Bearer tok-1"}
        assert second.headers == {"Authorization": "Bearer tok-2"}
        assert auth.real_token_fetch_count == 2

    @pytest.mark.asyncio
    async def test_scope_included_when_provided(self) -> None:
        async def post(url, data, **kwargs):  # type: ignore[no-untyped-def]
            assert data["scope"] == "sink.write"
            return _resp(200, {"access_token": "tok-1", "expires_in": 3600})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            auth = OAuth2ClientCredentialsAuthenticator(
                "https://idp.invalid/token", "cid", "secret", scope="sink.write"
            )
            await auth.prepare()

    @pytest.mark.asyncio
    async def test_non_200_raises_integration_sink_error(self) -> None:
        async def post(url, data, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(401, text="invalid_client")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            auth = OAuth2ClientCredentialsAuthenticator("https://idp.invalid/token", "cid", "bad")
            with pytest.raises(IntegrationSinkError):
                await auth.prepare()

    @pytest.mark.asyncio
    async def test_missing_access_token_raises_never_fabricates(self) -> None:
        async def post(url, data, **kwargs):  # type: ignore[no-untyped-def]
            return _resp(200, {"token_type": "Bearer"})

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            auth = OAuth2ClientCredentialsAuthenticator(
                "https://idp.invalid/token", "cid", "secret"
            )
            with pytest.raises(IntegrationSinkError):
                await auth.prepare()

    @pytest.mark.asyncio
    async def test_unreachable_token_endpoint_raises_integration_sink_error(self) -> None:
        async def post(url, data, **kwargs):  # type: ignore[no-untyped-def]
            raise httpx.ConnectError("connection refused")

        with patch("httpx.AsyncClient", return_value=_make_client(post)):
            auth = OAuth2ClientCredentialsAuthenticator(
                "https://idp.invalid/token", "cid", "secret"
            )
            with pytest.raises(IntegrationSinkError):
                await auth.prepare()
