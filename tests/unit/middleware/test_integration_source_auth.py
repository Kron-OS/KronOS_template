"""Unit tests for the IntegrationSource auth collaborators (roadmap Q1).

External dependency mocked per CLAUDE.md SS B.5: the OAuth2 token endpoint
is an AsyncMock-backed httpx.AsyncClient, never a real network call in a
unit test (the real call is proven in poc/integration_source_foundation/).
"""

from __future__ import annotations

import time
import uuid
from unittest.mock import AsyncMock

import httpx
import pytest

from src.domain.collector import CollectorIdentity
from src.exceptions import AuthenticationError
from src.external.middleware.integration_source_auth import (
    ApiKeyOutboundAuthStrategy,
    IntegrationSourceAuthError,
    MtlsOutboundAuthStrategy,
    OAuth2ClientCredentialsOutboundAuthStrategy,
    StaticApiKeyInboundAuthenticator,
    StaticApiKeyProvisioning,
    identity_from_collector_identity,
)


class TestIdentityFromCollectorIdentity:
    def test_adapts_org_and_source_id_verbatim(self) -> None:
        org_id = uuid.uuid4()
        collector_identity = CollectorIdentity(
            org_id=org_id,
            source_id="edr-host-1",
            cert_subject="CN=test",
            not_after="2026-01-01T00:00:00+00:00",
        )

        identity = identity_from_collector_identity(collector_identity, source_type="wazuh")

        assert identity.org_id == org_id
        assert identity.source_id == "edr-host-1"
        assert identity.source_type == "wazuh"
        assert identity.auth_method == "mtls"


class TestStaticApiKeyInboundAuthenticator:
    def _provisioning(self, org_id: uuid.UUID) -> StaticApiKeyProvisioning:
        return StaticApiKeyProvisioning(
            api_key="secret-key-1", org_id=org_id, source_id="s1", source_type="generic-webhook"
        )

    @pytest.mark.asyncio
    async def test_valid_key_resolves_to_provisioned_identity(self) -> None:
        org_id = uuid.uuid4()
        authenticator = StaticApiKeyInboundAuthenticator(
            {"secret-key-1": self._provisioning(org_id)}
        )

        identity = await authenticator.authenticate({"X-KronOS-Source-Key": "secret-key-1"})

        assert identity.org_id == org_id
        assert identity.source_id == "s1"
        assert identity.source_type == "generic-webhook"
        assert identity.auth_method == "api-key"

    @pytest.mark.asyncio
    async def test_header_lookup_is_case_insensitive(self) -> None:
        org_id = uuid.uuid4()
        authenticator = StaticApiKeyInboundAuthenticator(
            {"secret-key-1": self._provisioning(org_id)}
        )

        identity = await authenticator.authenticate({"x-kronos-source-key": "secret-key-1"})

        assert identity.org_id == org_id

    @pytest.mark.asyncio
    async def test_missing_header_raises(self) -> None:
        authenticator = StaticApiKeyInboundAuthenticator({})
        with pytest.raises(IntegrationSourceAuthError):
            await authenticator.authenticate({})

    @pytest.mark.asyncio
    async def test_unknown_key_raises(self) -> None:
        authenticator = StaticApiKeyInboundAuthenticator({})
        with pytest.raises(IntegrationSourceAuthError):
            await authenticator.authenticate({"X-KronOS-Source-Key": "not-provisioned"})

    def test_auth_error_is_an_authentication_error(self) -> None:
        assert issubclass(IntegrationSourceAuthError, AuthenticationError)


class TestApiKeyOutboundAuthStrategy:
    @pytest.mark.asyncio
    async def test_returns_configured_header(self) -> None:
        strategy = ApiKeyOutboundAuthStrategy("Authorization", "Bearer abc123")
        assert await strategy.headers() == {"Authorization": "Bearer abc123"}

    def test_no_extra_client_kwargs(self) -> None:
        strategy = ApiKeyOutboundAuthStrategy("X-Key", "abc")
        assert strategy.client_kwargs() == {}


class TestMtlsOutboundAuthStrategy:
    @pytest.mark.asyncio
    async def test_no_headers_needed(self) -> None:
        strategy = MtlsOutboundAuthStrategy("/tmp/cert.pem", "/tmp/key.pem")
        assert await strategy.headers() == {}

    def test_client_kwargs_carries_cert_tuple(self) -> None:
        strategy = MtlsOutboundAuthStrategy("/tmp/cert.pem", "/tmp/key.pem")
        assert strategy.client_kwargs() == {"cert": ("/tmp/cert.pem", "/tmp/key.pem")}


class TestOAuth2ClientCredentialsOutboundAuthStrategy:
    def _mock_client(self, status_code: int = 200, json_body: dict | None = None) -> AsyncMock:
        client = AsyncMock(spec=httpx.AsyncClient)
        response = httpx.Response(
            status_code=status_code,
            json=(
                json_body if json_body is not None else {"access_token": "tok-1", "expires_in": 300}
            ),
            request=httpx.Request("POST", "https://idp.example/token"),
        )
        client.post.return_value = response
        return client

    @pytest.mark.asyncio
    async def test_fetches_and_returns_bearer_token(self) -> None:
        client = self._mock_client()
        strategy = OAuth2ClientCredentialsOutboundAuthStrategy(
            client,
            token_endpoint="https://idp.example/token",
            client_id="id",
            client_secret="secret",
            scope="alerts.read",
        )

        headers = await strategy.headers()

        assert headers == {"Authorization": "Bearer tok-1"}
        client.post.assert_awaited_once()
        _url, kwargs = client.post.await_args[0][0], client.post.await_args[1]
        assert kwargs["data"]["grant_type"] == "client_credentials"
        assert kwargs["data"]["scope"] == "alerts.read"

    @pytest.mark.asyncio
    async def test_token_is_cached_across_calls(self) -> None:
        client = self._mock_client()
        strategy = OAuth2ClientCredentialsOutboundAuthStrategy(
            client,
            token_endpoint="https://idp.example/token",
            client_id="id",
            client_secret="secret",
        )

        await strategy.headers()
        await strategy.headers()

        client.post.assert_awaited_once()  # second call served from cache

    @pytest.mark.asyncio
    async def test_expired_token_is_refetched(self) -> None:
        client = self._mock_client(json_body={"access_token": "tok-1", "expires_in": 1})
        strategy = OAuth2ClientCredentialsOutboundAuthStrategy(
            client,
            token_endpoint="https://idp.example/token",
            client_id="id",
            client_secret="secret",
        )
        # Force the cached token to already be past its safety-margin expiry.
        await strategy.headers()
        assert strategy._cached is not None
        strategy._cached.expires_at_monotonic = time.monotonic() - 1

        await strategy.headers()

        assert client.post.await_count == 2

    @pytest.mark.asyncio
    async def test_non_200_response_raises(self) -> None:
        client = self._mock_client(status_code=401, json_body={"error": "invalid_client"})
        strategy = OAuth2ClientCredentialsOutboundAuthStrategy(
            client, token_endpoint="https://idp.example/token", client_id="id", client_secret="bad"
        )

        with pytest.raises(IntegrationSourceAuthError):
            await strategy.headers()

    @pytest.mark.asyncio
    async def test_malformed_response_raises(self) -> None:
        client = self._mock_client(json_body={"not_a_token_field": "x"})
        strategy = OAuth2ClientCredentialsOutboundAuthStrategy(
            client,
            token_endpoint="https://idp.example/token",
            client_id="id",
            client_secret="secret",
        )

        with pytest.raises(IntegrationSourceAuthError):
            await strategy.headers()

    @pytest.mark.asyncio
    async def test_http_error_raises(self) -> None:
        client = AsyncMock(spec=httpx.AsyncClient)
        client.post.side_effect = httpx.ConnectError("connection refused")
        strategy = OAuth2ClientCredentialsOutboundAuthStrategy(
            client,
            token_endpoint="https://idp.example/token",
            client_id="id",
            client_secret="secret",
        )

        with pytest.raises(IntegrationSourceAuthError):
            await strategy.headers()
