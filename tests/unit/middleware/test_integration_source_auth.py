"""Unit tests for the IntegrationSource auth collaborators (roadmap Q1).

External dependency mocked per CLAUDE.md SS B.5: the OAuth2 token endpoint
is an AsyncMock-backed httpx.AsyncClient, never a real network call in a
unit test (the real call is proven in poc/integration_source_foundation/).
"""

from __future__ import annotations

import time
import uuid
from unittest.mock import AsyncMock, patch

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

    @pytest.mark.asyncio
    async def test_multiple_provisioned_keys_each_resolve_correctly(self) -> None:
        """P2-W9 correctness check: with several provisioned keys, the linear
        hmac.compare_digest scan must still resolve each one to ITS OWN
        provisioning, not e.g. always the first/last key in the dict."""
        org_1, org_2 = uuid.uuid4(), uuid.uuid4()
        provisioning_1 = StaticApiKeyProvisioning(
            api_key="key-one", org_id=org_1, source_id="s1", source_type="wazuh"
        )
        provisioning_2 = StaticApiKeyProvisioning(
            api_key="key-two", org_id=org_2, source_id="s2", source_type="crowdstrike"
        )
        authenticator = StaticApiKeyInboundAuthenticator(
            {"key-one": provisioning_1, "key-two": provisioning_2}
        )

        identity_1 = await authenticator.authenticate({"X-KronOS-Source-Key": "key-one"})
        identity_2 = await authenticator.authenticate({"X-KronOS-Source-Key": "key-two"})

        assert identity_1.org_id == org_1
        assert identity_1.source_id == "s1"
        assert identity_2.org_id == org_2
        assert identity_2.source_id == "s2"

    @pytest.mark.asyncio
    async def test_key_comparison_uses_hmac_compare_digest(self) -> None:
        """Proves the fix actually replaced the dict-keyed lookup with
        hmac.compare_digest -- not a timing proof (CLAUDE.md SS F.2: timing
        itself is not easily unit-testable), just a correctness/wiring
        proof that the constant-time primitive is really on the hot path."""
        org_id = uuid.uuid4()
        authenticator = StaticApiKeyInboundAuthenticator(
            {"secret-key-1": self._provisioning(org_id)}
        )

        with patch(
            "src.external.middleware.integration_source_auth.hmac.compare_digest",
            wraps=__import__("hmac").compare_digest,
        ) as spy:
            identity = await authenticator.authenticate({"X-KronOS-Source-Key": "secret-key-1"})

        assert identity.org_id == org_id
        spy.assert_called_once_with(b"secret-key-1", b"secret-key-1")

    @pytest.mark.asyncio
    async def test_no_early_exit_all_candidates_compared(self) -> None:
        """The scan must not ``break`` on match -- every provisioned key is
        compared exactly once per request regardless of iteration order,
        so total comparison count doesn't leak which key matched."""
        org_id = uuid.uuid4()
        provisioning_map = {f"key-{i}": self._provisioning(org_id) for i in range(5)}
        authenticator = StaticApiKeyInboundAuthenticator(provisioning_map)

        with patch(
            "src.external.middleware.integration_source_auth.hmac.compare_digest",
            wraps=__import__("hmac").compare_digest,
        ) as spy:
            await authenticator.authenticate({"X-KronOS-Source-Key": "key-0"})

        assert spy.call_count == len(provisioning_map)


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
