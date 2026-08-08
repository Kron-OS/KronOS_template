"""Unit tests for IntegrationSource ABC contract + IntegrationSourceRegistry
(roadmap Q1)."""

from __future__ import annotations

import uuid

import pytest

from src.application.integration_source import IntegrationSource, IntegrationSourceRegistry
from src.domain.integration_source import IntegrationDeliveryMode, IntegrationSourceIdentity


class _StubPushSource(IntegrationSource):
    @property
    def source_type(self) -> str:
        return "stub-push"

    @property
    def source_version(self) -> str:
        return "1.0.0"

    @property
    def delivery_mode(self) -> IntegrationDeliveryMode:
        return IntegrationDeliveryMode.PUSH


class _StubPollSource(IntegrationSource):
    @property
    def source_type(self) -> str:
        return "stub-poll"

    @property
    def source_version(self) -> str:
        return "1.0.0"

    @property
    def delivery_mode(self) -> IntegrationDeliveryMode:
        return IntegrationDeliveryMode.POLL


def _identity(source_type: str) -> IntegrationSourceIdentity:
    return IntegrationSourceIdentity(
        org_id=uuid.uuid4(), source_id="s1", source_type=source_type, auth_method="api-key"
    )


class TestIntegrationSourceDefaults:
    @pytest.mark.asyncio
    async def test_default_parse_push_event_treats_whole_body_as_one_event(self) -> None:
        source = _StubPushSource()
        result = await source.parse_push_event(b'{"a": 1}')
        assert result == [b'{"a": 1}']

    @pytest.mark.asyncio
    async def test_poll_on_a_push_only_source_raises_not_implemented(self) -> None:
        source = _StubPushSource()
        with pytest.raises(NotImplementedError):
            await source.poll(_identity("stub-push"), None)


class TestIntegrationSourceRegistry:
    def test_register_then_get_returns_the_source(self) -> None:
        registry = IntegrationSourceRegistry()
        source = _StubPushSource()
        registry.register(source)
        assert registry.get("stub-push") is source

    def test_get_returns_none_for_unregistered_type(self) -> None:
        registry = IntegrationSourceRegistry()
        assert registry.get("nonexistent") is None

    def test_duplicate_registration_raises_value_error(self) -> None:
        registry = IntegrationSourceRegistry()
        registry.register(_StubPushSource())
        with pytest.raises(ValueError):
            registry.register(_StubPushSource())

    def test_all_sources_returns_every_registered_source(self) -> None:
        registry = IntegrationSourceRegistry()
        push, poll = _StubPushSource(), _StubPollSource()
        registry.register(push)
        registry.register(poll)

        all_sources = registry.all_sources()
        assert set(all_sources) == {push, poll}
