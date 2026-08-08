"""Unit tests for GenericWebhookPushSource (roadmap Q1)."""

from __future__ import annotations

import json

import pytest

from src.domain.integration_source import IntegrationDeliveryMode
from src.exceptions import ParsingError
from src.external.integration_sources.generic_webhook import GenericWebhookPushSource


class TestGenericWebhookPushSource:
    def test_identity_properties(self) -> None:
        source = GenericWebhookPushSource()
        assert source.source_type == "generic-webhook"
        assert source.source_version == "1.0.0"
        assert source.delivery_mode == IntegrationDeliveryMode.PUSH

    @pytest.mark.asyncio
    async def test_bare_json_object_is_one_event(self) -> None:
        source = GenericWebhookPushSource()
        body = json.dumps({"alert": "malware detected"}).encode()

        result = await source.parse_push_event(body)

        assert result == [body]

    @pytest.mark.asyncio
    async def test_non_json_body_is_one_opaque_event(self) -> None:
        source = GenericWebhookPushSource()
        body = b"not json at all"

        result = await source.parse_push_event(body)

        assert result == [body]

    @pytest.mark.asyncio
    async def test_batch_envelope_is_split_into_individual_events(self) -> None:
        source = GenericWebhookPushSource()
        body = json.dumps({"events": [{"id": 1}, {"id": 2}, {"id": 3}]}).encode()

        result = await source.parse_push_event(body)

        assert len(result) == 3
        decoded = [json.loads(r) for r in result]
        assert decoded == [{"id": 1}, {"id": 2}, {"id": 3}]

    @pytest.mark.asyncio
    async def test_empty_batch_envelope_raises_parsing_error(self) -> None:
        source = GenericWebhookPushSource()
        body = json.dumps({"events": []}).encode()

        with pytest.raises(ParsingError):
            await source.parse_push_event(body)

    @pytest.mark.asyncio
    async def test_bare_json_array_is_one_event_not_split(self) -> None:
        source = GenericWebhookPushSource()
        body = json.dumps([{"id": 1}, {"id": 2}]).encode()

        result = await source.parse_push_event(body)

        assert result == [body]
