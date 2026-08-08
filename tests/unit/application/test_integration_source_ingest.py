"""Unit tests for IntegrationSourceIngestService (mocked stream adapter,
dedup checker, cursor repository, audit log -- CLAUDE.md SS B.5: mock only
external dependencies, never the domain objects themselves) (roadmap Q1)."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock

import pytest

from src.application.integration_source import IntegrationSource, IntegrationSourceError
from src.application.integration_source_ingest import (
    IntegrationSourceBackpressureError,
    IntegrationSourceIngestService,
)
from src.domain.audit import AuditEventType
from src.domain.integration_source import (
    IntegrationDeliveryMode,
    IntegrationSourceIdentity,
    SourceCursor,
)


class _EchoPushSource(IntegrationSource):
    """Splits a batch envelope the same way GenericWebhookPushSource does,
    kept minimal/local here so this test doesn't depend on that concrete
    class's own behavior."""

    @property
    def source_type(self) -> str:
        return "echo-push"

    @property
    def source_version(self) -> str:
        return "1.0.0"

    @property
    def delivery_mode(self) -> IntegrationDeliveryMode:
        return IntegrationDeliveryMode.PUSH

    async def parse_push_event(self, raw_body: bytes) -> list[bytes]:
        if raw_body == b"batch-of-two":
            return [b"event-1", b"event-2"]
        return [raw_body]


class _StaticPollSource(IntegrationSource):
    def __init__(self, raw_events: list[bytes], next_cursor: str | None) -> None:
        self._raw_events = raw_events
        self._next_cursor = next_cursor
        self.last_cursor_seen: SourceCursor | None = "unset"  # type: ignore[assignment]

    @property
    def source_type(self) -> str:
        return "static-poll"

    @property
    def source_version(self) -> str:
        return "1.0.0"

    @property
    def delivery_mode(self) -> IntegrationDeliveryMode:
        return IntegrationDeliveryMode.POLL

    async def poll(self, identity: IntegrationSourceIdentity, cursor: SourceCursor | None):  # type: ignore[no-untyped-def]
        from src.application.integration_source import PollFetchResult

        self.last_cursor_seen = cursor
        return PollFetchResult(raw_events=self._raw_events, next_cursor=self._next_cursor)


def _identity(source_type: str, org_id: uuid.UUID | None = None) -> IntegrationSourceIdentity:
    return IntegrationSourceIdentity(
        org_id=org_id or uuid.uuid4(),
        source_id="s1",
        source_type=source_type,
        auth_method="api-key",
    )


@pytest.fixture
def stream_adapter() -> AsyncMock:
    adapter = AsyncMock()
    adapter.approximate_length.return_value = 0
    adapter.produce.return_value = "1-0"
    return adapter


@pytest.fixture
def dedup_checker() -> AsyncMock:
    checker = AsyncMock()
    checker.is_duplicate.return_value = False
    return checker


@pytest.fixture
def cursor_repository() -> AsyncMock:
    repo = AsyncMock()
    repo.get.return_value = None
    return repo


@pytest.fixture
def audit_log() -> AsyncMock:
    return AsyncMock()


def _service(  # type: ignore[no-untyped-def]
    registry, stream_adapter, dedup_checker, cursor_repository, audit_log
) -> IntegrationSourceIngestService:
    return IntegrationSourceIngestService(
        registry,
        stream_adapter,
        dedup_checker,
        cursor_repository,
        audit_log,
        max_stream_length=100,
        dedup_ttl_seconds=3600,
    )


class TestIngestPush:
    @pytest.mark.asyncio
    async def test_single_event_is_produced_and_audited(
        self,
        stream_adapter: AsyncMock,
        dedup_checker: AsyncMock,
        cursor_repository: AsyncMock,
        audit_log: AsyncMock,
    ) -> None:
        from src.application.integration_source import IntegrationSourceRegistry

        registry = IntegrationSourceRegistry()
        registry.register(_EchoPushSource())
        service = _service(registry, stream_adapter, dedup_checker, cursor_repository, audit_log)
        identity = _identity("echo-push")

        outcomes = await service.ingest_push(identity, b"one-event")

        assert len(outcomes) == 1
        assert outcomes[0].accepted is True
        stream_adapter.produce.assert_awaited_once_with(
            identity.org_id, identity.source_id, b"one-event"
        )
        audit_log.log.assert_awaited_once()
        call_args = audit_log.log.await_args
        assert call_args[0][0] == AuditEventType.INTEGRATION_SOURCE_PUSH_INGESTED
        assert call_args[1]["org_id"] == identity.org_id

    @pytest.mark.asyncio
    async def test_batch_envelope_is_split_into_multiple_produced_events(
        self,
        stream_adapter: AsyncMock,
        dedup_checker: AsyncMock,
        cursor_repository: AsyncMock,
        audit_log: AsyncMock,
    ) -> None:
        from src.application.integration_source import IntegrationSourceRegistry

        registry = IntegrationSourceRegistry()
        registry.register(_EchoPushSource())
        service = _service(registry, stream_adapter, dedup_checker, cursor_repository, audit_log)

        outcomes = await service.ingest_push(_identity("echo-push"), b"batch-of-two")

        assert len(outcomes) == 2
        assert stream_adapter.produce.await_count == 2

    @pytest.mark.asyncio
    async def test_duplicate_event_is_not_produced(
        self,
        stream_adapter: AsyncMock,
        dedup_checker: AsyncMock,
        cursor_repository: AsyncMock,
        audit_log: AsyncMock,
    ) -> None:
        from src.application.integration_source import IntegrationSourceRegistry

        dedup_checker.is_duplicate.return_value = True
        registry = IntegrationSourceRegistry()
        registry.register(_EchoPushSource())
        service = _service(registry, stream_adapter, dedup_checker, cursor_repository, audit_log)

        outcomes = await service.ingest_push(_identity("echo-push"), b"one-event")

        assert outcomes[0].duplicate is True
        assert outcomes[0].accepted is False
        stream_adapter.produce.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_backpressure_raised_when_stream_at_capacity(
        self,
        stream_adapter: AsyncMock,
        dedup_checker: AsyncMock,
        cursor_repository: AsyncMock,
        audit_log: AsyncMock,
    ) -> None:
        from src.application.integration_source import IntegrationSourceRegistry

        stream_adapter.approximate_length.return_value = 100
        registry = IntegrationSourceRegistry()
        registry.register(_EchoPushSource())
        service = _service(registry, stream_adapter, dedup_checker, cursor_repository, audit_log)

        with pytest.raises(IntegrationSourceBackpressureError):
            await service.ingest_push(_identity("echo-push"), b"one-event")

    @pytest.mark.asyncio
    async def test_unregistered_source_type_raises(
        self,
        stream_adapter: AsyncMock,
        dedup_checker: AsyncMock,
        cursor_repository: AsyncMock,
        audit_log: AsyncMock,
    ) -> None:
        from src.application.integration_source import IntegrationSourceRegistry

        registry = IntegrationSourceRegistry()
        service = _service(registry, stream_adapter, dedup_checker, cursor_repository, audit_log)

        with pytest.raises(IntegrationSourceError):
            await service.ingest_push(_identity("nonexistent"), b"x")

    @pytest.mark.asyncio
    async def test_poll_only_source_cannot_be_used_for_push(
        self,
        stream_adapter: AsyncMock,
        dedup_checker: AsyncMock,
        cursor_repository: AsyncMock,
        audit_log: AsyncMock,
    ) -> None:
        from src.application.integration_source import IntegrationSourceRegistry

        registry = IntegrationSourceRegistry()
        registry.register(_StaticPollSource([], None))
        service = _service(registry, stream_adapter, dedup_checker, cursor_repository, audit_log)

        with pytest.raises(IntegrationSourceError):
            await service.ingest_push(_identity("static-poll"), b"x")


class TestRunPollCycle:
    @pytest.mark.asyncio
    async def test_first_poll_passes_none_cursor(
        self,
        stream_adapter: AsyncMock,
        dedup_checker: AsyncMock,
        cursor_repository: AsyncMock,
        audit_log: AsyncMock,
    ) -> None:
        from src.application.integration_source import IntegrationSourceRegistry

        source = _StaticPollSource([b"e1"], "cursor-1")
        registry = IntegrationSourceRegistry()
        registry.register(source)
        service = _service(registry, stream_adapter, dedup_checker, cursor_repository, audit_log)

        await service.run_poll_cycle(_identity("static-poll"))

        assert source.last_cursor_seen is None

    @pytest.mark.asyncio
    async def test_events_produced_and_cursor_persisted(
        self,
        stream_adapter: AsyncMock,
        dedup_checker: AsyncMock,
        cursor_repository: AsyncMock,
        audit_log: AsyncMock,
    ) -> None:
        from src.application.integration_source import IntegrationSourceRegistry

        registry = IntegrationSourceRegistry()
        registry.register(_StaticPollSource([b"e1", b"e2"], "cursor-2"))
        service = _service(registry, stream_adapter, dedup_checker, cursor_repository, audit_log)
        identity = _identity("static-poll")

        result = await service.run_poll_cycle(identity)

        assert len(result.outcomes) == 2
        assert result.cursor_advanced is True
        cursor_repository.upsert.assert_awaited_once()
        persisted = cursor_repository.upsert.await_args[0][0]
        assert persisted.org_id == identity.org_id
        assert persisted.source_id == identity.source_id
        assert persisted.cursor_value == "cursor-2"

    @pytest.mark.asyncio
    async def test_empty_page_does_not_advance_cursor(
        self,
        stream_adapter: AsyncMock,
        dedup_checker: AsyncMock,
        cursor_repository: AsyncMock,
        audit_log: AsyncMock,
    ) -> None:
        from src.application.integration_source import IntegrationSourceRegistry

        registry = IntegrationSourceRegistry()
        registry.register(_StaticPollSource([], None))
        service = _service(registry, stream_adapter, dedup_checker, cursor_repository, audit_log)

        result = await service.run_poll_cycle(_identity("static-poll"))

        assert result.cursor_advanced is False
        cursor_repository.upsert.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_existing_cursor_is_passed_to_the_source(
        self,
        stream_adapter: AsyncMock,
        dedup_checker: AsyncMock,
        cursor_repository: AsyncMock,
        audit_log: AsyncMock,
    ) -> None:
        from src.application.integration_source import IntegrationSourceRegistry

        identity = _identity("static-poll")
        existing = SourceCursor(
            org_id=identity.org_id,
            source_id=identity.source_id,
            cursor_value="prev-token",
            updated_at=__import__("datetime").datetime.now(__import__("datetime").UTC),
        )
        cursor_repository.get.return_value = existing
        source = _StaticPollSource([b"e1"], "next-token")
        registry = IntegrationSourceRegistry()
        registry.register(source)
        service = _service(registry, stream_adapter, dedup_checker, cursor_repository, audit_log)

        await service.run_poll_cycle(identity)

        assert source.last_cursor_seen is existing

    @pytest.mark.asyncio
    async def test_poll_failure_is_audited_then_reraised(
        self,
        stream_adapter: AsyncMock,
        dedup_checker: AsyncMock,
        cursor_repository: AsyncMock,
        audit_log: AsyncMock,
    ) -> None:
        from src.application.integration_source import IntegrationSourceRegistry

        class _FailingPollSource(IntegrationSource):
            @property
            def source_type(self) -> str:
                return "failing-poll"

            @property
            def source_version(self) -> str:
                return "1.0.0"

            @property
            def delivery_mode(self) -> IntegrationDeliveryMode:
                return IntegrationDeliveryMode.POLL

            async def poll(self, identity, cursor):  # type: ignore[no-untyped-def]
                raise IntegrationSourceError("upstream rejected auth")

        registry = IntegrationSourceRegistry()
        registry.register(_FailingPollSource())
        service = _service(registry, stream_adapter, dedup_checker, cursor_repository, audit_log)

        with pytest.raises(IntegrationSourceError):
            await service.run_poll_cycle(_identity("failing-poll"))

        audit_log.log.assert_awaited_once()
        assert audit_log.log.await_args[0][0] == AuditEventType.INTEGRATION_SOURCE_POLL_FAILED

    @pytest.mark.asyncio
    async def test_push_only_source_cannot_be_used_for_poll(
        self,
        stream_adapter: AsyncMock,
        dedup_checker: AsyncMock,
        cursor_repository: AsyncMock,
        audit_log: AsyncMock,
    ) -> None:
        from src.application.integration_source import IntegrationSourceRegistry

        registry = IntegrationSourceRegistry()
        registry.register(_EchoPushSource())
        service = _service(registry, stream_adapter, dedup_checker, cursor_repository, audit_log)

        with pytest.raises(IntegrationSourceError):
            await service.run_poll_cycle(_identity("echo-push"))
