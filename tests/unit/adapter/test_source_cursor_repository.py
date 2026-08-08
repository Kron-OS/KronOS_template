"""Unit tests for InMemorySourceCursorRepository (roadmap Q1)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from src.adapter.repository.source_cursor import InMemorySourceCursorRepository
from src.domain.integration_source import SourceCursor


def _cursor(org_id: uuid.UUID, source_id: str, value: str) -> SourceCursor:
    return SourceCursor(
        org_id=org_id, source_id=source_id, cursor_value=value, updated_at=datetime.now(UTC)
    )


class TestInMemorySourceCursorRepository:
    @pytest.mark.asyncio
    async def test_get_returns_none_when_never_polled(self) -> None:
        repo = InMemorySourceCursorRepository()
        assert await repo.get(uuid.uuid4(), "generic-poll") is None

    @pytest.mark.asyncio
    async def test_upsert_then_get_round_trips(self) -> None:
        repo = InMemorySourceCursorRepository()
        org_id = uuid.uuid4()
        cursor = _cursor(org_id, "generic-poll", "page-1-token")

        await repo.upsert(cursor)

        assert await repo.get(org_id, "generic-poll") == cursor

    @pytest.mark.asyncio
    async def test_upsert_replaces_previous_cursor_for_same_org_and_source(self) -> None:
        repo = InMemorySourceCursorRepository()
        org_id = uuid.uuid4()
        await repo.upsert(_cursor(org_id, "generic-poll", "token-1"))
        await repo.upsert(_cursor(org_id, "generic-poll", "token-2"))

        result = await repo.get(org_id, "generic-poll")
        assert result is not None
        assert result.cursor_value == "token-2"

    @pytest.mark.asyncio
    async def test_cursors_scoped_independently_per_org(self) -> None:
        repo = InMemorySourceCursorRepository()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        await repo.upsert(_cursor(org_a, "generic-poll", "token-a"))

        assert await repo.get(org_b, "generic-poll") is None
        result = await repo.get(org_a, "generic-poll")
        assert result is not None
        assert result.cursor_value == "token-a"

    @pytest.mark.asyncio
    async def test_cursors_scoped_independently_per_source_within_same_org(self) -> None:
        repo = InMemorySourceCursorRepository()
        org_id = uuid.uuid4()
        await repo.upsert(_cursor(org_id, "source-a", "token-a"))
        await repo.upsert(_cursor(org_id, "source-b", "token-b"))

        result_a = await repo.get(org_id, "source-a")
        result_b = await repo.get(org_id, "source-b")
        assert result_a is not None and result_a.cursor_value == "token-a"
        assert result_b is not None and result_b.cursor_value == "token-b"
