"""Unit tests for InMemoryIOCFeedRepository (roadmap M5/F2)."""

from __future__ import annotations

import uuid

import pytest

from src.adapter.repository.ioc_feed import InMemoryIOCFeedRepository
from src.domain.ioc_feed import IOCFeedVersion, IOCIndicator, IOCType
from src.exceptions import StorageError


class TestInMemoryIOCFeedRepository:
    @pytest.mark.asyncio
    async def test_get_or_create_feed_is_idempotent(self) -> None:
        repo = InMemoryIOCFeedRepository()
        org_id = uuid.uuid4()

        feed1 = await repo.get_or_create_feed(org_id, "my-feed")
        feed2 = await repo.get_or_create_feed(org_id, "my-feed")

        assert feed1.feed_id == feed2.feed_id

    @pytest.mark.asyncio
    async def test_different_org_same_name_gets_different_feed(self) -> None:
        repo = InMemoryIOCFeedRepository()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()

        feed_a = await repo.get_or_create_feed(org_a, "shared-name")
        feed_b = await repo.get_or_create_feed(org_b, "shared-name")

        assert feed_a.feed_id != feed_b.feed_id

    @pytest.mark.asyncio
    async def test_save_version_then_get_latest(self) -> None:
        repo = InMemoryIOCFeedRepository()
        org_id = uuid.uuid4()
        feed = await repo.get_or_create_feed(org_id, "f")
        version = IOCFeedVersion(
            feed_id=feed.feed_id, version=1, org_id=org_id, source_format="stix2.1"
        )

        await repo.save_version(version)
        latest = await repo.get_latest_version(feed.feed_id)

        assert latest == version

    @pytest.mark.asyncio
    async def test_no_versions_yet_returns_none(self) -> None:
        repo = InMemoryIOCFeedRepository()
        feed = await repo.get_or_create_feed(uuid.uuid4(), "f")

        assert await repo.get_latest_version(feed.feed_id) is None

    @pytest.mark.asyncio
    async def test_duplicate_version_raises_storage_error(self) -> None:
        repo = InMemoryIOCFeedRepository()
        org_id = uuid.uuid4()
        feed = await repo.get_or_create_feed(org_id, "f")
        version = IOCFeedVersion(
            feed_id=feed.feed_id, version=1, org_id=org_id, source_format="stix2.1"
        )
        await repo.save_version(version)

        with pytest.raises(StorageError):
            await repo.save_version(version)

    @pytest.mark.asyncio
    async def test_list_versions_ascending_and_never_lost(self) -> None:
        repo = InMemoryIOCFeedRepository()
        org_id = uuid.uuid4()
        feed = await repo.get_or_create_feed(org_id, "f")
        v1 = IOCFeedVersion(feed_id=feed.feed_id, version=1, org_id=org_id, source_format="stix2.1")
        v2 = IOCFeedVersion(feed_id=feed.feed_id, version=2, org_id=org_id, source_format="stix2.1")
        await repo.save_version(v1)
        await repo.save_version(v2)

        versions = await repo.list_versions(feed.feed_id)

        assert [v.version for v in versions] == [1, 2]

    @pytest.mark.asyncio
    async def test_match_indicator_real_hit(self) -> None:
        repo = InMemoryIOCFeedRepository()
        org_id = uuid.uuid4()
        feed = await repo.get_or_create_feed(org_id, "f")
        indicator = IOCIndicator(ioc_type=IOCType.IP, value="203.0.113.66", confidence=85)
        await repo.save_version(
            IOCFeedVersion(
                feed_id=feed.feed_id,
                version=1,
                org_id=org_id,
                source_format="stix2.1",
                indicators=(indicator,),
            )
        )

        match = await repo.match_indicator(org_id, IOCType.IP, "203.0.113.66")

        assert match is not None
        assert match.feed_name == "f"
        assert match.indicator == indicator

    @pytest.mark.asyncio
    async def test_match_indicator_case_insensitive(self) -> None:
        repo = InMemoryIOCFeedRepository()
        org_id = uuid.uuid4()
        feed = await repo.get_or_create_feed(org_id, "f")
        await repo.save_version(
            IOCFeedVersion(
                feed_id=feed.feed_id,
                version=1,
                org_id=org_id,
                source_format="stix2.1",
                indicators=(IOCIndicator(ioc_type=IOCType.DOMAIN, value="evil.test"),),
            )
        )

        assert await repo.match_indicator(org_id, IOCType.DOMAIN, "EVIL.TEST") is not None

    @pytest.mark.asyncio
    async def test_match_indicator_no_match_is_honest_none(self) -> None:
        repo = InMemoryIOCFeedRepository()
        assert await repo.match_indicator(uuid.uuid4(), IOCType.IP, "1.2.3.4") is None

    @pytest.mark.asyncio
    async def test_match_indicator_wrong_ioc_type_does_not_match(self) -> None:
        repo = InMemoryIOCFeedRepository()
        org_id = uuid.uuid4()
        feed = await repo.get_or_create_feed(org_id, "f")
        await repo.save_version(
            IOCFeedVersion(
                feed_id=feed.feed_id,
                version=1,
                org_id=org_id,
                source_format="stix2.1",
                indicators=(IOCIndicator(ioc_type=IOCType.DOMAIN, value="203.0.113.66"),),
            )
        )

        assert await repo.match_indicator(org_id, IOCType.IP, "203.0.113.66") is None

    @pytest.mark.asyncio
    async def test_match_indicator_only_searches_current_latest_version(self) -> None:
        """An indicator present in a SUPERSEDED version must never match --
        only the current (latest) version is live (see this repo's own
        ABC docstring)."""
        repo = InMemoryIOCFeedRepository()
        org_id = uuid.uuid4()
        feed = await repo.get_or_create_feed(org_id, "f")
        await repo.save_version(
            IOCFeedVersion(
                feed_id=feed.feed_id,
                version=1,
                org_id=org_id,
                source_format="stix2.1",
                indicators=(IOCIndicator(ioc_type=IOCType.IP, value="203.0.113.66"),),
            )
        )
        # Version 2 supersedes version 1 and DROPS that indicator (feed
        # updated upstream, IOC no longer present).
        await repo.save_version(
            IOCFeedVersion(feed_id=feed.feed_id, version=2, org_id=org_id, source_format="stix2.1")
        )

        assert await repo.match_indicator(org_id, IOCType.IP, "203.0.113.66") is None

    @pytest.mark.asyncio
    async def test_match_indicator_cross_org_isolation_real(self) -> None:
        repo = InMemoryIOCFeedRepository()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        feed = await repo.get_or_create_feed(org_a, "f")
        await repo.save_version(
            IOCFeedVersion(
                feed_id=feed.feed_id,
                version=1,
                org_id=org_a,
                source_format="stix2.1",
                indicators=(IOCIndicator(ioc_type=IOCType.IP, value="203.0.113.66"),),
            )
        )

        assert await repo.match_indicator(org_b, IOCType.IP, "203.0.113.66") is None
