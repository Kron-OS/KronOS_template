"""Unit tests for InMemoryDetectionCorrelationRepository (no mocks -- pure in-memory impl)."""

from __future__ import annotations

import uuid

import pytest

from src.adapter.repository.detection_correlation import (
    InMemoryDetectionCorrelationRepository,
)
from src.domain.detection import DetectionCorrelation
from src.exceptions import StorageError


def make_correlation(org_id: uuid.UUID | None = None, **overrides: object) -> DetectionCorrelation:
    defaults: dict[str, object] = {
        "org_id": org_id or uuid.uuid4(),
        "detection_id_a": uuid.uuid4(),
        "detection_id_b": uuid.uuid4(),
        "finding_id_a": str(uuid.uuid4()),
        "finding_id_b": str(uuid.uuid4()),
        "rule_ids": ("rule-1",),
    }
    defaults.update(overrides)
    return DetectionCorrelation(**defaults)  # type: ignore[arg-type]


class TestInMemoryDetectionCorrelationRepository:
    @pytest.mark.asyncio
    async def test_save_and_stream_by_org(self) -> None:
        repo = InMemoryDetectionCorrelationRepository()
        org_id = uuid.uuid4()
        c = make_correlation(org_id=org_id)

        await repo.save(c)

        stored = [x async for x in repo.stream_by_org(org_id)]
        assert stored == [c]

    @pytest.mark.asyncio
    async def test_stream_by_org_excludes_other_orgs(self) -> None:
        repo = InMemoryDetectionCorrelationRepository()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        await repo.save(make_correlation(org_id=org_a))
        await repo.save(make_correlation(org_id=org_b))

        stored = [x async for x in repo.stream_by_org(org_a)]
        assert len(stored) == 1
        assert stored[0].org_id == org_a

    @pytest.mark.asyncio
    async def test_exists_for_pair_true_regardless_of_order(self) -> None:
        repo = InMemoryDetectionCorrelationRepository()
        org_id = uuid.uuid4()
        c = make_correlation(org_id=org_id, finding_id_a="finding-a", finding_id_b="finding-b")
        await repo.save(c)

        assert await repo.exists_for_pair(org_id, "finding-a", "finding-b") is True
        # SA reports pairs without a stable order (see the ABC's own
        # docstring) -- the reversed order must also be recognized.
        assert await repo.exists_for_pair(org_id, "finding-b", "finding-a") is True

    @pytest.mark.asyncio
    async def test_exists_for_pair_false_for_unrelated_findings(self) -> None:
        repo = InMemoryDetectionCorrelationRepository()
        org_id = uuid.uuid4()
        await repo.save(
            make_correlation(org_id=org_id, finding_id_a="finding-a", finding_id_b="finding-b")
        )

        assert await repo.exists_for_pair(org_id, "finding-a", "finding-c") is False

    @pytest.mark.asyncio
    async def test_exists_for_pair_scoped_to_org(self) -> None:
        repo = InMemoryDetectionCorrelationRepository()
        org_a, org_b = uuid.uuid4(), uuid.uuid4()
        await repo.save(
            make_correlation(org_id=org_a, finding_id_a="finding-a", finding_id_b="finding-b")
        )

        assert await repo.exists_for_pair(org_b, "finding-a", "finding-b") is False

    @pytest.mark.asyncio
    async def test_save_raises_on_duplicate_pair(self) -> None:
        repo = InMemoryDetectionCorrelationRepository()
        org_id = uuid.uuid4()
        c1 = make_correlation(org_id=org_id, finding_id_a="finding-a", finding_id_b="finding-b")
        c2 = make_correlation(org_id=org_id, finding_id_a="finding-b", finding_id_b="finding-a")
        await repo.save(c1)

        with pytest.raises(StorageError):
            await repo.save(c2)

    @pytest.mark.asyncio
    async def test_stream_by_detection_finds_link_regardless_of_side(self) -> None:
        repo = InMemoryDetectionCorrelationRepository()
        org_id = uuid.uuid4()
        detection_a, detection_b = uuid.uuid4(), uuid.uuid4()
        c = make_correlation(org_id=org_id, detection_id_a=detection_a, detection_id_b=detection_b)
        await repo.save(c)

        assert [x async for x in repo.stream_by_detection(detection_a, org_id)] == [c]
        assert [x async for x in repo.stream_by_detection(detection_b, org_id)] == [c]

    @pytest.mark.asyncio
    async def test_stream_by_detection_empty_when_unrelated(self) -> None:
        repo = InMemoryDetectionCorrelationRepository()
        org_id = uuid.uuid4()
        await repo.save(make_correlation(org_id=org_id))

        assert [x async for x in repo.stream_by_detection(uuid.uuid4(), org_id)] == []
