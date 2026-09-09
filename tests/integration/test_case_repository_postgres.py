"""Integration tests for PostgresCaseRepository's dynamic filter-building
(Milestone IIIII: CaseFilter) against a real testcontainers Postgres.

Requires: Docker (Postgres 16 container via testcontainers). Run with:
  pytest tests/integration/ -v -m integration

Cases already paginated over real SQL before this change; this confirms
the dynamic WHERE/ORDER BY built from CaseFilter (q/status/classification/
date range/sort) is correct against a genuinely fresh Postgres schema, not
just the in-memory double already covered by tests/unit/test_cases_routes.py.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from src.adapter.repository.case_repository import CaseFilter
from src.adapter.repository.postgres_case import PostgresCaseRepository
from src.domain.case import Case, CaseMetadata, CaseStatus

pytestmark = pytest.mark.integration


def _case(
    org_id: uuid.UUID,
    title: str,
    *,
    description: str | None = None,
    reference_number: str | None = None,
    classification: str = "UNCLASSIFIED",
    status: CaseStatus = CaseStatus.OPEN,
    created_at: datetime | None = None,
) -> Case:
    return Case(
        org_id=org_id,
        org_alias="testorg",
        owner_user_id=uuid.uuid4(),
        metadata=CaseMetadata(
            title=title,
            description=description,
            reference_number=reference_number,
            classification=classification,
        ),
        status=status,
        created_at=created_at or datetime.now(UTC),
        updated_at=created_at or datetime.now(UTC),
    )


@pytest.mark.asyncio
async def test_q_matches_title_description_or_reference_case_insensitively(
    postgres_engine,
) -> None:  # type: ignore[no-untyped-def]
    repo = PostgresCaseRepository(postgres_engine)
    org_id = uuid.uuid4()
    await repo.save(_case(org_id, "Ransomware Incident"))
    await repo.save(_case(org_id, "Phishing Campaign", description="targets RANSOMWARE actors"))
    await repo.save(_case(org_id, "Unrelated Case", reference_number="RANSOMWARE-2026-01"))
    await repo.save(_case(org_id, "Totally Different"))

    cases, total = await repo.list_by_org(org_id, filters=CaseFilter(q="ransomware"))

    assert total == 3
    assert {c.metadata.title for c in cases} == {
        "Ransomware Incident",
        "Phishing Campaign",
        "Unrelated Case",
    }


@pytest.mark.asyncio
async def test_filter_by_status(postgres_engine) -> None:  # type: ignore[no-untyped-def]
    repo = PostgresCaseRepository(postgres_engine)
    org_id = uuid.uuid4()
    await repo.save(_case(org_id, "Open One", status=CaseStatus.OPEN))
    await repo.save(_case(org_id, "Closed One", status=CaseStatus.CLOSED))
    await repo.save(_case(org_id, "Archived One", status=CaseStatus.ARCHIVED))

    cases, total = await repo.list_by_org(org_id, filters=CaseFilter(status=CaseStatus.CLOSED))

    assert total == 1
    assert cases[0].metadata.title == "Closed One"


@pytest.mark.asyncio
async def test_filter_by_classification(postgres_engine) -> None:  # type: ignore[no-untyped-def]
    repo = PostgresCaseRepository(postgres_engine)
    org_id = uuid.uuid4()
    await repo.save(_case(org_id, "Secret Case", classification="SECRET"))
    await repo.save(_case(org_id, "Plain Case"))

    cases, total = await repo.list_by_org(org_id, filters=CaseFilter(classification="SECRET"))

    assert total == 1
    assert cases[0].metadata.title == "Secret Case"


@pytest.mark.asyncio
async def test_filter_by_created_date_range(postgres_engine) -> None:  # type: ignore[no-untyped-def]
    repo = PostgresCaseRepository(postgres_engine)
    org_id = uuid.uuid4()
    await repo.save(_case(org_id, "Old Case", created_at=datetime(2020, 1, 1, tzinfo=UTC)))
    await repo.save(_case(org_id, "Recent Case", created_at=datetime(2026, 1, 1, tzinfo=UTC)))

    cases, total = await repo.list_by_org(
        org_id, filters=CaseFilter(created_from=datetime(2025, 1, 1, tzinfo=UTC))
    )

    assert total == 1
    assert cases[0].metadata.title == "Recent Case"


@pytest.mark.asyncio
async def test_sort_by_title_ascending(postgres_engine) -> None:  # type: ignore[no-untyped-def]
    repo = PostgresCaseRepository(postgres_engine)
    org_id = uuid.uuid4()
    await repo.save(_case(org_id, "Zebra"))
    await repo.save(_case(org_id, "Alpha"))
    await repo.save(_case(org_id, "Mike"))

    cases, _total = await repo.list_by_org(
        org_id, filters=CaseFilter(sort_by="title", sort_order="asc")
    )

    assert [c.metadata.title for c in cases] == ["Alpha", "Mike", "Zebra"]


@pytest.mark.asyncio
async def test_combined_filters_and_pagination(postgres_engine) -> None:  # type: ignore[no-untyped-def]
    repo = PostgresCaseRepository(postgres_engine)
    org_id = uuid.uuid4()
    for i in range(5):
        await repo.save(_case(org_id, f"Open Case {i}", status=CaseStatus.OPEN))
    await repo.save(_case(org_id, "Closed Case", status=CaseStatus.CLOSED))

    page1, total = await repo.list_by_org(
        org_id,
        page=1,
        page_size=2,
        filters=CaseFilter(status=CaseStatus.OPEN, sort_by="title", sort_order="asc"),
    )
    page2, _ = await repo.list_by_org(
        org_id,
        page=2,
        page_size=2,
        filters=CaseFilter(status=CaseStatus.OPEN, sort_by="title", sort_order="asc"),
    )

    assert total == 5
    assert len(page1) == 2
    assert len(page2) == 2
    assert {c.case_id for c in page1}.isdisjoint({c.case_id for c in page2})


@pytest.mark.asyncio
async def test_no_filters_argument_preserves_prior_behavior(
    postgres_engine,
) -> None:  # type: ignore[no-untyped-def]
    """list_by_org(org_id) with no filters kwarg at all must behave exactly
    as it did before Milestone IIIII -- callers that never pass filters
    (there are none left in src/, but this locks the contract in)."""
    repo = PostgresCaseRepository(postgres_engine)
    org_id = uuid.uuid4()
    await repo.save(_case(org_id, "Case A"))
    await repo.save(_case(org_id, "Case B"))

    cases, total = await repo.list_by_org(org_id)

    assert total == 2
    assert {c.metadata.title for c in cases} == {"Case A", "Case B"}
