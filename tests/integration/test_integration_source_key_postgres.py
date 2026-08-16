"""Integration tests for PostgresIntegrationSourceKeyRepository (Milestone
W8, Gap Audit P1-7) against a real testcontainers Postgres.

Requires: Docker (Postgres 16 container via testcontainers). Run with:
  pytest tests/integration/ -v -m integration

Complements ``poc/integration_source_key_provisioning/`` (real dev-stack
Postgres, full HTTP route + push-authentication round trip per CLAUDE.md
SS F) -- this file is the pytest-automated, repeatable proof that the
repository's own SQL is correct against a genuinely fresh Postgres schema.
"""

from __future__ import annotations

import uuid

import pytest

pytestmark = pytest.mark.integration


async def _repo(postgres_engine):  # type: ignore[no-untyped-def]
    from src.adapter.repository.postgres_integration_source_key import (
        PostgresIntegrationSourceKeyRepository,
    )

    await PostgresIntegrationSourceKeyRepository.create_tables(postgres_engine)
    return PostgresIntegrationSourceKeyRepository(postgres_engine)


@pytest.mark.asyncio
async def test_provision_then_get_by_key_round_trips(postgres_engine) -> None:  # type: ignore[no-untyped-def]
    repo = await _repo(postgres_engine)
    org_id = uuid.uuid4()

    record = await repo.provision(org_id, "pg-s1", "wazuh")
    resolved = await repo.get_by_key(record.api_key)

    assert resolved is not None
    assert resolved.org_id == org_id
    assert resolved.source_id == "pg-s1"
    assert resolved.source_type == "wazuh"


@pytest.mark.asyncio
async def test_plaintext_key_never_persisted_in_the_row(postgres_engine) -> None:  # type: ignore[no-untyped-def]
    """Reads the raw row back via a direct SELECT and confirms the
    plaintext key appears nowhere in it -- only the hash column."""
    from src.adapter.repository.postgres_integration_source_key import (
        integration_source_keys_table,
    )

    repo = await _repo(postgres_engine)
    org_id = uuid.uuid4()
    record = await repo.provision(org_id, "pg-s2", "wazuh")

    async with postgres_engine.connect() as conn:
        row = (
            await conn.execute(
                integration_source_keys_table.select().where(
                    integration_source_keys_table.c.org_id == org_id,
                    integration_source_keys_table.c.source_id == "pg-s2",
                )
            )
        ).one()

    row_values = [str(v) for v in row._asdict().values()]
    assert not any(record.api_key in v for v in row_values)


@pytest.mark.asyncio
async def test_revoke_then_get_by_key_returns_none(postgres_engine) -> None:  # type: ignore[no-untyped-def]
    repo = await _repo(postgres_engine)
    org_id = uuid.uuid4()
    record = await repo.provision(org_id, "pg-s3", "wazuh")

    await repo.revoke(org_id, "pg-s3")

    assert await repo.get_by_key(record.api_key) is None


@pytest.mark.asyncio
async def test_list_by_org_excludes_plaintext_and_is_org_scoped(postgres_engine) -> None:  # type: ignore[no-untyped-def]
    repo = await _repo(postgres_engine)
    org_a, org_b = uuid.uuid4(), uuid.uuid4()
    await repo.provision(org_a, "pg-s4", "wazuh")
    await repo.provision(org_b, "pg-s5", "crowdstrike")

    summaries = await repo.list_by_org(org_a)

    assert len(summaries) == 1
    assert summaries[0].source_id == "pg-s4"
    assert not hasattr(summaries[0], "api_key")


@pytest.mark.asyncio
async def test_reprovision_rotates_key_on_real_postgres(postgres_engine) -> None:  # type: ignore[no-untyped-def]
    repo = await _repo(postgres_engine)
    org_id = uuid.uuid4()
    first = await repo.provision(org_id, "pg-s6", "wazuh")
    second = await repo.provision(org_id, "pg-s6", "wazuh")

    assert first.api_key != second.api_key
    assert await repo.get_by_key(first.api_key) is None
    assert await repo.get_by_key(second.api_key) is not None
