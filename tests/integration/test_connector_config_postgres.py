"""Integration tests for PostgresConnectorConfigRepository against a real
testcontainers Postgres (connector marketplace, `/admin/connectors`).

Complements poc/vault_secret_store/ (real Vault, per CLAUDE.md SS F) --
this file is the pytest-automated proof that the repository's own SQL
(composite PK upsert, JSON columns, circuit-breaker counters) is correct
against a genuinely fresh Postgres schema. Mirrors
test_integration_source_key_postgres.py's exact fixture/skip pattern.
"""

from __future__ import annotations

import uuid

import pytest

pytestmark = pytest.mark.integration


async def _repo(postgres_engine):  # type: ignore[no-untyped-def]
    from src.adapter.repository.postgres_connector_config import (
        PostgresConnectorConfigRepository,
    )

    await PostgresConnectorConfigRepository.create_tables(postgres_engine)
    return PostgresConnectorConfigRepository(postgres_engine)


@pytest.mark.asyncio
async def test_upsert_then_get_round_trips(postgres_engine) -> None:  # type: ignore[no-untyped-def]
    repo = await _repo(postgres_engine)
    org_id = uuid.uuid4()

    summary = await repo.upsert(
        org_id, "ms-defender-alerts", {"defender_tenant_id": "t1"}, ("defender_client_secret",)
    )
    resolved = await repo.get(org_id, "ms-defender-alerts")

    assert resolved is not None
    assert resolved.org_id == org_id
    assert resolved.enabled is True
    assert resolved.non_secret_fields == {"defender_tenant_id": "t1"}
    assert resolved.secret_field_names == ("defender_client_secret",)
    assert resolved.created_at == summary.created_at


@pytest.mark.asyncio
async def test_reupsert_resets_failure_state(postgres_engine) -> None:  # type: ignore[no-untyped-def]
    repo = await _repo(postgres_engine)
    org_id = uuid.uuid4()
    await repo.upsert(org_id, "splunk-hec", {"splunk_hec_url": "https://a"}, ("splunk_hec_token",))
    await repo.record_failure(org_id, "splunk-hec", auto_disable_threshold=1)

    disabled = await repo.get(org_id, "splunk-hec")
    assert disabled is not None and disabled.enabled is False and disabled.auto_disabled_at is not None

    await repo.upsert(org_id, "splunk-hec", {"splunk_hec_url": "https://b"}, ("splunk_hec_token",))
    refreshed = await repo.get(org_id, "splunk-hec")
    assert refreshed is not None
    assert refreshed.enabled is True
    assert refreshed.auto_disabled_at is None
    assert refreshed.consecutive_failure_count == 0
    assert refreshed.non_secret_fields == {"splunk_hec_url": "https://b"}


@pytest.mark.asyncio
async def test_record_failure_auto_disables_at_threshold(postgres_engine) -> None:  # type: ignore[no-untyped-def]
    repo = await _repo(postgres_engine)
    org_id = uuid.uuid4()
    await repo.upsert(org_id, "cef-syslog", {"cef_syslog_host": "h"}, ())

    for _ in range(2):
        await repo.record_failure(org_id, "cef-syslog", auto_disable_threshold=3)
    still_enabled = await repo.get(org_id, "cef-syslog")
    assert still_enabled is not None and still_enabled.enabled is True

    await repo.record_failure(org_id, "cef-syslog", auto_disable_threshold=3)
    disabled = await repo.get(org_id, "cef-syslog")
    assert disabled is not None
    assert disabled.enabled is False
    assert disabled.consecutive_failure_count == 3
    assert disabled.auto_disabled_at is not None


@pytest.mark.asyncio
async def test_set_enabled_true_clears_auto_disabled_state(postgres_engine) -> None:  # type: ignore[no-untyped-def]
    repo = await _repo(postgres_engine)
    org_id = uuid.uuid4()
    await repo.upsert(org_id, "cef-syslog", {"cef_syslog_host": "h"}, ())
    await repo.record_failure(org_id, "cef-syslog", auto_disable_threshold=1)

    await repo.set_enabled(org_id, "cef-syslog", True)
    resolved = await repo.get(org_id, "cef-syslog")
    assert resolved is not None
    assert resolved.enabled is True
    assert resolved.auto_disabled_at is None


@pytest.mark.asyncio
async def test_list_all_enabled_by_source_type_excludes_disabled_and_other_types(
    postgres_engine,  # type: ignore[no-untyped-def]
) -> None:
    # A synthetic, per-run-unique source_type (not a real catalog value):
    # postgres_engine is session-scoped (shared across every test in this
    # file, no truncation between tests -- see conftest.py's own comment),
    # so querying a real, commonly-reused source_type like
    # "ms-defender-alerts" here would pick up other tests' leftover rows
    # too. A real, reproduced flake this file's own earlier draft hit
    # before this fix.
    source_type = f"test-source-{uuid.uuid4()}"
    repo = await _repo(postgres_engine)
    org_a, org_b, org_c = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    await repo.upsert(org_a, source_type, {"defender_tenant_id": "a"}, ())
    await repo.upsert(org_b, source_type, {"defender_tenant_id": "b"}, ())
    await repo.set_enabled(org_b, source_type, False)
    await repo.upsert(org_c, "splunk-hec", {"splunk_hec_url": "https://c"}, ())

    enabled = await repo.list_all_enabled_by_source_type(source_type)

    assert {s.org_id for s in enabled} == {org_a}


@pytest.mark.asyncio
async def test_cross_org_isolation_delete_and_list(postgres_engine) -> None:  # type: ignore[no-untyped-def]
    """Hard requirement (CLAUDE.md 'no collision, independent per client'):
    deleting/listing one org's config must never affect another's."""
    repo = await _repo(postgres_engine)
    org_a, org_b = uuid.uuid4(), uuid.uuid4()
    await repo.upsert(org_a, "sentinel", {"sentinel_tenant_id": "a"}, ("sentinel_client_secret",))
    await repo.upsert(org_b, "sentinel", {"sentinel_tenant_id": "b"}, ("sentinel_client_secret",))

    await repo.delete(org_a, "sentinel")

    assert await repo.get(org_a, "sentinel") is None
    resolved_b = await repo.get(org_b, "sentinel")
    assert resolved_b is not None
    assert resolved_b.non_secret_fields == {"sentinel_tenant_id": "b"}
    assert [s.org_id for s in await repo.list_by_org(org_a)] == []
    assert [s.org_id for s in await repo.list_by_org(org_b)] == [org_b]
