#!/usr/bin/env python3
"""Verification-first PoC: real MetricCalculators against the live dev
stack's own real historical data (roadmap M8/I2).

Pinned versions/services (all real, running `docker-*-1` containers already
up from this session's own H1-I1 PoC work, confirmed via
`docker compose -f docker/docker-compose.dev.yml ps` before this ran):
  - Postgres 16 (docker-postgres-1) -- real `detections`, `audit_log`,
    `sealed_batches` rows from this session's own prior H1-I1 PoC runs.
    sqlalchemy 2.0.51 / asyncpg 0.31.0 (same as poc/batch_sealing/).
  - Redis 7 (docker-redis-1) -- confirmed EMPTY (`DBSIZE` == 0) at the start
    of this run: the D1-D5 session's own real Streams data does not survive
    a restart (no AOF/RDB persistence configured for the dev compose Redis).
    This is itself a real finding, not a PoC inconvenience -- see README.md.
  - OpenSearch 2.11.1 (docker-opensearch-1) -- real indexed timeline
    documents + real Security Analytics prepackaged-rule catalogue
    (opensearch-py 3.2, same client class as every other OpenSearch PoC).
  - MinIO (docker-minio-1) -- used only for the one live sealer-lag
    round-trip below (S3SealedBatchStorage, boto3, same creds as
    poc/batch_sealing/).

This script exercises the real, unmodified src/ classes:
  src/application/metric_calculator.py  -- MetricCalculator/MetricRegistry/MetricsService
  src/application/metric_mttd.py        -- MeanTimeToDetectCalculator
  src/application/metric_fp_rate.py     -- FalsePositiveRateCalculator
  src/application/metric_rule_coverage.py -- RuleCoverageCalculator
  src/application/metric_sealer_lag.py  -- SealerLagCalculator
  src/adapter/opensearch/rule_catalog.py -- SecurityAnalyticsRuleCatalog
  src/adapter/repository/postgres_detection.py
  src/adapter/repository/postgres_audit_log.py
  src/adapter/repository/postgres_sealed_batch.py (+ its new
      list_source_ids_for_org method, added alongside this item)
  src/adapter/opensearch/client.py      -- OpenSearchClient
  src/adapter/queue/stream_ingest.py    -- RedisStreamIngestAdapter
  src/application/batch_sealing.py      -- BatchSealingService (live round-trip only)

Three real scenarios:
  1. Compute all 4 metrics for the org with the most real historical data
     (kronos-dev, org_id 482072f5-8086-4815-be03-879cc2eaecb5 -- 796 real
     Detections, 10 real triage-transition audit events, several real
     sealed batches from this session's own prior work).
  2. Compute all 4 metrics for a near-empty org to demonstrate the honest
     "insufficient data" path actually returns None + a real reason string,
     never a fabricated 0%/100%.
  3. A live sealer-lag round-trip: since Redis has no surviving stream data,
     produce a few REAL fresh stream messages, run one real
     BatchSealingService.seal_pending() cycle (real MinIO WORM write, real
     Postgres row, real audit event -- TSA omitted, see README.md), leave
     a few more messages unconsumed, and show SealerLagCalculator surface
     the real, live, non-zero backlog this produces.

Run: ~/venv/bin/python3 poc/metrics_kpis/run_poc.py
"""

from __future__ import annotations

import asyncio
import json
import sys
import uuid
from dataclasses import asdict, is_dataclass
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from redis.asyncio import Redis as AsyncRedis  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from src.adapter.opensearch.client import OpenSearchClient  # noqa: E402
from src.adapter.opensearch.rule_catalog import SecurityAnalyticsRuleCatalog  # noqa: E402
from src.adapter.queue.stream_ingest import RedisStreamIngestAdapter  # noqa: E402
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository  # noqa: E402
from src.adapter.repository.postgres_detection import PostgresDetectionRepository  # noqa: E402
from src.adapter.repository.postgres_sealed_batch import PostgresSealedBatchRepository  # noqa: E402
from src.adapter.storage.sealed_batch_storage import S3SealedBatchStorage  # noqa: E402
from src.application.audit_log import AuditLogService  # noqa: E402
from src.application.batch_sealing import BatchSealingService  # noqa: E402
from src.application.metric_calculator import MetricRegistry, MetricsService  # noqa: E402
from src.application.metric_fp_rate import FalsePositiveRateCalculator  # noqa: E402
from src.application.metric_mttd import MeanTimeToDetectCalculator  # noqa: E402
from src.application.metric_rule_coverage import RuleCoverageCalculator  # noqa: E402
from src.application.metric_sealer_lag import SealerLagCalculator  # noqa: E402
from src.application.sealing_trigger_policy import SizeBoundTriggerPolicy  # noqa: E402
from src.domain.user import Role, TenantContext  # noqa: E402

DATABASE_URL = "postgresql+asyncpg://kronos:kronos_dev_password@localhost:5432/kronos"
REDIS_STREAM_DSN = "redis://localhost:6379/3"
OPENSEARCH_HOST = "localhost"
OPENSEARCH_PORT = 9200
OPENSEARCH_USER = "admin"
OPENSEARCH_PASSWORD = "admin"
MINIO_ENDPOINT = "http://localhost:9000"
MINIO_ACCESS_KEY = "kronos_minio"
MINIO_SECRET_KEY = "kronos_minio_dev_password"

# Real org from this session's own prior H1-I1 work (confirmed via direct
# `SELECT org_id, count(*) FROM detections GROUP BY org_id` -- see README.md).
KRONOS_DEV_ORG_ID = uuid.UUID("482072f5-8086-4815-be03-879cc2eaecb5")
KRONOS_DEV_ORG_ALIAS = "kronos-dev"

# A real org with exactly 1 Detection and zero triage transitions/sealed
# batches -- picked from the same real query, not invented, to exercise the
# honest "insufficient data" path for real.
SPARSE_ORG_ID = uuid.UUID("d98979e9-2151-4da7-a76b-4cc790c8d688")
SPARSE_ORG_ALIAS = "kronos-dbg"

LIVE_DEMO_SOURCE_ID = "kronos-i2-metrics-live-demo"


def _tenant(org_id: uuid.UUID, org_alias: str) -> TenantContext:
    """Synthetic scaffolding TenantContext for this driver script only --
    only org_id is read by any MetricCalculator (verified: none of the four
    read org_alias/user_id/username/roles/acr); a real caller always gets a
    genuine authenticated TenantContext from FastAPI's own auth middleware."""
    return TenantContext(
        org_id=org_id,
        org_alias=org_alias,
        user_id=uuid.uuid4(),
        username="metrics-poc-driver",
        roles=frozenset({Role.ORG_ADMIN}),
        correlation_id=str(uuid.uuid4()),
    )


def _json_default(obj):
    if isinstance(obj, uuid.UUID):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    return str(obj)


async def print_metric_results(label: str, results: list) -> None:
    print(f"\n=== {label} ===")
    for r in results:
        print(json.dumps(r.model_dump(), indent=2, default=_json_default))


async def main() -> None:
    engine = create_async_engine(DATABASE_URL, pool_size=5)
    redis_client = AsyncRedis.from_url(REDIS_STREAM_DSN)

    detection_repo = PostgresDetectionRepository(engine)
    audit_repo = PostgresAuditLogRepository(engine)
    sealed_batch_repo = PostgresSealedBatchRepository(engine)
    stream_adapter = RedisStreamIngestAdapter(redis_client)
    opensearch = OpenSearchClient(
        hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
        http_auth=(OPENSEARCH_USER, OPENSEARCH_PASSWORD),
        use_ssl=True,
        verify_certs=False,
    )
    rule_catalog = SecurityAnalyticsRuleCatalog(
        base_url=f"https://{OPENSEARCH_HOST}:{OPENSEARCH_PORT}",
        admin_username=OPENSEARCH_USER,
        admin_password=OPENSEARCH_PASSWORD,
    )

    registry = MetricRegistry()
    registry.register(MeanTimeToDetectCalculator(detection_repo, opensearch))
    registry.register(FalsePositiveRateCalculator(audit_repo))
    registry.register(RuleCoverageCalculator(detection_repo, rule_catalog))
    registry.register(SealerLagCalculator(sealed_batch_repo, stream_adapter))
    service = MetricsService(registry)

    print("Registered metrics:", registry.all_metric_names())

    # --- Sanity: confirm Redis really has zero stream keys right now
    # (documented finding, not assumed) ---
    dbsize = await redis_client.dbsize()
    print(f"\nRedis DBSIZE on stream db (redis://localhost:6379/3): {dbsize}")

    # --- Scenario 1: real, data-rich org ---
    tenant_dev = _tenant(KRONOS_DEV_ORG_ID, KRONOS_DEV_ORG_ALIAS)
    results_dev = await service.compute_all(tenant_dev)
    await print_metric_results(f"Scenario 1: kronos-dev ({KRONOS_DEV_ORG_ID})", results_dev)

    # --- Scenario 2: sparse org, honest "unavailable" path ---
    tenant_sparse = _tenant(SPARSE_ORG_ID, SPARSE_ORG_ALIAS)
    results_sparse = await service.compute_all(tenant_sparse)
    await print_metric_results(f"Scenario 2: sparse org ({SPARSE_ORG_ID})", results_sparse)

    # --- Scenario 3: live sealer-lag round-trip ---
    print(f"\n=== Scenario 3: live sealer-lag round-trip on '{LIVE_DEMO_SOURCE_ID}' ===")
    sealer_lag_calc = SealerLagCalculator(sealed_batch_repo, stream_adapter)

    before = await sealer_lag_calc.compute(tenant_dev)
    print("Before any live activity on this fresh source (expected: not in list yet):")
    print(json.dumps(before.model_dump(), indent=2, default=_json_default))

    storage = S3SealedBatchStorage(
        endpoint_url=MINIO_ENDPOINT, access_key=MINIO_ACCESS_KEY, secret_key=MINIO_SECRET_KEY
    )
    sealing_service = BatchSealingService(
        stream_adapter=stream_adapter,
        storage=storage,
        timestamp_service=None,  # TSA omitted -- see README.md "what was not verified"
        audit_log=AuditLogService(audit_repo),
        repository=sealed_batch_repo,
        trigger_policy=SizeBoundTriggerPolicy(max_events=3),
    )

    for i in range(3):
        await stream_adapter.produce(
            KRONOS_DEV_ORG_ID, LIVE_DEMO_SOURCE_ID, f"live-metrics-poc-event-{i}".encode()
        )
    sealed = await sealing_service.seal_pending(KRONOS_DEV_ORG_ID, LIVE_DEMO_SOURCE_ID)
    print(f"Real seal_pending() result: batch_id={sealed.batch_id if sealed else None}, "
          f"event_count={sealed.event_count if sealed else None}")

    # Produce more events WITHOUT consuming them -- a real, undelivered
    # backlog (the "lag" failure mode, not "pending").
    for i in range(4):
        await stream_adapter.produce(
            KRONOS_DEV_ORG_ID, LIVE_DEMO_SOURCE_ID, f"live-metrics-poc-unconsumed-{i}".encode()
        )

    after = await sealer_lag_calc.compute(tenant_dev)
    print("\nAfter one real seal + 4 real un-consumed messages left behind:")
    print(json.dumps(after.model_dump(), indent=2, default=_json_default))

    await opensearch.close()
    await redis_client.aclose()
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
