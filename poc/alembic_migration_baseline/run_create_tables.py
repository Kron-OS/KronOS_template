import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from src.adapter.repository.postgres_artifact import PostgresArtifactRepository
from src.adapter.repository.postgres_asset import PostgresAssetRepository
from src.adapter.repository.postgres_audit_log import PostgresAuditLogRepository
from src.adapter.repository.postgres_case import PostgresCaseRepository
from src.adapter.repository.postgres_dead_letter import PostgresDeadLetterSink
from src.adapter.repository.postgres_detection import PostgresDetectionRepository
from src.adapter.repository.postgres_detection_correlation import PostgresDetectionCorrelationRepository
from src.adapter.repository.postgres_evidence import PostgresEvidenceRepository
from src.adapter.repository.postgres_ioc_feed import PostgresIOCFeedRepository
from src.adapter.repository.postgres_quota import PostgresOrgQuotaRepository
from src.adapter.repository.postgres_rule_pack import PostgresRulePackRepository
from src.adapter.repository.postgres_sealed_batch import PostgresSealedBatchRepository
from src.adapter.repository.postgres_source_cursor import PostgresSourceCursorRepository
from src.adapter.repository.postgres_yara_rule_pack import PostgresYaraRulePackRepository

import os

async def main():
    url = os.environ["DATABASE_URL"]
    engine = create_async_engine(url, poolclass=NullPool)
    try:
        # Exact same call sequence as src/external/startup.py's
        # wire_dependencies_async() (before this V4 change removed them
        # from the real startup path).
        await PostgresAuditLogRepository.create_tables(engine)
        await PostgresEvidenceRepository.create_tables(engine)
        await PostgresCaseRepository.create_tables(engine)
        await PostgresArtifactRepository.create_tables(engine)
        await PostgresDetectionRepository.create_tables(engine)
        await PostgresDetectionCorrelationRepository.create_tables(engine)
        await PostgresRulePackRepository.create_tables(engine)
        await PostgresYaraRulePackRepository.create_tables(engine)
        await PostgresAssetRepository.create_tables(engine)
        await PostgresIOCFeedRepository.create_tables(engine)
        await PostgresSealedBatchRepository.create_tables(engine)
        await PostgresOrgQuotaRepository.create_tables(engine)
        await PostgresSourceCursorRepository.create_tables(engine)
        await PostgresDeadLetterSink.create_tables(engine)
        print("create_tables(): all 14 repositories done")
    finally:
        await engine.dispose()

asyncio.run(main())
