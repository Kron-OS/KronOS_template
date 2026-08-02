"""Unit tests for DetectionSyncService (mock only the OpenSearch findings client)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from src.adapter.opensearch.client import InMemoryOpenSearchClient
from src.adapter.opensearch.findings_client import FindingsClient
from src.adapter.repository.detection import InMemoryDetectionRepository
from src.application.audit_log import AuditLogService
from src.application.detection_sync import DetectionSyncService, _extract_case_id
from src.domain.audit import AuditEventType
from tests.conftest import InMemoryAuditLogRepository
from tests.fixtures.factories import make_tenant_context

_CASE_ID = "1a49dcd0-b6a6-4410-83aa-def7ffc9f9fa"


def _real_finding_hit(
    finding_id: str,
    *,
    monitor_name: str = "kronos-testorg-network-detector",
    source_index: str = f"kronos-testorg-case-{_CASE_ID}-202601",
    timestamp_ms: int = 1785423677843,
) -> dict[str, Any]:
    """Shaped exactly like a real SA finding document (verified against a
    live OpenSearch 2.11.1 cluster -- see poc/detection_finding_sync/)."""
    return {
        "_index": ".opensearch-sap-network-findings-2026.07.29-1",
        "_id": finding_id,
        "_source": {
            "id": finding_id,
            "related_doc_ids": ["f648d8e8-32fd-4217-b51d-1645d34d83a4"],
            "correlated_doc_ids": ["f648d8e8-32fd-4217-b51d-1645d34d83a4"],
            "monitor_id": "S8yIs58BG52zb-VTinMn",
            "monitor_name": monitor_name,
            "index": source_index,
            "queries": [
                {
                    "id": "1fc0809e-06bf-4de3-ad52-25e5263b7623",
                    "name": "1fc0809e-06bf-4de3-ad52-25e5263b7623",
                    "tags": ["high", "network", "attack.t1021.001"],
                }
            ],
            "timestamp": timestamp_ms,
            "execution_id": None,
        },
    }


class _FakeFindingsClient(FindingsClient):
    def __init__(self, hits: list[dict[str, Any]]) -> None:
        self._hits = hits
        self.calls: list[tuple[str, tuple[str, ...]]] = []

    async def fetch_org_findings(
        self, org_alias: str, log_types: tuple[str, ...]
    ) -> list[dict[str, Any]]:
        self.calls.append((org_alias, log_types))
        return self._hits


def _make_service(
    hits: list[dict[str, Any]], timeline_index: InMemoryOpenSearchClient | None = None
) -> tuple[DetectionSyncService, InMemoryDetectionRepository, InMemoryAuditLogRepository]:
    audit_repo = InMemoryAuditLogRepository()
    audit_log = AuditLogService(audit_repo)
    detection_repo = InMemoryDetectionRepository()
    findings_client = _FakeFindingsClient(hits)
    service = DetectionSyncService(
        findings_client,
        detection_repo,
        audit_log,
        timeline_index=timeline_index or InMemoryOpenSearchClient(),
        log_types=("network",),
    )
    return service, detection_repo, audit_repo


class TestExtractCaseId:
    def test_extracts_case_id_from_real_index_naming_convention(self) -> None:
        assert _extract_case_id(f"kronos-acme-case-{_CASE_ID}-202601") == uuid.UUID(_CASE_ID)

    def test_returns_none_for_unrecognized_index_name(self) -> None:
        assert _extract_case_id("kronos-acme-stream-syslog-202601") is None

    def test_returns_none_for_empty_string(self) -> None:
        assert _extract_case_id("") is None


class TestDetectionSyncService:
    @pytest.mark.asyncio
    async def test_creates_one_detection_per_new_finding(self) -> None:
        hits = [_real_finding_hit("finding-1"), _real_finding_hit("finding-2")]
        service, repo, _ = _make_service(hits)
        tenant = make_tenant_context()

        created = await service.sync_org_findings(tenant)

        assert created == 2
        stored = [d async for d in repo.stream_by_org(tenant.org_id)]
        assert {d.finding_id for d in stored} == {"finding-1", "finding-2"}

    @pytest.mark.asyncio
    async def test_org_id_comes_from_tenant_never_from_finding(self) -> None:
        """Invariant #3: even if a finding claimed a different org somehow,
        the stored Detection's org_id must be the syncing tenant's own."""
        hits = [_real_finding_hit("finding-1")]
        service, repo, _ = _make_service(hits)
        tenant = make_tenant_context()

        await service.sync_org_findings(tenant)

        stored = [d async for d in repo.stream_by_org(tenant.org_id)][0]
        assert stored.org_id == tenant.org_id
        assert stored.org_alias == tenant.org_alias

    @pytest.mark.asyncio
    async def test_new_detection_starts_in_new_triage_state(self) -> None:
        hits = [_real_finding_hit("finding-1")]
        service, repo, _ = _make_service(hits)
        tenant = make_tenant_context()

        await service.sync_org_findings(tenant)

        stored = [d async for d in repo.stream_by_org(tenant.org_id)][0]
        assert stored.triage_state.value == "NEW"

    @pytest.mark.asyncio
    async def test_stores_real_rule_id_for_replayability(self) -> None:
        hits = [_real_finding_hit("finding-1")]
        service, repo, _ = _make_service(hits)
        tenant = make_tenant_context()

        await service.sync_org_findings(tenant)

        stored = [d async for d in repo.stream_by_org(tenant.org_id)][0]
        assert stored.rule_matches[0].rule_id == "1fc0809e-06bf-4de3-ad52-25e5263b7623"
        assert stored.attack_tags == ("attack.t1021.001",)

    @pytest.mark.asyncio
    async def test_case_id_extracted_from_source_index(self) -> None:
        hits = [_real_finding_hit("finding-1")]
        service, repo, _ = _make_service(hits)
        tenant = make_tenant_context()

        await service.sync_org_findings(tenant)

        stored = [d async for d in repo.stream_by_org(tenant.org_id)][0]
        assert stored.case_id == uuid.UUID(_CASE_ID)

    @pytest.mark.asyncio
    async def test_rerun_is_idempotent_no_duplicates(self) -> None:
        hits = [_real_finding_hit("finding-1"), _real_finding_hit("finding-2")]
        service, repo, _ = _make_service(hits)
        tenant = make_tenant_context()

        first_created = await service.sync_org_findings(tenant)
        second_created = await service.sync_org_findings(tenant)

        assert first_created == 2
        assert second_created == 0
        stored = [d async for d in repo.stream_by_org(tenant.org_id)]
        assert len(stored) == 2

    @pytest.mark.asyncio
    async def test_sync_creates_audit_event_per_new_detection(self) -> None:
        hits = [_real_finding_hit("finding-1")]
        service, _, audit_repo = _make_service(hits)
        tenant = make_tenant_context()

        await service.sync_org_findings(tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        synced_events = [e for e in events if e.event_type == AuditEventType.DETECTION_SYNCED]
        assert len(synced_events) == 1
        assert synced_events[0].details["finding_id"] == "finding-1"

    @pytest.mark.asyncio
    async def test_rerun_produces_no_additional_audit_events(self) -> None:
        hits = [_real_finding_hit("finding-1")]
        service, _, audit_repo = _make_service(hits)
        tenant = make_tenant_context()

        await service.sync_org_findings(tenant)
        await service.sync_org_findings(tenant)

        events = [e async for e in audit_repo.stream_by_org(tenant.org_id)]
        synced_events = [e for e in events if e.event_type == AuditEventType.DETECTION_SYNCED]
        assert len(synced_events) == 1

    @pytest.mark.asyncio
    async def test_findings_client_queried_with_tenant_org_alias(self) -> None:
        hits: list[dict[str, Any]] = []
        service, _, _ = _make_service(hits)
        tenant = make_tenant_context()

        await service.sync_org_findings(tenant)

        findings_client = service._findings_client  # noqa: SLF001
        assert findings_client.calls == [(tenant.org_alias, ("network",))]

    @pytest.mark.asyncio
    async def test_no_findings_returns_zero(self) -> None:
        service, repo, _ = _make_service([])
        tenant = make_tenant_context()

        created = await service.sync_org_findings(tenant)

        assert created == 0
        assert [d async for d in repo.stream_by_org(tenant.org_id)] == []

    @pytest.mark.asyncio
    async def test_pre_existing_detection_is_not_recreated(self) -> None:
        """If a Detection for this finding already exists (e.g. a previous
        sync call, or one that lost a race), the pre-check must find it and
        skip -- must not raise, must not double count."""
        hits = [_real_finding_hit("finding-1")]
        service, repo, _ = _make_service(hits)
        tenant = make_tenant_context()

        from datetime import UTC as _UTC
        from datetime import datetime as _datetime

        from src.domain.detection import Detection

        await repo.save(
            Detection(
                org_id=tenant.org_id,
                org_alias=tenant.org_alias,
                finding_id="finding-1",
                detector_name="kronos-testorg-network-detector",
                source_index=f"kronos-testorg-case-{_CASE_ID}-202601",
                finding_timestamp=_datetime.now(_UTC),
            )
        )

        created = await service.sync_org_findings(tenant)

        assert created == 0
        assert len([d async for d in repo.stream_by_org(tenant.org_id)]) == 1

    @pytest.mark.asyncio
    async def test_save_race_after_precheck_is_swallowed_not_raised(self) -> None:
        """A concurrent sync call can win the (org_id, finding_id) uniqueness
        race strictly between our own get_by_finding_id pre-check and our
        save() call. The repository's save() is the real backstop for this
        (a unique constraint in Postgres) -- verify DetectionSyncService
        treats that specific failure as "already synced elsewhere", not a
        hard error that aborts the whole sync run."""
        from src.exceptions import StorageError

        hits = [_real_finding_hit("finding-1"), _real_finding_hit("finding-2")]

        class _RaceyRepository(InMemoryDetectionRepository):
            async def save(self, detection):  # type: ignore[override]
                if detection.finding_id == "finding-1":
                    raise StorageError("simulated unique-constraint race")
                return await super().save(detection)

        audit_repo = InMemoryAuditLogRepository()
        audit_log = AuditLogService(audit_repo)
        repo = _RaceyRepository()
        findings_client = _FakeFindingsClient(hits)
        service = DetectionSyncService(
            findings_client,
            repo,
            audit_log,
            timeline_index=InMemoryOpenSearchClient(),
            log_types=("network",),
        )
        tenant = make_tenant_context()

        created = await service.sync_org_findings(tenant)

        # finding-1 raced and lost (not counted, not raised); finding-2 is
        # entirely unaffected -- one failure must not abort the whole sync.
        assert created == 1
        stored = [d async for d in repo.stream_by_org(tenant.org_id)]
        assert {d.finding_id for d in stored} == {"finding-2"}


class TestDetectionSyncRiskScoring:
    """Roadmap M5/F4: risk_score/risk_factors computed ONCE at sync time
    from the real rule severity tag plus whatever enrichment.ioc.*/
    enrichment.asset.* fields the finding's own matched documents carry
    right now via the new get_documents_by_id mget-style read path."""

    _DOC_ID = "f648d8e8-32fd-4217-b51d-1645d34d83a4"
    _SOURCE_INDEX = f"kronos-testorg-case-{_CASE_ID}-202601"

    @pytest.mark.asyncio
    async def test_risk_score_from_rule_severity_alone_when_no_matched_document_found(self) -> None:
        """No document exists at the matched id (never indexed in this test's
        InMemoryOpenSearchClient) -- ioc_confidence/asset_criticality must be
        honestly absent, and the score must come from rule_severity alone:
        'high' -> normalized 0.75, weight 0.35 -> 0.75 * 100 = 75.0."""
        hits = [_real_finding_hit("finding-1")]
        service, repo, _ = _make_service(hits)
        tenant = make_tenant_context()

        await service.sync_org_findings(tenant)

        stored = [d async for d in repo.stream_by_org(tenant.org_id)][0]
        assert stored.rule_severity == "high"
        assert stored.risk_score == pytest.approx(75.0)
        by_name = {f.name: f for f in stored.risk_factors}
        assert by_name["rule_severity"].normalized_value == pytest.approx(0.75)
        assert by_name["ioc_confidence"].normalized_value is None
        assert by_name["asset_criticality"].normalized_value is None
        assert by_name["identity_privilege"].normalized_value is None
        assert len(stored.risk_factors) == 4

    @pytest.mark.asyncio
    async def test_risk_score_increases_with_real_matched_document_enrichment(self) -> None:
        """Same rule severity as above, but this time the matched document
        DOES exist and carries real enrichment.ioc.confidence=80 and
        enrichment.asset.criticality='critical' -- the score must be
        deterministically HIGHER than the rule-severity-only case, and the
        exact delta is reproducible from the documented formula:
        (0.35*0.75 + 0.30*0.80 + 0.20*1.0) / 0.85 * 100 = 82.65."""
        timeline_index = InMemoryOpenSearchClient()
        await timeline_index.bulk_index(
            [
                (
                    self._SOURCE_INDEX,
                    self._DOC_ID,
                    {
                        "enrichment": {
                            "ioc": {"confidence": 80},
                            "asset": {"criticality": "critical"},
                        }
                    },
                )
            ]
        )
        hits = [_real_finding_hit("finding-1")]
        service, repo, _ = _make_service(hits, timeline_index=timeline_index)
        tenant = make_tenant_context()

        await service.sync_org_findings(tenant)

        stored = [d async for d in repo.stream_by_org(tenant.org_id)][0]
        assert stored.risk_score == pytest.approx(82.65, abs=0.01)
        assert stored.risk_score > 75.0
        by_name = {f.name: f for f in stored.risk_factors}
        assert by_name["ioc_confidence"].normalized_value == pytest.approx(0.8)
        assert by_name["asset_criticality"].normalized_value == pytest.approx(1.0)

    @pytest.mark.asyncio
    async def test_risk_score_from_rule_severity_alone_when_finding_has_no_matched_documents(
        self,
    ) -> None:
        """A real finding with an empty related_doc_ids array (no matched
        documents at all, distinct from a matched id that doesn't resolve)
        must short-circuit _resolve_risk_inputs' own empty-list check and
        still score from rule_severity alone."""
        hit = _real_finding_hit("finding-1")
        hit["_source"]["related_doc_ids"] = []
        service, repo, _ = _make_service([hit])
        tenant = make_tenant_context()

        await service.sync_org_findings(tenant)

        stored = [d async for d in repo.stream_by_org(tenant.org_id)][0]
        assert stored.matched_document_ids == ()
        assert stored.risk_score == pytest.approx(75.0)

    @pytest.mark.asyncio
    async def test_risk_score_none_when_no_severity_tag_and_no_matched_documents(self) -> None:
        """Degenerate honest case: a finding whose matched rule carries no
        recognized severity tag and whose matched document doesn't resolve
        -- risk_score must be None (could not be scored), never a
        fabricated 0.0 that would misleadingly read as 'confirmed safe'."""
        hit = _real_finding_hit("finding-1")
        hit["_source"]["queries"][0]["tags"] = ["network", "attack.t1021.001"]
        service, repo, _ = _make_service([hit])
        tenant = make_tenant_context()

        await service.sync_org_findings(tenant)

        stored = [d async for d in repo.stream_by_org(tenant.org_id)][0]
        assert stored.rule_severity is None
        assert stored.risk_score is None

    @pytest.mark.asyncio
    async def test_risk_scoring_document_lookup_failure_degrades_honestly(self) -> None:
        """A real lookup failure (e.g. the source index no longer exists)
        must never sink the whole sync -- it degrades to an absent input,
        exactly like a genuinely missing document would."""

        class _BrokenTimelineIndex(InMemoryOpenSearchClient):
            async def get_documents_by_id(self, index: str, doc_ids: list[str]):  # type: ignore[override]
                raise RuntimeError("simulated real lookup failure")

        hits = [_real_finding_hit("finding-1")]
        service, repo, _ = _make_service(hits, timeline_index=_BrokenTimelineIndex())
        tenant = make_tenant_context()

        created = await service.sync_org_findings(tenant)

        assert created == 1
        stored = [d async for d in repo.stream_by_org(tenant.org_id)][0]
        assert stored.risk_score == pytest.approx(75.0)
