"""Unit tests for ForensicParser ABC and document_id helper."""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime

import pytest

from src.application.parsing import ForensicParser, ParserType
from src.application.parsing_orchestration import _make_document_id
from src.domain.artifact import StructuredArtifact
from src.domain.evidence import Evidence
from src.domain.timeline import KronosProvenance, TimelineRecord
from src.domain.user import TenantContext
from tests.fixtures.factories import make_evidence, make_tenant_context

# ---------------------------------------------------------------------------
# A minimal concrete parser for testing the abstract contract
# ---------------------------------------------------------------------------


class FakeParser(ForensicParser):
    """Controllable parser that yields a fixed number of synthetic records."""

    def __init__(self, record_count: int = 3, accept_ext: str = ".fake") -> None:
        self._count = record_count
        self._accept_ext = accept_ext

    @property
    def parser_name(self) -> str:
        return "fake"

    @property
    def parser_version(self) -> str:
        return "0.1.0"

    @property
    def parser_type(self) -> ParserType:
        return ParserType.FAST

    def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
        return filename.endswith(self._accept_ext)

    async def parse(  # type: ignore[override]
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[TimelineRecord]:
        for i in range(self._count):
            yield TimelineRecord(
                **{
                    "@timestamp": datetime(2024, 1, 1, 12, i, 0, tzinfo=UTC),
                    "message": f"fake event {i}",
                    "event.kind": "event",
                },
                kronos=KronosProvenance(
                    evidence_id=evidence.evidence_id,
                    case_id=evidence.metadata.case_id,
                    org_id=evidence.metadata.org_id,
                    sha256=evidence.sha256 or "",
                    parser=self.parser_name,
                    parser_version=self.parser_version,
                    record_index=i,
                    ingest_timestamp=datetime.now(UTC),
                ),
            )


class EmptyParser(FakeParser):
    """Parser that yields no records."""

    def __init__(self) -> None:
        super().__init__(record_count=0, accept_ext=".empty")


class FakeArtifactModule(FakeParser):
    """A module that opts into the new extract_artifacts() capability --
    the real-world shape a future VolatilityModule would take (yields both
    TimelineRecord via parse() AND StructuredArtifact via
    extract_artifacts(), see reviews/Data_Source_Module_System.md)."""

    async def extract_artifacts(  # type: ignore[override]
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[StructuredArtifact]:
        yield StructuredArtifact(
            kind="test.pstree",
            content={"pid": 4, "children": [{"pid": 812, "children": []}]},
            kronos=KronosProvenance(
                evidence_id=evidence.evidence_id,
                case_id=evidence.metadata.case_id,
                org_id=evidence.metadata.org_id,
                sha256=evidence.sha256 or "",
                parser=self.parser_name,
                parser_version=self.parser_version,
                record_index=0,
                ingest_timestamp=datetime.now(UTC),
            ),
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _drain(it: AsyncIterator[TimelineRecord]) -> list[TimelineRecord]:
    records = []
    async for rec in it:
        records.append(rec)
    return records


async def _empty_stream() -> AsyncIterator[bytes]:
    return
    yield b""  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestFakeParser:
    def test_supports_correct_extension(self) -> None:
        parser = FakeParser()
        assert parser.supports("test.fake", "application/octet-stream", b"") is True

    def test_does_not_support_other_extension(self) -> None:
        parser = FakeParser()
        assert parser.supports("test.json", "application/json", b"") is False

    @pytest.mark.asyncio
    async def test_yields_expected_number_of_records(self) -> None:
        parser = FakeParser(record_count=5)
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_empty_stream(), evidence, tenant))
        assert len(records) == 5

    @pytest.mark.asyncio
    async def test_timeline_record_has_kronos_provenance(self) -> None:
        parser = FakeParser(record_count=1)
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_empty_stream(), evidence, tenant))
        assert records[0].kronos is not None
        assert records[0].kronos.evidence_id == evidence.evidence_id

    @pytest.mark.asyncio
    async def test_record_index_is_sequential(self) -> None:
        parser = FakeParser(record_count=4)
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_empty_stream(), evidence, tenant))
        indices = [r.kronos.record_index for r in records]
        assert indices == [0, 1, 2, 3]

    @pytest.mark.asyncio
    async def test_parse_empty_stream_yields_nothing(self) -> None:
        parser = EmptyParser()
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_empty_stream(), evidence, tenant))
        assert records == []


class TestExtractArtifacts:
    """extract_artifacts() -- the module-system generalization
    (reviews/Data_Source_Module_System.md). Default must be a true no-op
    for every parser that doesn't override it (zero migration cost)."""

    @pytest.mark.asyncio
    async def test_default_yields_nothing_for_existing_parsers(self) -> None:
        parser = FakeParser(record_count=3)
        evidence = make_evidence()
        tenant = make_tenant_context()
        artifacts = [
            a async for a in parser.extract_artifacts(_empty_stream(), evidence, tenant)
        ]
        assert artifacts == []

    @pytest.mark.asyncio
    async def test_default_does_not_affect_parse(self) -> None:
        # A parser that never overrides extract_artifacts() must keep
        # producing exactly the same parse() output as before this method
        # existed -- this is the whole "zero migration cost" claim.
        parser = FakeParser(record_count=5)
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_empty_stream(), evidence, tenant))
        assert len(records) == 5

    @pytest.mark.asyncio
    async def test_opted_in_module_yields_structured_artifact(self) -> None:
        parser = FakeArtifactModule(record_count=1)
        evidence = make_evidence()
        tenant = make_tenant_context()
        artifacts = [
            a async for a in parser.extract_artifacts(_empty_stream(), evidence, tenant)
        ]
        assert len(artifacts) == 1
        assert artifacts[0].kind == "test.pstree"
        assert artifacts[0].content["pid"] == 4
        assert artifacts[0].kronos.evidence_id == evidence.evidence_id

    @pytest.mark.asyncio
    async def test_opted_in_module_still_yields_timeline_records_too(self) -> None:
        # A single module can produce BOTH shapes -- the core design point
        # (one module, mixed output), not a parallel class hierarchy.
        parser = FakeArtifactModule(record_count=2)
        evidence = make_evidence()
        tenant = make_tenant_context()
        records = await _drain(parser.parse(_empty_stream(), evidence, tenant))
        artifacts = [
            a async for a in parser.extract_artifacts(_empty_stream(), evidence, tenant)
        ]
        assert len(records) == 2
        assert len(artifacts) == 1


class TestDocumentId:
    def test_document_id_is_deterministic(self) -> None:
        eid = uuid.uuid4()
        d1 = _make_document_id(eid, "cloudtrail", 42)
        d2 = _make_document_id(eid, "cloudtrail", 42)
        assert d1 == d2

    def test_document_id_changes_with_record_index(self) -> None:
        eid = uuid.uuid4()
        assert _make_document_id(eid, "cloudtrail", 0) != _make_document_id(eid, "cloudtrail", 1)

    def test_document_id_changes_with_parser_name(self) -> None:
        eid = uuid.uuid4()
        assert _make_document_id(eid, "cloudtrail", 0) != _make_document_id(eid, "nginx", 0)

    def test_document_id_is_sha1_hex(self) -> None:
        eid = uuid.uuid4()
        doc_id = _make_document_id(eid, "cloudtrail", 0)
        assert len(doc_id) == 40
        assert all(c in "0123456789abcdef" for c in doc_id)

    def test_document_id_matches_manual_sha1(self) -> None:
        eid = uuid.UUID("12345678-1234-5678-1234-567812345678")
        expected_input = f"{eid}:nginx:7"
        expected = hashlib.sha1(expected_input.encode()).hexdigest()
        assert _make_document_id(eid, "nginx", 7) == expected
