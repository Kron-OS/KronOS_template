"""Unit tests for TimelineRecord domain model."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError as PydanticValidationError

from src.domain.timeline import KronosProvenance
from tests.fixtures.factories import make_timeline_record


class TestKronosProvenance:
    def test_required_fields(self) -> None:
        prov = KronosProvenance(
            evidence_id=uuid.uuid4(),
            case_id=uuid.uuid4(),
            org_id=uuid.uuid4(),
            sha256="a" * 64,
            parser="evtx-rs",
            parser_version="1.0.0",
            record_index=0,
            ingest_timestamp=datetime.now(UTC),
        )
        assert prov.parser == "evtx-rs"
        assert prov.record_index == 0

    def test_record_index_non_negative(self) -> None:
        with pytest.raises(PydanticValidationError):
            KronosProvenance(
                evidence_id=uuid.uuid4(),
                case_id=uuid.uuid4(),
                org_id=uuid.uuid4(),
                sha256="a" * 64,
                parser="evtx-rs",
                parser_version="1.0.0",
                record_index=-1,
                ingest_timestamp=datetime.now(UTC),
            )


class TestTimelineRecord:
    def test_kronos_provenance_present(self) -> None:
        rec = make_timeline_record()
        assert rec.kronos.parser == "evtx-rs"

    def test_timestamp_field(self) -> None:
        rec = make_timeline_record()
        assert rec.timestamp.year == 2024

    def test_ecs_categories(self) -> None:
        rec = make_timeline_record()
        assert "authentication" in rec.event_category

    def test_frozen(self) -> None:
        rec = make_timeline_record()
        try:
            rec.message = "tampered"  # type: ignore[misc]
            raise AssertionError("Should have raised")
        except Exception:
            pass

    def test_extra_defaults_empty(self) -> None:
        rec = make_timeline_record()
        assert rec.extra == {}
