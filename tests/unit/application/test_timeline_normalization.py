"""Unit tests for ECSNormalizer and build_index_name."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from src.application.timeline_normalization import ECSNormalizer, build_index_name
from tests.fixtures.factories import make_timeline_record


class TestBuildIndexName:
    def test_basic_pattern(self) -> None:
        ts = datetime(2024, 3, 15, tzinfo=UTC)
        name = build_index_name("acme", "3fa85f64-5717-4562-b3fc-2c963f66afa6", ts)
        assert name == "kronos-acme-case-3fa85f64-5717-4562-b3fc-2c963f66afa6-202403"

    def test_uppercase_org_alias_lowercased(self) -> None:
        ts = datetime(2024, 1, 1, tzinfo=UTC)
        name = build_index_name("ACME", "case-id", ts)
        assert name.startswith("kronos-acme-")

    def test_special_chars_in_org_alias_replaced(self) -> None:
        ts = datetime(2024, 6, 1, tzinfo=UTC)
        name = build_index_name("my org!", "case-id", ts)
        assert "!" not in name
        assert " " not in name

    def test_yyyymm_suffix(self) -> None:
        ts = datetime(2025, 12, 31, tzinfo=UTC)
        name = build_index_name("org", "cid", ts)
        assert name.endswith("-202512")

    def test_different_months_produce_different_names(self) -> None:
        ts1 = datetime(2024, 1, 1, tzinfo=UTC)
        ts2 = datetime(2024, 2, 1, tzinfo=UTC)
        assert build_index_name("org", "cid", ts1) != build_index_name("org", "cid", ts2)


class TestECSNormalizer:
    def setup_method(self) -> None:
        self.normalizer = ECSNormalizer()

    def test_timestamp_is_iso_string(self) -> None:
        record = make_timeline_record()
        doc = self.normalizer.to_document(record)
        assert isinstance(doc["@timestamp"], str)
        assert "T" in doc["@timestamp"]

    def test_ecs_event_block_present(self) -> None:
        record = make_timeline_record()
        doc = self.normalizer.to_document(record)
        assert "event" in doc
        assert doc["event"]["kind"] == "event"
        assert "authentication" in doc["event"]["category"]

    def test_kronos_block_present(self) -> None:
        record = make_timeline_record()
        doc = self.normalizer.to_document(record)
        assert "kronos" in doc
        k = doc["kronos"]
        assert k["parser"] == "evtx-rs"
        assert k["record_index"] == 0
        assert len(k["sha256"]) == 64

    def test_kronos_ids_are_strings(self) -> None:
        eid = uuid.uuid4()
        record = make_timeline_record(evidence_id=eid)
        doc = self.normalizer.to_document(record)
        assert doc["kronos"]["evidence_id"] == str(eid)

    def test_none_fields_omitted(self) -> None:
        record = make_timeline_record()
        doc = self.normalizer.to_document(record)
        # host, user, process are None on the factory record — their blocks should
        # be absent or their None sub-keys excluded.
        host_block = doc.get("host", {})
        assert "name" not in host_block or host_block["name"] is not None

    def test_message_included_when_set(self) -> None:
        record = make_timeline_record()
        doc = self.normalizer.to_document(record)
        assert doc.get("message") == "Test event"

    def test_extra_dotted_ecs_keys_are_nested(self) -> None:
        """Dotted extra keys like event.code must be nested, not stored as flat strings."""
        from src.domain.timeline import KronosProvenance, TimelineRecord

        record = TimelineRecord(
            **{
                "@timestamp": datetime(2024, 1, 1, tzinfo=UTC),
                "message": "x",
            },
            extra={"event.code": "4624", "custom_field": 42},
            kronos=KronosProvenance(
                evidence_id=uuid.uuid4(),
                case_id=uuid.uuid4(),
                org_id=uuid.uuid4(),
                sha256="b" * 64,
                parser="evtx-rs",
                parser_version="0.8",
                record_index=0,
                ingest_timestamp=datetime.now(UTC),
            ),
        )
        doc = self.normalizer.to_document(record)
        # event.code must be nested inside the event block, not a top-level dotted key
        assert "event.code" not in doc
        assert doc["event"]["code"] == "4624"
        # Non-dotted extra keys stay at top level
        assert doc["custom_field"] == 42

    def test_extra_deeply_nested_dotted_key(self) -> None:
        """Multi-segment dotted keys like winlog.event_data.SubjectUserName are deeply nested."""
        from src.domain.timeline import KronosProvenance, TimelineRecord

        record = TimelineRecord(
            **{"@timestamp": datetime(2024, 1, 1, tzinfo=UTC)},
            extra={"winlog.event_data.SubjectUserName": "SYSTEM"},
            kronos=KronosProvenance(
                evidence_id=uuid.uuid4(),
                case_id=uuid.uuid4(),
                org_id=uuid.uuid4(),
                sha256="d" * 64,
                parser="evtx-rs",
                parser_version="0.8",
                record_index=0,
                ingest_timestamp=datetime.now(UTC),
            ),
        )
        doc = self.normalizer.to_document(record)
        assert "winlog.event_data.SubjectUserName" not in doc
        assert doc["winlog"]["event_data"]["SubjectUserName"] == "SYSTEM"

    def test_ingest_timestamp_is_iso_string(self) -> None:
        record = make_timeline_record()
        doc = self.normalizer.to_document(record)
        assert isinstance(doc["kronos"]["ingest_timestamp"], str)

    def test_empty_event_category_omitted(self) -> None:
        from src.domain.timeline import KronosProvenance, TimelineRecord

        record = TimelineRecord(
            **{"@timestamp": datetime(2024, 1, 1, tzinfo=UTC)},
            kronos=KronosProvenance(
                evidence_id=uuid.uuid4(),
                case_id=uuid.uuid4(),
                org_id=uuid.uuid4(),
                sha256="c" * 64,
                parser="nginx",
                parser_version="1.0.0",
                record_index=0,
                ingest_timestamp=datetime.now(UTC),
            ),
        )
        doc = self.normalizer.to_document(record)
        event_block = doc.get("event", {})
        # Empty lists should not appear as None — they are either present or absent.
        if "category" in event_block:
            assert event_block["category"] is not None
