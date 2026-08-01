"""Unit tests for StreamProvenance and the EvidenceProvenance|StreamProvenance union.

Covers B1 (docs/NEXTGEN_SOC_ROADMAP.md): the asymmetry between evidence-file
provenance and continuous-telemetry provenance must be type-checked, not
papered over with sentinel UUIDs. These tests are this task's real,
executed L1 proof (CLAUDE.md §F) for a pure-Pydantic domain change: real
construction, real validation failures, and a real discriminated-union
round trip via `pydantic.TypeAdapter` -- no external dependency is involved,
so there is nothing a poc/ runner would exercise that these tests do not
already exercise identically (see poc/provenance_split/README.md for the
explicit reasoning on why a poc/ dir was still added alongside, not instead).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import TypeAdapter
from pydantic import ValidationError as PydanticValidationError

# Provenance (the EvidenceProvenance | StreamProvenance discriminated union)
# now lives in src.domain.timeline, not src.domain.stream (roadmap D4) --
# stream.py deliberately no longer imports anything from timeline.py (see
# stream.py's own docstring: that avoided a real circular import once
# TimelineRecord.kronos needed to import StreamProvenance from this module).
from src.domain.stream import StreamProvenance
from src.domain.timeline import EvidenceProvenance, Provenance


def _now() -> datetime:
    return datetime.now(UTC)


def _make_stream_provenance(**overrides: object) -> StreamProvenance:
    defaults: dict[str, object] = {
        "org_id": uuid.uuid4(),
        "parser": "zeek-conn-log",
        "parser_version": "1.0.0",
        "ingest_timestamp": _now(),
        "source_id": "zeek-conn-log",
        "batch_id": uuid.uuid4(),
        "event_offset": 0,
    }
    defaults.update(overrides)
    return StreamProvenance(**defaults)  # type: ignore[arg-type]


def _make_evidence_provenance(**overrides: object) -> EvidenceProvenance:
    defaults: dict[str, object] = {
        "evidence_id": uuid.uuid4(),
        "case_id": uuid.uuid4(),
        "org_id": uuid.uuid4(),
        "sha256": "a" * 64,
        "parser": "evtx-rs",
        "parser_version": "1.0.0",
        "record_index": 0,
        "ingest_timestamp": _now(),
    }
    defaults.update(overrides)
    return EvidenceProvenance(**defaults)  # type: ignore[arg-type]


class TestStreamProvenanceConstruction:
    def test_construction_without_case_id(self) -> None:
        """A stream event has no case at ingest time -- case_id must default to None."""
        prov = _make_stream_provenance()
        assert prov.case_id is None
        assert prov.kind == "stream"

    def test_construction_with_case_id_attached_later(self) -> None:
        """case_id is attachable (triage), but never mandatory."""
        cid = uuid.uuid4()
        prov = _make_stream_provenance(case_id=cid)
        assert prov.case_id == cid

    def test_no_evidence_id_or_sha256_fields_exist(self) -> None:
        """StreamProvenance must not carry evidence-file-only fields at all --
        not just leave them unset. Their absence from the model is the point:
        there is no sentinel value that would be honest here."""
        prov = _make_stream_provenance()
        assert not hasattr(prov, "evidence_id")
        assert not hasattr(prov, "sha256")

    def test_frozen(self) -> None:
        prov = _make_stream_provenance()
        with pytest.raises(PydanticValidationError):
            prov.event_offset = 5  # type: ignore[misc]


class TestStreamProvenanceValidationFailures:
    def test_missing_source_id_rejected(self) -> None:
        with pytest.raises(PydanticValidationError):
            _make_stream_provenance(source_id=None)  # type: ignore[arg-type]

    def test_missing_batch_id_rejected(self) -> None:
        with pytest.raises(PydanticValidationError):
            StreamProvenance(
                org_id=uuid.uuid4(),
                parser="zeek-conn-log",
                parser_version="1.0.0",
                ingest_timestamp=_now(),
                source_id="zeek-conn-log",
                event_offset=0,
            )  # type: ignore[call-arg]

    def test_negative_event_offset_rejected(self) -> None:
        with pytest.raises(PydanticValidationError):
            _make_stream_provenance(event_offset=-1)

    def test_empty_source_id_rejected(self) -> None:
        with pytest.raises(PydanticValidationError):
            _make_stream_provenance(source_id="")

    def test_missing_org_id_rejected(self) -> None:
        with pytest.raises(PydanticValidationError):
            StreamProvenance(
                parser="zeek-conn-log",
                parser_version="1.0.0",
                ingest_timestamp=_now(),
                source_id="zeek-conn-log",
                batch_id=uuid.uuid4(),
                event_offset=0,
            )  # type: ignore[call-arg]


class TestEvidenceProvenanceStillRequiresEvidenceFields:
    """Asymmetry check: the other side of the union still enforces what it always did."""

    def test_missing_evidence_id_rejected(self) -> None:
        with pytest.raises(PydanticValidationError):
            EvidenceProvenance(
                case_id=uuid.uuid4(),
                org_id=uuid.uuid4(),
                sha256="a" * 64,
                parser="evtx-rs",
                parser_version="1.0.0",
                record_index=0,
                ingest_timestamp=_now(),
            )  # type: ignore[call-arg]

    def test_missing_sha256_rejected(self) -> None:
        with pytest.raises(PydanticValidationError):
            EvidenceProvenance(
                evidence_id=uuid.uuid4(),
                case_id=uuid.uuid4(),
                org_id=uuid.uuid4(),
                parser="evtx-rs",
                parser_version="1.0.0",
                record_index=0,
                ingest_timestamp=_now(),
            )  # type: ignore[call-arg]

    def test_kind_defaults_to_evidence(self) -> None:
        """Every existing caller constructs EvidenceProvenance without `kind=`."""
        prov = _make_evidence_provenance()
        assert prov.kind == "evidence"


class TestDiscriminatedUnion:
    """Real pydantic.TypeAdapter round trip over the EvidenceProvenance|StreamProvenance union.

    This is the concrete, executed demonstration that the discriminator
    mechanism (Field(discriminator="kind") on an Annotated Union, the
    pydantic 2.13 syntax pinned in pyproject.toml) actually dispatches to
    the right concrete type -- not just that both types independently
    validate.
    """

    def test_discriminates_evidence_branch(self) -> None:
        adapter: TypeAdapter[EvidenceProvenance | StreamProvenance] = TypeAdapter(Provenance)
        payload = {
            "kind": "evidence",
            "evidence_id": str(uuid.uuid4()),
            "case_id": str(uuid.uuid4()),
            "org_id": str(uuid.uuid4()),
            "sha256": "a" * 64,
            "parser": "evtx-rs",
            "parser_version": "1.0.0",
            "record_index": 0,
            "ingest_timestamp": _now().isoformat(),
        }
        result = adapter.validate_python(payload)
        assert isinstance(result, EvidenceProvenance)

    def test_discriminates_stream_branch(self) -> None:
        adapter: TypeAdapter[EvidenceProvenance | StreamProvenance] = TypeAdapter(Provenance)
        payload = {
            "kind": "stream",
            "org_id": str(uuid.uuid4()),
            "parser": "zeek-conn-log",
            "parser_version": "1.0.0",
            "ingest_timestamp": _now().isoformat(),
            "source_id": "zeek-conn-log",
            "batch_id": str(uuid.uuid4()),
            "event_offset": 42,
        }
        result = adapter.validate_python(payload)
        assert isinstance(result, StreamProvenance)
        assert result.case_id is None

    def test_unknown_kind_rejected(self) -> None:
        adapter: TypeAdapter[EvidenceProvenance | StreamProvenance] = TypeAdapter(Provenance)
        with pytest.raises(PydanticValidationError):
            adapter.validate_python({"kind": "carrier_pigeon"})

    def test_round_trip_serialization_preserves_discriminator(self) -> None:
        """model_dump(mode="json") -> TypeAdapter.validate_python must recover
        the same concrete type, proving `kind` survives a real serialize/
        deserialize cycle (the shape a Redis Streams payload would take,
        roadmap D1)."""
        adapter: TypeAdapter[EvidenceProvenance | StreamProvenance] = TypeAdapter(Provenance)
        original = _make_stream_provenance()
        dumped = adapter.dump_python(original, mode="json")
        restored = adapter.validate_python(dumped)
        assert isinstance(restored, StreamProvenance)
        assert restored == original
