"""End-to-end ingestion pipeline test: raw file bytes -> OpenSearch document.

This exercises the EXACT production path a file takes from the moment the
parser layer receives its bytes to the moment it is ready to be handed to
OpenSearch's bulk API, and asserts on the *contents* of the resulting
documents (timestamps, ECS fields, kronos provenance, index routing,
deterministic ids) — not merely that some records came out.

Stages, mirroring src/application/parsing_orchestration.execute_parse():

    registry.get_parser(header)      # detection over the first 8 KB
      -> parser.parse(full stream)   # format-specific extraction
        -> _annotate_records(...)    # document_id + org_alias stamping
          -> ECSNormalizer.to_document(...)   # nested ECS doc
            -> build_index_name(...)          # per-tenant monthly index

Heavy parsers (Plaso) shell out to a sandboxed subprocess and are covered
separately (tests/unit/test_firecracker_launcher.py); this module covers the
in-process FAST parsers whose output can be verified deterministically here.
"""

from __future__ import annotations

import sqlite3
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from src.application.parser_registry import ParserRegistry
from src.application.parsing_orchestration import _annotate_records
from src.application.timeline_normalization import ECSNormalizer, build_index_name
from src.external.parsers.chrome_history import ChromeHistoryParser
from src.external.parsers.cloudtrail import CloudTrailParser
from src.external.parsers.nginx import NginxParser
from tests.fixtures.factories import make_evidence, make_tenant_context

REAL = Path(__file__).parents[1] / "fixtures" / "samples" / "real"
_HEADER_BYTES = 8192


def _registry() -> ParserRegistry:
    """The production FAST-parser registration order (see dependencies.py)."""
    r = ParserRegistry()
    r.register(CloudTrailParser())
    r.register(NginxParser())
    r.register(ChromeHistoryParser())
    try:
        from src.external.parsers.evtx import FastEvtxParser

        r.register(FastEvtxParser())
    except ImportError:
        pass
    return r


async def _stream(data: bytes, chunk: int = 65536) -> AsyncIterator[bytes]:
    for i in range(0, len(data), chunk):
        yield data[i : i + chunk]


async def run_pipeline(
    filename: str, content_type: str, data: bytes
) -> tuple[str, list[tuple[str, str, dict[str, Any]]]]:
    """Drive the full pipeline; return (parser_name, [(index, doc_id, doc), ...])."""
    registry = _registry()
    evidence = make_evidence()
    evidence = evidence.model_copy(
        update={"metadata": evidence.metadata.model_copy(update={"original_filename": filename})}
    )
    tenant = make_tenant_context()

    parser = registry.get_parser(filename, content_type, data[:_HEADER_BYTES])
    assert parser is not None, f"no parser detected for {filename}"

    normalizer = ECSNormalizer()
    annotated = _annotate_records(
        parser.parse(_stream(data), evidence, tenant),
        evidence.evidence_id,
        parser.parser_name,
        tenant.org_alias,
    )
    out: list[tuple[str, str, dict[str, Any]]] = []
    async for rec in annotated:
        doc = normalizer.to_document(rec)
        index = build_index_name(tenant.org_alias, str(rec.kronos.case_id), rec.timestamp)
        assert rec.document_id is not None
        out.append((index, rec.document_id, doc))
    return parser.parser_name, out


def _assert_well_formed(index: str, doc_id: str, doc: dict[str, Any]) -> None:
    """Invariants every pipeline document must satisfy before OpenSearch."""
    assert doc["@timestamp"]  # present and non-empty
    # Deterministic id: 40-hex SHA1 (idempotent re-index on parser retry).
    assert len(doc_id) == 40 and all(c in "0123456789abcdef" for c in doc_id)
    # Index routing is per-tenant + per-case + monthly.
    assert index.startswith("kronos-") and "-case-" in index
    # kronos provenance block is mandatory and fully populated.
    k = doc["kronos"]
    for field in ("evidence_id", "case_id", "org_id", "parser", "parser_version"):
        assert k.get(field), f"missing kronos.{field}"
    assert isinstance(k["record_index"], int)


# ---------------------------------------------------------------------------
# nginx / apache access log
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nginx_pipeline_contents() -> None:
    data = (REAL / "apache_access.log").read_bytes()
    parser, docs = await run_pipeline("apache_access.log", "text/plain", data)
    assert parser == "nginx"
    assert len(docs) == 15
    for index, doc_id, doc in docs:
        _assert_well_formed(index, doc_id, doc)
        assert doc["event"]["category"] == ["web"]
        assert "source" in doc and "ip" in doc["source"]
        assert doc["http"]["response"]["status_code"] >= 100

    # A specific known line's content is mapped correctly.
    first_doc = docs[0][2]
    assert first_doc["source"]["ip"] == "10.0.0.1"
    assert first_doc["url"]["path"].startswith("/wp-content/")
    assert first_doc["http"]["request"]["method"] == "GET"


# ---------------------------------------------------------------------------
# AWS CloudTrail (Lake/S3-export NDJSON)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cloudtrail_pipeline_contents() -> None:
    data = (REAL / "aws_cloudtrail.jsonl").read_bytes()
    parser, docs = await run_pipeline("aws_cloudtrail.jsonl", "application/json", data)
    assert parser == "cloudtrail"
    assert len(docs) == 6
    for index, doc_id, doc in docs:
        _assert_well_formed(index, doc_id, doc)
        assert doc["event"]["category"] == ["cloud"]
        assert doc["cloud"]["service"]["name"].endswith("amazonaws.com")

    first = docs[0][2]
    assert first["@timestamp"].startswith("2022-")
    assert "DescribeInstances" in first["message"]
    assert first["user"]["name"] == "fakeusername"


# ---------------------------------------------------------------------------
# Chrome/Chromium History (native SQLite parser)
# ---------------------------------------------------------------------------


def _build_history(path: Path) -> None:
    epoch = datetime(1601, 1, 1, tzinfo=UTC)
    visit = datetime(2024, 6, 1, 9, 0, 0, tzinfo=UTC)
    micros = int((visit - epoch).total_seconds() * 1_000_000)
    conn = sqlite3.connect(str(path))
    conn.executescript(
        "CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT,title TEXT,visit_count INT,"
        "typed_count INT,last_visit_time INT,hidden INT);"
        "CREATE TABLE visits(id INTEGER PRIMARY KEY,url INT,visit_time INT,from_visit INT,"
        "transition INT,visit_duration INT);"
    )
    conn.execute("INSERT INTO urls VALUES(1,'https://intranet.corp/hr','HR',5,2,?,0)", (micros,))
    conn.execute("INSERT INTO visits VALUES(1,1,?,0,1,0)", (micros,))
    conn.commit()
    conn.close()


@pytest.mark.asyncio
async def test_chrome_history_pipeline_contents(tmp_path: Path) -> None:
    path = tmp_path / "History"
    _build_history(path)
    parser, docs = await run_pipeline("History", "application/octet-stream", path.read_bytes())
    assert parser == "chrome-history"
    assert len(docs) == 1
    index, doc_id, doc = docs[0]
    _assert_well_formed(index, doc_id, doc)
    assert doc["@timestamp"].startswith("2024-06-01T09:00:00")
    assert doc["url"]["full"] == "https://intranet.corp/hr"
    assert doc["url"]["domain"] == "intranet.corp"
    assert doc["event"]["category"] == ["web"]
    assert doc["kronos"]["parser"] == "chrome-history"


# ---------------------------------------------------------------------------
# Windows EVTX (optional dependency)
# ---------------------------------------------------------------------------

evtx = pytest.importorskip("evtx")


@pytest.mark.asyncio
async def test_evtx_pipeline_contents() -> None:
    data = (REAL / "system.evtx").read_bytes()
    parser, docs = await run_pipeline("system.evtx", "application/octet-stream", data)
    assert parser == "evtx-rs"
    assert len(docs) > 0
    for index, doc_id, doc in docs:
        _assert_well_formed(index, doc_id, doc)
        assert doc["event"]["module"] == "windows"
    # EVTX event codes are surfaced under event.code for querying.
    assert any("code" in doc["event"] for _, _, doc in docs)


# ---------------------------------------------------------------------------
# Cross-cutting: deterministic ids are stable across re-runs (idempotent
# re-index on Celery retry) and unique within a file.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_document_ids_deterministic_and_unique() -> None:
    data = (REAL / "apache_access.log").read_bytes()
    _, docs_a = await run_pipeline("apache_access.log", "text/plain", data)
    ids_a = [doc_id for _, doc_id, _ in docs_a]
    # Unique within the file.
    assert len(ids_a) == len(set(ids_a))
    # Stable for the same evidence_id/parser/index across a re-parse: recompute
    # with the same evidence identity and confirm the id formula is positional.
    from src.application.parsing_orchestration import _make_document_id

    ev_id = uuid.uuid4()
    assert _make_document_id(ev_id, "nginx", 3) == _make_document_id(ev_id, "nginx", 3)
    assert _make_document_id(ev_id, "nginx", 3) != _make_document_id(ev_id, "nginx", 4)
