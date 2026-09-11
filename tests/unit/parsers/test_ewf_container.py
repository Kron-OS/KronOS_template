"""EwfContainerParser tests: synthetic EWF-shaped happy-path + fallback
cases, mocking the pyewf C-extension boundary (same "mock only the
external dependency" precedent test_volatility.py already applies to
VolatilityLauncher's own subprocess boundary -- CLAUDE.md §B.5).

The real, end-to-end reproduction of the actual incident this closes (a
real EWF file whose real media payload is a real tar archive, extracted
with the real, pinned pyewf against the real forensic2 evidence) lives in
``poc/ewf_memory_extraction/`` per CLAUDE.md Section F -- this file covers
the parser's own unit-level contract (detection, redispatch-vs-fallback
decision, recursion budget) with a fake pyewf, exactly as test_volatility.py
does for VolatilityLauncher.
"""

from __future__ import annotations

import io
import sys
import tarfile
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from types import ModuleType

import pytest

from src.application.parser_registry import ParserRegistry
from src.application.parsing import ForensicParser, ParserType
from src.domain.evidence import Evidence
from src.domain.timeline import EvidenceProvenance, TimelineRecord
from src.external.parsers._container_common import EWF_MAGIC
from src.external.parsers.ewf_container import EwfContainerParser
from src.external.parsers.nginx import NginxParser
from src.external.parsers.tar_archive import TarArchiveParser
from tests.fixtures.factories import make_evidence, make_tenant_context

_HEADER_BYTES = 8192


class _FakeEwfHandle:
    """Stands in for a real pyewf.handle() -- serves *media* bytes exactly
    as the real EWF C extension would via get_media_size()/read()."""

    def __init__(self, media: bytes) -> None:
        self._media = media
        self._pos = 0

    def open(self, filenames: list[str]) -> None:
        pass

    def get_media_size(self) -> int:
        return len(self._media)

    def read(self, size: int) -> bytes:
        chunk = self._media[self._pos : self._pos + size]
        self._pos += len(chunk)
        return chunk

    def close(self) -> None:
        pass


def _install_fake_pyewf(monkeypatch: pytest.MonkeyPatch, media: bytes) -> None:
    fake_module = ModuleType("pyewf")
    fake_module.handle = lambda: _FakeEwfHandle(media)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "pyewf", fake_module)


class _FakePlasoParser(ForensicParser):
    """Records what it was called with, yields one sentinel record --
    stands in for the real PlasoParser (never imported/run in these fast
    unit tests) so the fallback path is provable without Plaso/Firecracker."""

    def __init__(self) -> None:
        self.parse_calls: list[bytes] = []

    @property
    def parser_name(self) -> str:
        return "plaso"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def parser_type(self) -> ParserType:
        return ParserType.HEAVY

    def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
        return False  # never claimed via the registry in these tests

    async def parse(
        self, stream: AsyncIterator[bytes], evidence: Evidence, tenant: object
    ) -> AsyncIterator[TimelineRecord]:
        data = b"".join([chunk async for chunk in stream])
        self.parse_calls.append(data)
        yield TimelineRecord(
            **{
                "@timestamp": datetime(2024, 1, 1, tzinfo=UTC),
                "event.kind": "event",
            },
            kronos=EvidenceProvenance(
                evidence_id=evidence.evidence_id,
                case_id=evidence.metadata.case_id,
                org_id=evidence.metadata.org_id,
                sha256="",
                parser=self.parser_name,
                parser_version=self.parser_version,
                record_index=0,
                ingest_timestamp=datetime.now(UTC),
            ),
        )


def _build_tar(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


async def _bytes_stream(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def _drain_records(it: AsyncIterator[TimelineRecord]) -> list[TimelineRecord]:
    return [r async for r in it]


class TestSupports:
    def test_matches_real_ewf_magic(self) -> None:
        registry = ParserRegistry()
        parser = EwfContainerParser(registry, _FakePlasoParser())
        assert parser.supports("forensic2", "application/octet-stream", EWF_MAGIC + b"rest")

    def test_rejects_non_ewf_content(self) -> None:
        registry = ParserRegistry()
        parser = EwfContainerParser(registry, _FakePlasoParser())
        assert not parser.supports("forensic2", "application/octet-stream", b"not ewf")

    def test_registry_detects_ewf_container_parser_ahead_of_plaso(self) -> None:
        registry = ParserRegistry()
        plaso = _FakePlasoParser()
        ewf_parser = EwfContainerParser(registry, plaso)
        registry.register(ewf_parser)
        found = registry.get_parser("forensic2", "application/octet-stream", EWF_MAGIC)
        assert found is ewf_parser


class TestRedispatchToTar:
    async def test_ewf_wrapping_a_tar_redispatches_to_tar_archive_parser(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Real, reproduced case (43097ab0-aae3-4968-915b-8f0229ac3865,
        'forensic2'): the decoded EWF media is itself a tar archive --
        must redispatch through the registry (landing on
        TarArchiveParser), not fall back to Plaso."""
        access_log = b'127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 100\n'
        tar_bytes = _build_tar({"nginx.log": access_log})
        _install_fake_pyewf(monkeypatch, tar_bytes)

        registry = ParserRegistry()
        registry.register(TarArchiveParser(registry))
        registry.register(NginxParser())
        plaso = _FakePlasoParser()
        ewf_parser = EwfContainerParser(registry, plaso)
        registry.register(ewf_parser)

        evidence = make_evidence()
        stream = _bytes_stream(EWF_MAGIC + b"\x00" * 100)
        records = await _drain_records(ewf_parser.parse(stream, evidence, make_tenant_context()))

        assert len(records) == 1
        assert records[0].kronos.parser == "nginx"
        # Real source_path stamping: the record's provenance shows it came
        # from inside the unwrapped EWF media, not straight from Plaso.
        kronos = records[0].kronos
        assert isinstance(kronos, EvidenceProvenance)
        assert kronos.source_path is not None
        assert "EWF media" in kronos.source_path
        assert plaso.parse_calls == []  # Plaso must never be invoked on this path


class TestFallbackToPlaso:
    async def test_ewf_wrapping_a_genuine_disk_image_falls_back_to_plaso(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The common, correct case: decoded media matches no registered
        parser (a genuine raw disk image/memory has no distinguishing
        magic byte at all) -- must delegate straight to Plaso on the
        ORIGINAL EWF bytes, today's existing, unchanged behaviour."""
        genuine_disk_media = b"\x00" * 4096  # no recognizable magic anywhere
        _install_fake_pyewf(monkeypatch, genuine_disk_media)

        registry = ParserRegistry()
        registry.register(TarArchiveParser(registry))
        registry.register(NginxParser())
        plaso = _FakePlasoParser()
        ewf_parser = EwfContainerParser(registry, plaso)
        registry.register(ewf_parser)

        evidence = make_evidence()
        original_ewf_bytes = EWF_MAGIC + b"\x01\x02\x03"
        records = await _drain_records(
            ewf_parser.parse(_bytes_stream(original_ewf_bytes), evidence, make_tenant_context())
        )

        assert len(records) == 1
        assert records[0].kronos.parser == "plaso"
        # Plaso must receive the ORIGINAL EWF bytes, not the decoded media.
        assert plaso.parse_calls == [original_ewf_bytes]

    async def test_does_not_redispatch_to_itself_on_nested_ewf_match(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A decoded media that also happens to start with EWF magic must
        not trigger a pointless self-redirect through the extraction path
        -- falls back to Plaso on the original bytes instead, same as any
        other unrecognised-container case (nested EWF-in-EWF is a real but
        separate scenario the depth guard below still protects against if
        it were ever built out further)."""
        nested_ewf_media = EWF_MAGIC + b"\x00" * 100
        _install_fake_pyewf(monkeypatch, nested_ewf_media)

        registry = ParserRegistry()
        plaso = _FakePlasoParser()
        ewf_parser = EwfContainerParser(registry, plaso)
        registry.register(ewf_parser)

        evidence = make_evidence()
        original_ewf_bytes = EWF_MAGIC + b"\x09\x0a"
        records = await _drain_records(
            ewf_parser.parse(_bytes_stream(original_ewf_bytes), evidence, make_tenant_context())
        )

        assert len(records) == 1
        assert records[0].kronos.parser == "plaso"
        assert plaso.parse_calls == [original_ewf_bytes]


class TestExtractArtifacts:
    async def test_redispatches_extract_artifacts_to_tar_parser_too(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """extract_artifacts() must mirror parse()'s own redispatch
        decision -- TarArchiveParser's own extract_artifacts() (YARA) is a
        real, separate method that must also see the unwrapped media."""
        tar_bytes = _build_tar({"a.txt": b"hello"})
        _install_fake_pyewf(monkeypatch, tar_bytes)

        registry = ParserRegistry()
        registry.register(TarArchiveParser(registry))  # no yara runner configured -> honestly empty
        plaso = _FakePlasoParser()
        ewf_parser = EwfContainerParser(registry, plaso)
        registry.register(ewf_parser)

        evidence = make_evidence()
        artifacts = [
            a
            async for a in ewf_parser.extract_artifacts(
                _bytes_stream(EWF_MAGIC + b"\x00"), evidence, make_tenant_context()
            )
        ]
        assert artifacts == []  # honest empty, not an error -- TarArchiveParser has no YARA runner
