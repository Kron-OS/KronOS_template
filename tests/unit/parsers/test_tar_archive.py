"""TarArchiveParser tests: synthetic tar-shaped adversarial + happy-path
cases, mirroring test_archive.py's ZipArchiveParser coverage exactly (see
TarArchiveParser's own module docstring for why the two parsers share the
same recursion pattern and the same _container_common.py defenses).

The real, end-to-end reproduction of the actual incident this closes (a
tar containing a real raw disk image with real filesystem timestamps, run
through the real evidence-intake pipeline) lives in
``poc/tar_container_unwrapping/`` per CLAUDE.md Section F -- this file
covers the parser's own unit-level contract (detection, recursion,
adversarial guards, shared cross-container-type budget) with fast synthetic
tars, exactly as test_archive.py already does for zip.
"""

from __future__ import annotations

import io
import tarfile
import zipfile
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from src.application.parser_registry import ParserRegistry
from src.domain.timeline import TimelineRecord
from src.exceptions import ParsingError
from src.external.parsers import archive as archive_module
from src.external.parsers import tar_archive as tar_archive_module
from src.external.parsers.archive import ZipArchiveParser
from src.external.parsers.cloudtrail import CloudTrailParser
from src.external.parsers.nginx import NginxParser
from src.external.parsers.tar_archive import TarArchiveParser
from tests.fixtures.factories import make_evidence, make_tenant_context

_HEADER_BYTES = 8192


def _make_registry_with_tar() -> ParserRegistry:
    registry = ParserRegistry()
    registry.register(TarArchiveParser(registry))
    registry.register(CloudTrailParser())
    registry.register(NginxParser())
    return registry


async def _bytes_stream(data: bytes) -> AsyncIterator[bytes]:
    yield data


async def _drain(it: AsyncIterator[TimelineRecord]) -> list[TimelineRecord]:
    return [r async for r in it]


def _build_tar(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _build_zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


_ACCESS_LOG = b'127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 100\n'


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


class TestTarDetection:
    def test_registry_detects_tar_archive_parser(self) -> None:
        registry = _make_registry_with_tar()
        data = _build_tar({"access.log": _ACCESS_LOG})
        parser = registry.get_parser("bundle.tar", "application/x-tar", data[:_HEADER_BYTES])
        assert isinstance(parser, TarArchiveParser)

    def test_ustar_magic_present_at_real_offset_257(self) -> None:
        # Ground truth: verified on this host against both GNU tar 1.35's
        # own CLI output and Python's own tarfile module -- both carry the
        # 5-byte "ustar" prefix at the fixed POSIX header offset 257 (see
        # tar_archive.py's module docstring for the full byte dump).
        data = _build_tar({"a.txt": b"hi"})
        assert data[257:262] == b"ustar"

    def test_does_not_falsely_claim_a_zip(self) -> None:
        parser = TarArchiveParser(ParserRegistry())
        data = _build_zip({"a.txt": b"hi"})
        assert parser.supports("evil.tar", "application/x-tar", data[:_HEADER_BYTES]) is False


# ---------------------------------------------------------------------------
# Happy path: recursive re-dispatch
# ---------------------------------------------------------------------------


class TestTarRecursiveDispatch:
    @pytest.mark.asyncio
    async def test_recursively_dispatches_every_member_to_its_real_parser(self) -> None:
        registry = _make_registry_with_tar()
        cloudtrail_record = b'{"Records": [{"eventName": "ConsoleLogin"}]}'
        data = _build_tar(
            {
                "logs/access.log": _ACCESS_LOG,
                "aws/cloudtrail.json": cloudtrail_record,
            }
        )
        evidence = make_evidence()
        evidence = evidence.model_copy(
            update={"sha256": __import__("hashlib").sha256(data).hexdigest()}
        )
        tenant = make_tenant_context()
        parser = registry.get_parser("bundle.tar", "application/x-tar", data[:_HEADER_BYTES])
        assert isinstance(parser, TarArchiveParser)
        records = await _drain(parser.parse(_bytes_stream(data), evidence, tenant))

        by_parser: dict[str, list[TimelineRecord]] = {}
        for r in records:
            by_parser.setdefault(r.kronos.parser, []).append(r)

        assert by_parser["nginx"], "the access.log member must be re-dispatched"
        assert {r.kronos.source_path for r in by_parser["nginx"]} == {"logs/access.log"}
        assert by_parser["cloudtrail"], "the cloudtrail.json member must be re-dispatched"
        assert {r.kronos.source_path for r in by_parser["cloudtrail"]} == {"aws/cloudtrail.json"}
        assert all(r.kronos.container_sha256 == evidence.sha256 for r in records)

    @pytest.mark.asyncio
    async def test_unmatched_member_is_skipped_not_fatal(self) -> None:
        # Mirrors ZipArchiveParser's own "no parser for this member yet"
        # precedent -- the exact behaviour `memory.dmp` needs (E5/Volatility
        # is a separate, not-yet-built roadmap item): log and move on, never
        # raise, never silently vanish without a trace (see the
        # "tar_member_no_parser" log line in tar_archive.py).
        registry = ParserRegistry()
        registry.register(TarArchiveParser(registry))
        data = _build_tar({"memory.dmp": b"\x00\x01\x02\x03deadbeef"})
        evidence = make_evidence()
        tenant = make_tenant_context()
        parser = registry.get_parser("bundle.tar", "application/x-tar", data[:_HEADER_BYTES])
        assert isinstance(parser, TarArchiveParser)
        records = await _drain(parser.parse(_bytes_stream(data), evidence, tenant))
        assert records == []

    @pytest.mark.asyncio
    async def test_directory_members_are_skipped(self) -> None:
        registry = _make_registry_with_tar()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            dir_info = tarfile.TarInfo(name="sub")
            dir_info.type = tarfile.DIRTYPE
            tf.addfile(dir_info)
            file_info = tarfile.TarInfo(name="sub/access.log")
            file_info.size = len(_ACCESS_LOG)
            tf.addfile(file_info, io.BytesIO(_ACCESS_LOG))
        data = buf.getvalue()
        evidence = make_evidence()
        tenant = make_tenant_context()
        parser = registry.get_parser("bundle.tar", "application/x-tar", data[:_HEADER_BYTES])
        assert isinstance(parser, TarArchiveParser)
        records = await _drain(parser.parse(_bytes_stream(data), evidence, tenant))
        assert any(r.kronos.source_path == "sub/access.log" for r in records)


# ---------------------------------------------------------------------------
# Adversarial / guard behaviour
# ---------------------------------------------------------------------------


class TestTarArchiveGuards:
    @pytest.mark.asyncio
    async def test_rejects_tar_slip_absolute_member_path(self) -> None:
        registry = ParserRegistry()
        registry.register(TarArchiveParser(registry))
        registry.register(NginxParser())
        data = _build_tar(
            {
                "/etc/passwd": b"root:x:0:0::/root:/bin/bash\n",
                "safe/access.log": _ACCESS_LOG,
            }
        )
        evidence = make_evidence()
        tenant = make_tenant_context()
        parser = registry.get_parser("evil.tar", "application/x-tar", data[:_HEADER_BYTES])
        assert isinstance(parser, TarArchiveParser)
        records = await _drain(parser.parse(_bytes_stream(data), evidence, tenant))
        assert all(r.kronos.source_path != "/etc/passwd" for r in records)
        assert any(r.kronos.source_path == "safe/access.log" for r in records)

    @pytest.mark.asyncio
    async def test_rejects_tar_slip_dotdot_member_path(self) -> None:
        registry = ParserRegistry()
        registry.register(TarArchiveParser(registry))
        registry.register(NginxParser())
        data = _build_tar(
            {
                "../../etc/passwd": b"root:x:0:0::/root:/bin/bash\n",
                "safe/access.log": _ACCESS_LOG,
            }
        )
        evidence = make_evidence()
        tenant = make_tenant_context()
        parser = registry.get_parser("evil.tar", "application/x-tar", data[:_HEADER_BYTES])
        assert isinstance(parser, TarArchiveParser)
        records = await _drain(parser.parse(_bytes_stream(data), evidence, tenant))
        assert all(r.kronos.source_path != "../../etc/passwd" for r in records)
        assert any(r.kronos.source_path == "safe/access.log" for r in records)

    @pytest.mark.asyncio
    async def test_rejects_symlink_member(self) -> None:
        # tarfile's documented traversal footgun: a symlink member whose
        # target escapes the extraction root. TarArchiveParser never
        # resolves symlinks/hardlinks at all (isfile() check) -- it must not
        # even attempt to read one.
        registry = ParserRegistry()
        registry.register(TarArchiveParser(registry))
        registry.register(NginxParser())
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tf:
            link_info = tarfile.TarInfo(name="evil_link")
            link_info.type = tarfile.SYMTYPE
            link_info.linkname = "/etc/passwd"
            tf.addfile(link_info)
            file_info = tarfile.TarInfo(name="access.log")
            file_info.size = len(_ACCESS_LOG)
            tf.addfile(file_info, io.BytesIO(_ACCESS_LOG))
        data = buf.getvalue()
        evidence = make_evidence()
        tenant = make_tenant_context()
        parser = registry.get_parser("evil.tar", "application/x-tar", data[:_HEADER_BYTES])
        assert isinstance(parser, TarArchiveParser)
        records = await _drain(parser.parse(_bytes_stream(data), evidence, tenant))
        assert any(r.kronos.source_path == "access.log" for r in records)

    @pytest.mark.asyncio
    async def test_rejects_container_nesting_beyond_max_depth(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(tar_archive_module, "MAX_CONTAINER_DEPTH", 2)
        registry = ParserRegistry()
        registry.register(TarArchiveParser(registry))

        innermost = _build_tar({"leaf.txt": b"hello"})
        level2 = _build_tar({"nested.tar": innermost})
        level1 = _build_tar({"nested.tar": level2})

        evidence = make_evidence()
        tenant = make_tenant_context()
        parser = registry.get_parser("l1.tar", "application/x-tar", level1[:_HEADER_BYTES])
        assert isinstance(parser, TarArchiveParser)
        with pytest.raises(ParsingError, match="maximum depth"):
            await _drain(parser.parse(_bytes_stream(level1), evidence, tenant))

    @pytest.mark.asyncio
    async def test_rejects_container_exceeding_max_member_count(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(tar_archive_module, "MAX_MEMBER_COUNT", 3)
        registry = ParserRegistry()
        registry.register(TarArchiveParser(registry))
        data = _build_tar({f"file{i}.txt": b"x" for i in range(5)})

        evidence = make_evidence()
        tenant = make_tenant_context()
        parser = registry.get_parser("many.tar", "application/x-tar", data[:_HEADER_BYTES])
        assert isinstance(parser, TarArchiveParser)
        with pytest.raises(ParsingError, match="member count"):
            await _drain(parser.parse(_bytes_stream(data), evidence, tenant))

    @pytest.mark.asyncio
    async def test_rejects_container_exceeding_total_byte_budget(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(tar_archive_module, "MAX_TOTAL_UNCOMPRESSED_BYTES", 10)
        registry = ParserRegistry()
        registry.register(TarArchiveParser(registry))
        data = _build_tar({"big.txt": b"x" * 100})

        evidence = make_evidence()
        tenant = make_tenant_context()
        parser = registry.get_parser("big.tar", "application/x-tar", data[:_HEADER_BYTES])
        assert isinstance(parser, TarArchiveParser)
        with pytest.raises(ParsingError, match="total extracted bytes"):
            await _drain(parser.parse(_bytes_stream(data), evidence, tenant))

    @pytest.mark.asyncio
    async def test_skips_oversized_single_member_without_failing_whole_container(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(tar_archive_module, "MAX_PER_FILE_UNCOMPRESSED_BYTES", 200)
        registry = ParserRegistry()
        registry.register(TarArchiveParser(registry))
        registry.register(NginxParser())
        data = _build_tar({"huge.bin": b"x" * 1000, "access.log": _ACCESS_LOG})
        evidence = make_evidence()
        tenant = make_tenant_context()
        parser = registry.get_parser("mixed.tar", "application/x-tar", data[:_HEADER_BYTES])
        assert isinstance(parser, TarArchiveParser)
        records = await _drain(parser.parse(_bytes_stream(data), evidence, tenant))
        assert any(r.kronos.source_path == "access.log" for r in records)
        assert all(r.kronos.source_path != "huge.bin" for r in records)

    @pytest.mark.asyncio
    async def test_bad_tar_raises_parsing_error(self) -> None:
        registry = ParserRegistry()
        registry.register(TarArchiveParser(registry))
        evidence = make_evidence()
        tenant = make_tenant_context()
        parser = TarArchiveParser(registry)
        garbage = b"\x00" * 257 + b"ustar" + b"not a real tar" * 10
        with pytest.raises(ParsingError, match="valid tar"):
            await _drain(parser.parse(_bytes_stream(garbage), evidence, tenant))


# ---------------------------------------------------------------------------
# Cross-container-type shared budget/depth (the real reason for
# _container_common.py existing at all, not just an implementation detail)
# ---------------------------------------------------------------------------


class TestSharedCrossContainerTypeDefense:
    @pytest.mark.asyncio
    async def test_depth_is_shared_across_tar_and_zip_nesting(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # tar -> zip -> tar, 3 levels total. If depth were tracked
        # independently per container *type* (a naive per-parser
        # ContextVar), each type would individually see only 2 levels of
        # its own kind and neither check would fire. Patching both modules'
        # MAX_CONTAINER_DEPTH to 2 must still reject this, because the
        # depth counter itself (_container_common.depth_var) is shared.
        monkeypatch.setattr(tar_archive_module, "MAX_CONTAINER_DEPTH", 2)
        monkeypatch.setattr(archive_module, "MAX_CONTAINER_DEPTH", 2)

        registry = ParserRegistry()
        registry.register(TarArchiveParser(registry))
        registry.register(ZipArchiveParser(registry))

        innermost_tar = _build_tar({"leaf.txt": b"hello"})
        middle_zip = _build_zip({"nested.tar": innermost_tar})
        outer_tar = _build_tar({"nested.zip": middle_zip})

        evidence = make_evidence()
        tenant = make_tenant_context()
        parser = registry.get_parser("l1.tar", "application/x-tar", outer_tar[:_HEADER_BYTES])
        assert isinstance(parser, TarArchiveParser)
        with pytest.raises(ParsingError, match="maximum depth"):
            await _drain(parser.parse(_bytes_stream(outer_tar), evidence, tenant))

    @pytest.mark.asyncio
    async def test_byte_budget_is_shared_across_tar_and_zip_nesting(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A tar containing a zip: the tar member's bytes and the zip's own
        # inner member bytes must both count against the *same* aggregate
        # budget, regardless of which module charges them.
        monkeypatch.setattr(tar_archive_module, "MAX_TOTAL_UNCOMPRESSED_BYTES", 50)
        monkeypatch.setattr(archive_module, "MAX_TOTAL_UNCOMPRESSED_BYTES", 50)

        registry = ParserRegistry()
        registry.register(TarArchiveParser(registry))
        registry.register(ZipArchiveParser(registry))

        inner_zip = _build_zip({"big.txt": b"x" * 60})
        outer_tar = _build_tar({"nested.zip": inner_zip})

        evidence = make_evidence()
        tenant = make_tenant_context()
        parser = registry.get_parser("l1.tar", "application/x-tar", outer_tar[:_HEADER_BYTES])
        assert isinstance(parser, TarArchiveParser)
        with pytest.raises(ParsingError, match="total extracted bytes"):
            await _drain(parser.parse(_bytes_stream(outer_tar), evidence, tenant))
