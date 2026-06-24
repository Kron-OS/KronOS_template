"""Unit tests for ParserRegistry."""

from __future__ import annotations

from src.application.parser_registry import ParserRegistry
from src.application.parsing import ForensicParser, ParserType

# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class _AlwaysParser(ForensicParser):
    """Parser that always claims to support the file."""

    def __init__(self, name: str = "always") -> None:
        self._name = name
        self.supports_call_count = 0

    @property
    def parser_name(self) -> str:
        return self._name

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def parser_type(self) -> ParserType:
        return ParserType.FAST

    def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
        self.supports_call_count += 1
        return True

    async def parse(self, stream, evidence, tenant):  # type: ignore[override]
        return
        yield  # type: ignore[misc]


class _NeverParser(ForensicParser):
    """Parser that never supports any file."""

    def __init__(self, name: str = "never") -> None:
        self._name = name
        self.supports_call_count = 0

    @property
    def parser_name(self) -> str:
        return self._name

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def parser_type(self) -> ParserType:
        return ParserType.HEAVY

    def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
        self.supports_call_count += 1
        return False

    async def parse(self, stream, evidence, tenant):  # type: ignore[override]
        return
        yield  # type: ignore[misc]


class _ExtParser(ForensicParser):
    """Parser that accepts a specific extension."""

    def __init__(self, ext: str, name: str | None = None) -> None:
        self._ext = ext
        self._name = name or f"ext-{ext}"

    @property
    def parser_name(self) -> str:
        return self._name

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def parser_type(self) -> ParserType:
        return ParserType.FAST

    def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
        return filename.endswith(self._ext)

    async def parse(self, stream, evidence, tenant):  # type: ignore[override]
        return
        yield  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestParserRegistry:
    def test_register_and_retrieve(self) -> None:
        registry = ParserRegistry()
        parser = _AlwaysParser()
        registry.register(parser)
        result = registry.get_parser("any.file", "application/octet-stream", b"")
        assert result is parser

    def test_no_match_returns_none(self) -> None:
        registry = ParserRegistry()
        registry.register(_NeverParser())
        assert registry.get_parser("any.file", "text/plain", b"") is None

    def test_empty_registry_returns_none(self) -> None:
        registry = ParserRegistry()
        assert registry.get_parser("file.json", "application/json", b"{}") is None

    def test_first_match_wins(self) -> None:
        registry = ParserRegistry()
        first = _AlwaysParser("first")
        second = _AlwaysParser("second")
        registry.register(first)
        registry.register(second)
        result = registry.get_parser("file.log", "text/plain", b"data")
        assert result is first

    def test_parser_not_called_after_match(self) -> None:
        registry = ParserRegistry()
        first = _AlwaysParser()
        second = _AlwaysParser("second")
        registry.register(first)
        registry.register(second)
        registry.get_parser("file.log", "text/plain", b"")
        # second.supports() should never be called because first matched.
        assert second.supports_call_count == 0

    def test_all_parsers_returns_registered(self) -> None:
        registry = ParserRegistry()
        p1 = _AlwaysParser("a")
        p2 = _NeverParser("b")
        registry.register(p1)
        registry.register(p2)
        result = registry.all_parsers()
        assert len(result) == 2
        assert result[0] is p1
        assert result[1] is p2

    def test_all_parsers_returns_copy(self) -> None:
        registry = ParserRegistry()
        registry.register(_AlwaysParser())
        lst = registry.all_parsers()
        lst.clear()
        assert len(registry.all_parsers()) == 1

    def test_register_multiple_types(self) -> None:
        registry = ParserRegistry()
        fast = _ExtParser(".json", "json-fast")
        heavy = _ExtParser(".evtx", "evtx-heavy")
        registry.register(fast)
        registry.register(heavy)
        assert registry.get_parser("data.json", "application/json", b"") is fast
        assert registry.get_parser("log.evtx", "application/octet-stream", b"ElfFile\x00") is heavy

    def test_get_parser_calls_supports_with_correct_args(self) -> None:
        received: list[tuple[str, str, bytes]] = []

        class _SpyParser(_NeverParser):
            def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
                received.append((filename, content_type, header_bytes))
                return False

        registry = ParserRegistry()
        registry.register(_SpyParser())
        registry.get_parser("report.pdf", "application/pdf", b"%PDF")
        assert received == [("report.pdf", "application/pdf", b"%PDF")]
