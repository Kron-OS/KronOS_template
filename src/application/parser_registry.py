"""ParserRegistry: polymorphic parser selection with no if/elif chains."""

from __future__ import annotations

from src.application.parsing import ForensicParser


class ParserRegistry:
    """Holds registered ForensicParser instances; selects the right one per file.

    Parsers are evaluated in registration order; the first one whose supports()
    returns True is used.  Adding a new parser requires only a register() call —
    zero changes to orchestration code.
    """

    def __init__(self) -> None:
        self._parsers: list[ForensicParser] = []

    def register(self, parser: ForensicParser) -> None:
        """Add a parser. Registration order determines priority (first-match wins)."""
        self._parsers.append(parser)

    def get_parser(
        self, filename: str, content_type: str, header_bytes: bytes
    ) -> ForensicParser | None:
        """Return the first parser that supports this file, or None."""
        for parser in self._parsers:
            if parser.supports(filename, content_type, header_bytes):
                return parser
        return None

    def all_parsers(self) -> list[ForensicParser]:
        """Return a copy of all registered parsers in registration order."""
        return list(self._parsers)
