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

    def get_by_name(self, parser_name: str) -> ForensicParser | None:
        """Return the registered parser with this exact ``parser_name``, or None.

        Real diagnosis fix (case 43097ab0-aae3-4968-915b-8f0229ac3865):
        backs an explicit, analyst-declared format override
        (``EvidenceMetadata.declared_format``) bypassing the normal
        extension/magic-byte ``supports()`` detection in
        ``ParsingOrchestrationService._detect_parser`` -- kept generic (by
        name, not a hardcoded import of a concrete parser class) so
        ``parsing_orchestration.py`` never needs to import a specific
        parser implementation directly.
        """
        for parser in self._parsers:
            if parser.parser_name == parser_name:
                return parser
        return None

    def all_parsers(self) -> list[ForensicParser]:
        """Return a copy of all registered parsers in registration order."""
        return list(self._parsers)
