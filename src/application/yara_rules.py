"""YaraRuleProvider: minimal, swappable plumbing for supplying YARA-X rule
text to ``ZipArchiveParser``/``TarArchiveParser``'s ``extract_artifacts()``
(roadmap E3).

**Scope note (deliberately minimal).** This is NOT E4 (ruleset lifecycle:
signed, versioned, Cosign-verified, custom-rule CRUD API) -- that is a
separate, not-yet-started roadmap item. This ABC exists only so E3's own
container parsers have *some* real, honest way to be handed rule text to
scan with, shaped so E4 can later swap in a signed/versioned implementation
without ``ZipArchiveParser``/``TarArchiveParser`` changing again -- mirrors
this codebase's own "optional collaborator, honestly disabled when unset"
idiom already used for ``RFC3161TimestampService``/
``DashboardsIndexPatternProvisioner`` in ``src/external/startup.py``.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from pathlib import Path

logger = logging.getLogger(__name__)

_RULE_FILE_GLOB = "*.yar"


class YaraRuleProvider(ABC):
    """Abstract source of YARA-X rule text for container-member scanning.

    A single combined rule-source string (not a list of per-rule sources) is
    the deliberate return shape: ``YaraXSandboxRunner.run()`` compiles one
    ``rule_source`` string per call (roadmap E2), and YARA-X's own syntax
    allows multiple ``rule { ... }`` blocks in one source string. Combining
    every configured rule into one string means a container parser pays for
    exactly one compile+scan per member regardless of how many individual
    rule files/rules are configured -- not one compile+scan per rule, which
    would multiply real, measured subprocess-launch overhead
    (``ZipArchiveParser.extract_artifacts()``'s own docstring has the actual
    numbers this was checked against, per CLAUDE.md's "measure before
    engineering around it" instruction).
    """

    @abstractmethod
    async def get_rule_source(self) -> str | None:
        """Return every configured rule's source, concatenated into one
        YARA-X-compilable string, or ``None`` if no ruleset is configured.

        ``None`` is a valid, honest "scanning disabled" state -- callers
        must treat it that way (yield nothing further), never substitute a
        fake default ruleset.
        """


class DirectoryYaraRuleProvider(YaraRuleProvider):
    """Reads every ``*.yar`` file from a configured directory, concatenated.

    The simplest honest concrete implementation for E3's own scope -- no
    signing, no versioning, no hot-reload/caching (E4's job, if ever
    needed). Re-reads the directory on every call rather than caching:
    ``extract_artifacts()`` is called once per top-level evidence file's
    parse (not once per container member), so re-reading a handful of small
    rule files from local disk on that cadence is not a real cost worth
    adding cache-invalidation complexity for.
    """

    def __init__(self, rules_directory: Path) -> None:
        self._rules_directory = rules_directory

    async def get_rule_source(self) -> str | None:
        if not self._rules_directory.is_dir():
            logger.warning(
                "yara_rules_directory_missing", extra={"path": str(self._rules_directory)}
            )
            return None

        rule_files = sorted(self._rules_directory.glob(_RULE_FILE_GLOB))
        if not rule_files:
            return None

        sources: list[str] = []
        for rule_file in rule_files:
            try:
                sources.append(rule_file.read_text(encoding="utf-8"))
            except OSError as exc:
                logger.warning(
                    "yara_rule_file_unreadable",
                    extra={"path": str(rule_file), "error": str(exc)},
                )

        return "\n\n".join(sources) if sources else None
