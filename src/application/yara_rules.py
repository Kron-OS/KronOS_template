"""YaraRuleProvider: minimal, swappable plumbing for supplying YARA-X rule
text to ``ZipArchiveParser``/``TarArchiveParser``'s ``extract_artifacts()``
(roadmap E3).

**E4 update.** Roadmap E4 ("same trust model as C3, applied to YARA
rulesets") is now implemented -- ``SignedYaraRulePackProvider`` below is
the signed/versioned implementation this module's own original docstring
anticipated, backed by ``YaraRulePackRepository``/``YaraRulePackService``
(``src/adapter/repository/yara_rule_pack.py``,
``src/application/yara_rule_pack_service.py``). ``DirectoryYaraRuleProvider``
remains for local/dev use (no signing, no versioning, no per-org scoping)
-- neither implementation required any change to
``ZipArchiveParser``/``TarArchiveParser`` themselves, exactly as this
module's original docstring promised: both parsers still call
``self._yara_rule_provider.get_rule_source()`` with zero arguments.

**Why ``yara_scan_org_var`` exists.** ``get_rule_source()``'s signature is
deliberately zero-argument (see the ABC below) so the container parsers'
call sites never need to change. But a signed/versioned ruleset is
inherently org-scoped (roadmap invariant: org_id always from the
authenticated ``TenantContext``, never from content or a process-wide
default -- CLAUDE.md SS G.3), and the parser registry
(``src/external/dependencies.py::get_parser_registry``) is a
process-wide singleton built once, not reconstructed per request/tenant.
The only way to thread "which org is this scan for" through an unchanged,
zero-argument call is the same ``ContextVar`` idiom this codebase already
uses for ``depth_var``/``budget_var``
(``src/external/parsers/_container_common.py``): set once by
``ParsingOrchestrationService`` (the sole caller of every
``ForensicParser.extract_artifacts()``, not just the two container
parsers) immediately around its own call to ``extract_artifacts()``, read
by ``SignedYaraRulePackProvider.get_rule_source()``.
"""

from __future__ import annotations

import logging
import uuid
from abc import ABC, abstractmethod
from contextvars import ContextVar
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.adapter.repository.yara_rule_pack import YaraRulePackRepository

logger = logging.getLogger(__name__)

_RULE_FILE_GLOB = "*.yar"

# See this module's docstring ("Why yara_scan_org_var exists"). Set/reset by
# ParsingOrchestrationService around its extract_artifacts() call; read by
# SignedYaraRulePackProvider.get_rule_source(). None means "no org context
# bound" -- an honest state (e.g. a direct unit-test call to get_rule_source()
# with no orchestration wrapper around it), never silently defaulted to some
# other org's rules.
yara_scan_org_var: ContextVar[uuid.UUID | None] = ContextVar("yara_scan_org_var", default=None)


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


class SignedYaraRulePackProvider(YaraRuleProvider):
    """Signed, versioned, org-scoped ``YaraRuleProvider`` (roadmap E4).

    Backed by ``YaraRulePackRepository``: returns the concatenated
    ``combined_rule_source`` of every currently-published version of every
    pack belonging to the org bound in ``yara_scan_org_var`` (see this
    module's own docstring for why that ``ContextVar`` -- not a
    constructor/method argument -- is how org scoping reaches this class
    without ``ZipArchiveParser``/``TarArchiveParser`` needing any change to
    their existing zero-argument ``get_rule_source()`` call).

    An org with no packs, or packs with nothing published yet, correctly
    returns ``None`` (honest "no ruleset configured" -- mirrors
    ``DirectoryYaraRuleProvider``'s own empty-directory case), never a
    fabricated empty ruleset. Likewise, no bound org context at all
    (``yara_scan_org_var.get()`` is ``None``) is logged and treated as "no
    ruleset configured" rather than silently scanning with some other org's
    rules or raising -- extract_artifacts() must never propagate this as an
    exception (see ``ZipArchiveParser.extract_artifacts()``'s own docstring
    on that contract).
    """

    def __init__(self, repository: YaraRulePackRepository) -> None:
        self._repo = repository

    async def get_rule_source(self) -> str | None:
        org_id = yara_scan_org_var.get()
        if org_id is None:
            logger.warning("yara_rule_pack_provider_no_org_context")
            return None

        versions = await self._repo.list_published_versions_for_org(org_id)
        sources = [s for v in versions if (s := v.combined_rule_source) is not None]
        return "\n\n".join(sources) if sources else None
