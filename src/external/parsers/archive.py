"""ZipArchiveParser: explodes a ZIP container (e.g. a KAPE triage collection)
into inner artifacts and recursively re-dispatches each through the same
ParserRegistry, so a KAPE ``.zip`` works with every parser already registered
without any of them needing to know about containers.

**YARA scanning (roadmap E3).** ``extract_artifacts()`` re-walks the same
member set ``parse()`` recurses into (via the shared ``_iter_members()``
walk below) and scans each member's raw bytes with an injected
``YaraXSandboxRunner`` against an injected ``YaraRuleProvider``'s rule text,
emitting ``StructuredArtifact(kind="yara.match")`` per real match. Both
collaborators are optional and default to ``None`` -- "no runner/no rules
configured" is an honest disabled state (yields nothing), the same pattern
this codebase already uses for ``RFC3161TimestampService`` etc. See that
method's own docstring for the compile-once-per-member design and the real
measured numbers behind not batching further.

Deliberate simplification vs. reviews/Extensibility_Architecture_Proposal.md's
originally sketched design (a separate ``ArchiveExtractor`` ABC + registry,
wired as a new branch in ``ParsingOrchestrationService``): this ships as a
``ForensicParser`` subclass instead, registered *first* in ``ParserRegistry``.
That means zero changes were needed to orchestration -- it still just
"resolve one parser via first-match-wins, call parse(), get records" -- which
is far lower-risk to ship and verify than a parallel dispatch path. The
tradeoff is that an extracted member's bytes must be fully buffered in memory
per-member (bounded by MAX_PER_FILE_UNCOMPRESSED_BYTES) rather than streamed
member-by-member from a lazily-reopened archive handle; real KAPE artifacts
(individual EVTX/registry/prefetch/SQLite files) are routinely well under
that bound.

Zip-bomb defense reads each member through a bounded ``read(cap + 1)`` (never
trusting the archive's own declared ``ZipInfo.file_size``, which a malicious
zip can lie about) and charges a *shared* budget across the whole recursive
extraction tree via a ContextVar (``_container_common.py``, shared with
``TarArchiveParser`` too -- see that module's docstring for why the budget
must be shared *across container types*, not just within one), so nested
zip-in-zip (or zip-in-tar-in-zip) containers can't each individually stay
"under limit" while the aggregate explodes.
"""

from __future__ import annotations

import logging
import tempfile
import zipfile
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from src.application.parsing import ForensicParser, ParserType
from src.application.yara_rules import YaraRuleProvider
from src.domain.artifact import StructuredArtifact
from src.domain.evidence import Evidence
from src.domain.timeline import EvidenceProvenance, TimelineRecord
from src.domain.user import TenantContext
from src.exceptions import ParsingError, YaraRuleCompilationError, YaraScanError
from src.external.parsers._container_common import (
    ExtractionBudget,
    budget_var,
    depth_var,
    is_unsafe_member_path,
    stamp_artifact_source_path,
    stamp_source_path,
)
from src.external.sandbox.yara_x_runner import YaraRuleMatch, YaraXSandboxRunner

if TYPE_CHECKING:
    from src.application.parser_registry import ParserRegistry

logger = logging.getLogger(__name__)

_ZIP_MAGIC = b"PK\x03\x04"

MAX_CONTAINER_DEPTH = 3
MAX_MEMBER_COUNT = 50_000
MAX_TOTAL_UNCOMPRESSED_BYTES = 4 * 1024**3  # 4 GiB
MAX_PER_FILE_UNCOMPRESSED_BYTES = 1024**3  # 1 GiB -- matches the single-file upload cap


class ZipArchiveParser(ForensicParser):
    """Explodes a ZIP into inner artifacts, re-dispatching each through the
    injected ``ParserRegistry``.

    Must be registered FIRST in that same registry (see
    ``src/external/dependencies.py::get_parser_registry``): first-match-wins
    detection means it claims every ZIP before any other parser gets a
    chance, and its own recursive ``get_parser()`` calls transparently
    support zip-in-zip nesting (bounded by ``MAX_CONTAINER_DEPTH``) since a
    nested zip member resolves back to this same class in the registry.
    """

    def __init__(
        self,
        registry: ParserRegistry,
        yara_runner: YaraXSandboxRunner | None = None,
        yara_rule_provider: YaraRuleProvider | None = None,
    ) -> None:
        self._registry = registry
        self._yara_runner = yara_runner
        self._yara_rule_provider = yara_rule_provider

    @property
    def parser_name(self) -> str:
        return "zip-archive"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def parser_type(self) -> ParserType:
        # Always HEAVY: an inner member may require Plaso (registry hive,
        # prefetch, SQLite), and only the heavy queue's worker image has
        # Plaso installed (docker/Dockerfile.plaso-worker's venv is `pip
        # install .` PLUS plaso -- a strict superset, so every first-party
        # fast parser also runs fine there; the reverse is not true).
        return ParserType.HEAVY

    def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
        return header_bytes[: len(_ZIP_MAGIC)] == _ZIP_MAGIC

    async def parse(
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[TimelineRecord]:
        depth = depth_var.get()
        if depth >= MAX_CONTAINER_DEPTH:
            raise ParsingError(
                "Container nesting exceeds maximum depth",
                context={
                    "evidence_id": str(evidence.evidence_id),
                    "max_depth": MAX_CONTAINER_DEPTH,
                },
            )

        budget = budget_var.get()
        owns_budget = budget is None
        if owns_budget:
            budget = ExtractionBudget()
            budget_var.set(budget)

        depth_token = depth_var.set(depth + 1)
        try:
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                async for chunk in stream:
                    tmp.write(chunk)
                tmp_path = tmp.name

            try:
                async for record in self._walk_zip(tmp_path, evidence, tenant, budget):
                    yield record
            finally:
                Path(tmp_path).unlink(missing_ok=True)
        finally:
            depth_var.reset(depth_token)
            if owns_budget:
                budget_var.set(None)

    async def extract_artifacts(
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[StructuredArtifact]:
        """YARA-scan every ZIP member's raw bytes, yielding real matches.

        Honestly disabled (yields nothing) when no ``yara_runner``/
        ``yara_rule_provider`` was injected, or the provider has no rules
        configured -- same "optional collaborator" idiom this codebase
        already uses elsewhere (see this module's own docstring).

        A second, independent recursive walk of the same container (its own
        depth/budget scope, same tradeoff ``ParsingOrchestrationService``
        already documents for the ``parse()``/``extract_artifacts()``
        split). Re-uses :meth:`_iter_members` -- the exact same
        container-bomb defenses (path-traversal rejection, bounded reads,
        shared ``ExtractionBudget``) ``parse()`` itself relies on, so a fix
        to one is a fix to both, never two copies to keep in sync.

        One compile+scan per *member* (not per configured rule -- see
        ``YaraRuleProvider``'s own docstring for why rules are combined into
        one source string). Real, measured numbers checked before deciding
        not to also batch multiple *members* into one subprocess call
        (compile-once-scan-many across an entire container): a bare cold
        ``python3 -c 'pass'`` subprocess launch costs ~13ms on this dev
        host, but the real, complete round trip through
        ``YaraXSandboxRunner.run()`` -- launching the actual worker script,
        which additionally imports ``yara_x`` (a real Rust extension with
        its own load cost) and does the rule-file/target-file I/O -- was
        independently measured end to end (``poc/yara_recursion_scanning/``)
        at ~58ms per member, not ~16ms as an earlier, narrower measurement
        (bare subprocess launch + in-process compile/scan, no real worker
        invocation) implied. Even at this real, higher number, a
        pathological 500-member KAPE zip adds only ~29s, still well inside a
        HEAVY Celery task's multi-minute budget (CLAUDE.md B.6). Batching
        many members into one subprocess call would need to buffer their
        bytes simultaneously in memory, working against the same per-member
        memory-boundedness ``parse()`` already relies on -- not worth that
        tradeoff to solve a cost that isn't actually a problem at realistic
        container sizes. Flagged as a real, checked (not guessed) follow-up
        if a much larger real container makes this measurement stale.

        A rule *compilation* error (bad ruleset syntax) is a ruleset-wide
        problem -- it will fail identically for every member, so scanning
        is aborted for the rest of this evidence file's extract_artifacts()
        after the first occurrence (logged once), rather than repeating the
        same guaranteed failure per member. A rule *scan* error (subprocess
        hiccup, in-worker timeout on one pathological member) is treated as
        specific to that one member -- logged and skipped, scanning
        continues with the next member. Neither ever propagates as an
        exception: this method's own failures must never abort or block
        parse()'s TimelineRecord output for the same evidence file (a
        wholly separate stream/pass in ParsingOrchestrationService), nor
        the evidence's own PARSE_COMPLETED transition.
        """
        if self._yara_runner is None or self._yara_rule_provider is None:
            return
        rule_source = await self._yara_rule_provider.get_rule_source()
        if not rule_source:
            return

        depth = depth_var.get()
        if depth >= MAX_CONTAINER_DEPTH:
            logger.warning(
                "zip_yara_scan_skipped_depth_exceeded",
                extra={"evidence_id": str(evidence.evidence_id), "max_depth": MAX_CONTAINER_DEPTH},
            )
            return

        budget = budget_var.get()
        owns_budget = budget is None
        if owns_budget:
            budget = ExtractionBudget()
            budget_var.set(budget)

        depth_token = depth_var.set(depth + 1)
        try:
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
                async for chunk in stream:
                    tmp.write(chunk)
                tmp_path = tmp.name

            try:
                async for artifact in self._scan_members_for_yara(
                    tmp_path, evidence, tenant, budget, rule_source
                ):
                    yield artifact
            finally:
                Path(tmp_path).unlink(missing_ok=True)
        finally:
            depth_var.reset(depth_token)
            if owns_budget:
                budget_var.set(None)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _walk_zip(
        self,
        zip_path: str,
        evidence: Evidence,
        tenant: TenantContext,
        budget: ExtractionBudget,
    ) -> AsyncIterator[TimelineRecord]:
        async for member_path, data in self._iter_members(zip_path, evidence, budget):
            async for record in self._dispatch_member(member_path, data, evidence, tenant):
                yield record

    async def _iter_members(
        self,
        zip_path: str,
        evidence: Evidence,
        budget: ExtractionBudget,
    ) -> AsyncIterator[tuple[str, bytes]]:
        """Yield ``(member_path, data)`` for every safe, budget-charged member.

        Shared by ``parse()`` (dispatches each member to a sub-parser) and
        ``extract_artifacts()`` (YARA-scans each member's raw bytes) so the
        container-bomb defenses (path-traversal rejection, bounded reads,
        shared ``ExtractionBudget``) live in exactly one place, not two
        copies that could drift (CLAUDE.md's own concern: "a fix applied to
        one copy and not the other").
        """
        try:
            zf = zipfile.ZipFile(zip_path)
        except zipfile.BadZipFile as exc:
            raise ParsingError(
                "Not a valid ZIP archive",
                context={"evidence_id": str(evidence.evidence_id), "error": str(exc)},
            ) from exc

        with zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if is_unsafe_member_path(info.filename):
                    logger.warning(
                        "zip_member_path_rejected",
                        extra={"evidence_id": str(evidence.evidence_id), "member": info.filename},
                    )
                    continue

                # Never trust ZipInfo.file_size (a malicious archive can lie
                # about it) -- bound the actual decompressed read instead.
                with zf.open(info) as member_fp:
                    data = member_fp.read(MAX_PER_FILE_UNCOMPRESSED_BYTES + 1)
                if len(data) > MAX_PER_FILE_UNCOMPRESSED_BYTES:
                    logger.warning(
                        "zip_member_too_large_skipped",
                        extra={"evidence_id": str(evidence.evidence_id), "member": info.filename},
                    )
                    continue

                budget.charge(
                    len(data),
                    evidence,
                    max_member_count=MAX_MEMBER_COUNT,
                    max_total_bytes=MAX_TOTAL_UNCOMPRESSED_BYTES,
                )

                yield info.filename, data

    async def _dispatch_member(
        self,
        member_path: str,
        data: bytes,
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[TimelineRecord]:
        basename = Path(member_path).name
        header = data[:8192]
        parser = self._registry.get_parser(basename, "application/octet-stream", header)
        if parser is None:
            logger.info(
                "zip_member_no_parser",
                extra={"evidence_id": str(evidence.evidence_id), "member": member_path},
            )
            return

        async def _one_shot() -> AsyncIterator[bytes]:
            yield data

        async for record in parser.parse(_one_shot(), evidence, tenant):
            yield stamp_source_path(record, member_path, evidence)

    async def _scan_members_for_yara(
        self,
        zip_path: str,
        evidence: Evidence,
        tenant: TenantContext,
        budget: ExtractionBudget,
        rule_source: str,
    ) -> AsyncIterator[StructuredArtifact]:
        """YARA-scan every member yielded by :meth:`_iter_members`.

        Also recurses into a member that is itself a container (zip/tar),
        re-dispatching through the same registry ``parse()``'s own
        ``_dispatch_member`` uses -- mirrors that recursion exactly, so a
        zip-in-zip's innermost members get scanned individually with a
        correctly nested ``source_path``, not just as opaque bytes of the
        outer member.
        """
        record_index = 0
        async for member_path, data in self._iter_members(zip_path, evidence, budget):
            try:
                scan_result = await self._yara_runner.run(rule_source, data)  # type: ignore[union-attr]
            except YaraRuleCompilationError as exc:
                # A ruleset-wide problem (bad rule syntax) -- it will fail
                # identically for every remaining member, so stop scanning
                # for the rest of this evidence file rather than repeat a
                # guaranteed failure per member. Logged once here, never
                # re-raised: extract_artifacts() must never propagate an
                # exception that could abort parse()'s independent
                # TimelineRecord pass or the evidence's own completion.
                logger.warning(
                    "yara_ruleset_compile_failed",
                    extra={"evidence_id": str(evidence.evidence_id), "error": str(exc)},
                )
                return
            except YaraScanError as exc:
                # Specific to this one member (subprocess hiccup, an
                # in-worker timeout on pathological content) -- log and move
                # on to the next member, mirroring the
                # zip_member_no_parser/tar_member_no_parser "one bad thing
                # doesn't sink the container" precedent.
                logger.warning(
                    "yara_scan_member_failed",
                    extra={
                        "evidence_id": str(evidence.evidence_id),
                        "member": member_path,
                        "error": str(exc),
                    },
                )
            else:
                for rule_match in scan_result.matched_rules:
                    yield self._build_yara_artifact(rule_match, member_path, evidence, record_index)
                    record_index += 1

            async for nested_artifact in self._recurse_into_nested_container(
                member_path, data, evidence, tenant
            ):
                yield nested_artifact

    async def _recurse_into_nested_container(
        self,
        member_path: str,
        data: bytes,
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[StructuredArtifact]:
        basename = Path(member_path).name
        header = data[:8192]
        nested_parser = self._registry.get_parser(basename, "application/octet-stream", header)
        if nested_parser is None:
            return

        async def _one_shot() -> AsyncIterator[bytes]:
            yield data

        async for artifact in nested_parser.extract_artifacts(_one_shot(), evidence, tenant):
            yield stamp_artifact_source_path(artifact, member_path, evidence)

    def _build_yara_artifact(
        self,
        rule_match: YaraRuleMatch,
        member_path: str,
        evidence: Evidence,
        record_index: int,
    ) -> StructuredArtifact:
        content = {
            "rule_identifier": rule_match.identifier,
            "rule_namespace": rule_match.namespace,
            "rule_tags": list(rule_match.tags),
            "matched_strings": [
                {
                    "pattern_identifier": s.pattern_identifier,
                    "offset": s.offset,
                    "length": s.length,
                    "xor_key": s.xor_key,
                }
                for s in rule_match.matched_strings
            ],
        }
        provenance = EvidenceProvenance(
            evidence_id=evidence.evidence_id,
            case_id=evidence.metadata.case_id,
            org_id=evidence.metadata.org_id,
            org_alias=evidence.metadata.org_alias,
            sha256=evidence.sha256 or "",
            parser=self.parser_name,
            parser_version=self.parser_version,
            record_index=record_index,
            ingest_timestamp=datetime.now(UTC),
            source_path=member_path,
            container_sha256=evidence.sha256,
        )
        return StructuredArtifact(kind="yara.match", content=content, kronos=provenance)
