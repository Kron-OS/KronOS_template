"""Abstract forensic parser base class and ParserType enum."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from enum import StrEnum

from src.domain.artifact import StructuredArtifact
from src.domain.evidence import Evidence
from src.domain.timeline import TimelineRecord
from src.domain.user import TenantContext


class ParserType(StrEnum):
    """Execution environment for a parser."""

    FAST = "fast"  # gVisor; completes in seconds
    HEAVY = "heavy"  # Firecracker; may take minutes


class ForensicParser(ABC):
    """Abstract base for all forensic parsers -- the one unified module
    interface for turning raw evidence into KronOS data, whether that data
    is timeline-shaped (parse()) or not (extract_artifacts()).

    Subclasses implement format-specific logic and register themselves with
    ParserRegistry at startup.  The orchestrator selects a parser purely via
    supports() — no if/elif chains anywhere in orchestration code. A single
    module may internally run several sub-analyses and yield a mixed result
    (PlasoParser already does this for TimelineRecord; a future
    VolatilityModule would do the same across parse()+extract_artifacts()) --
    see reviews/Data_Source_Module_System.md for the full design.
    """

    @property
    @abstractmethod
    def parser_name(self) -> str:
        """Stable identifier, e.g. 'evtx-rs', 'cloudtrail', 'nginx'."""

    @property
    @abstractmethod
    def parser_version(self) -> str:
        """Semver string, e.g. '1.0.0'."""

    @property
    @abstractmethod
    def parser_type(self) -> ParserType:
        """FAST (gVisor) or HEAVY (Firecracker)."""

    @abstractmethod
    def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
        """Return True if this parser can handle the given file."""

    @abstractmethod
    async def parse(
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[TimelineRecord]:
        """Yield TimelineRecord objects one at a time.

        Implementations must be memory-efficient: accumulate only as many bytes
        as needed to decode one record at a time.  Every yielded record must have
        a fully-populated kronos.* provenance block with record_index set to its
        zero-based position within this evidence file.
        """
        # Stub body makes this an async generator consistent with concrete subclasses.
        return
        yield  # noqa: RET504

    async def extract_artifacts(
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[StructuredArtifact]:
        """Yield non-timeline structured artifacts this parser can produce.

        Concrete (not abstract) with a real default of "nothing" -- every
        existing parser needs zero changes to keep working. Override only
        when this module produces data that doesn't belong in a timeline
        (a process tree, a network graph, a config snapshot, ...); see
        reviews/DFIR_Artifact_Landscape.md §10 for the real, named examples
        this exists for, and reviews/Data_Source_Module_System.md for why
        this is a second method rather than a union return type on parse().
        """
        return
        yield  # noqa: RET504
