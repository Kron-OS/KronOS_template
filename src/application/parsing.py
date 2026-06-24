"""Abstract forensic parser base class and ParserType enum."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from enum import StrEnum

from src.domain.evidence import Evidence
from src.domain.timeline import TimelineRecord
from src.domain.user import TenantContext


class ParserType(StrEnum):
    """Execution environment for a parser."""

    FAST = "fast"  # gVisor; completes in seconds
    HEAVY = "heavy"  # Firecracker; may take minutes


class ForensicParser(ABC):
    """Abstract base for all forensic parsers.

    Subclasses implement format-specific logic and register themselves with
    ParserRegistry at startup.  The orchestrator selects a parser purely via
    supports() — no if/elif chains anywhere in orchestration code.
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
