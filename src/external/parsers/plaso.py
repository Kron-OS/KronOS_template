"""PlasoParser: heavy forensic parser using Plaso in a Firecracker microVM.

Supports: Windows Registry (REGF), Prefetch, SRUM, SQLite artifacts,
Amcache, systemd journald, and EML email archives.
"""

from __future__ import annotations

import logging
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

from src.application.parsing import ForensicParser, ParserType
from src.domain.evidence import Evidence
from src.domain.timeline import TimelineRecord
from src.domain.user import TenantContext

logger = logging.getLogger(__name__)

# Magic bytes for formats Plaso specialises in.
_REGF_MAGIC = b"regf"
_PREFETCH_MAGIC = b"MAM"  # Prefetch files start with MAM\x04 or MAM\x08
_SQLITE_MAGIC = b"SQLite format 3"
_EVTX_MAGIC = b"ElfFile\x00"  # Already handled by FastEvtxParser


class PlasoParser(ForensicParser):
    """Heavy forensic parser delegating to Plaso via Firecracker sandbox.

    Plaso can handle: Windows Registry, Prefetch, SRUM, SQLite, Amcache,
    journald, EML. EVTX is explicitly excluded — FastEvtxParser is faster.
    """

    # Extensions that Plaso handles better than generic parsers.
    _SUPPORTED_EXTENSIONS: frozenset[str] = frozenset(
        {
            "dat",  # Windows SRUM / Amcache / Shimcache
            "db",
            "sqlite",
            "sqlite3",
            "hve",
            "hiv",  # Registry hives
        }
    )

    @property
    def parser_name(self) -> str:
        return "plaso"

    @property
    def parser_version(self) -> str:
        return "20240101"

    @property
    def parser_type(self) -> ParserType:
        return ParserType.HEAVY

    def supports(self, filename: str, content_type: str, header_bytes: bytes) -> bool:
        """Return True for formats Plaso handles exclusively."""
        # Never claim EVTX — FastEvtxParser is faster and registered first.
        if header_bytes.startswith(_EVTX_MAGIC):
            return False

        # Registry hive
        if header_bytes.startswith(_REGF_MAGIC):
            return True

        # Prefetch files
        if len(header_bytes) >= 4 and header_bytes[:3] == b"MAM":
            return True

        # SQLite databases (SRUM, Amcache, browser history, etc.)
        if header_bytes.startswith(_SQLITE_MAGIC):
            return True

        # journald binary journals
        if header_bytes.startswith(b"\xbe\xb9\xb0\xd9\x70\x14\x1e\x2d"):
            return True

        ext = Path(filename).suffix.lstrip(".").lower()
        return ext in self._SUPPORTED_EXTENSIONS

    async def parse(
        self,
        stream: AsyncIterator[bytes],
        evidence: Evidence,
        tenant: TenantContext,
    ) -> AsyncIterator[TimelineRecord]:
        """Write evidence to a temp file and invoke Plaso via FirecrackerLauncher."""
        from src.external.sandbox.firecracker import FirecrackerLauncher  # noqa: PLC0415

        with tempfile.NamedTemporaryFile(
            suffix=Path(evidence.metadata.original_filename).suffix,
            delete=False,
        ) as tmp:
            async for chunk in stream:
                tmp.write(chunk)
            tmp_path = tmp.name

        logger.info(
            "plaso_temp_file_ready",
            extra={"evidence_id": str(evidence.evidence_id), "path": tmp_path},
        )

        launcher = FirecrackerLauncher()
        records = await launcher.run(
            evidence_path=tmp_path,
            evidence_id=str(evidence.evidence_id),
            case_id=str(evidence.metadata.case_id),
            org_id=str(evidence.metadata.org_id),
            org_alias=evidence.metadata.org_alias,
            sha256=evidence.sha256 or "",
            parser_name=self.parser_name,
            parser_version=self.parser_version,
        )

        async for record in records:
            yield record

        # Clean up temp file.
        try:
            Path(tmp_path).unlink(missing_ok=True)
        except OSError:
            pass
