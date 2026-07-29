"""StructuredArtifact: a piece of forensic evidence that is not a timeline event.

See reviews/Data_Source_Module_System.md for the full design rationale.
Examples: a Volatility `pstree` (process tree), a NetFlow connection
matrix, a `.plist` config snapshot -- none of these is "a list of
timestamped events," so none belongs in TimelineRecord. `content` is
intentionally opaque (module-defined shape) -- no per-kind schema or
presentation/analysis layer is decided yet; this type only guarantees safe
capture with the same chain-of-custody provenance every other KronOS
record carries.
"""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, Field

from src.domain.timeline import KronosProvenance


class StructuredArtifact(BaseModel):
    """A single non-timeline forensic artifact, opaque by design."""

    model_config = {"frozen": True}

    # Modules never need to generate this themselves -- same ergonomics as
    # TimelineRecord.document_id being computed by the orchestrator, not
    # the parser.
    artifact_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    # Namespaced, module-declared string (e.g. "volatility.pstree") --
    # deliberately not a closed enum, so new modules can introduce new
    # kinds without a domain-layer code change (CLAUDE.md A.4).
    kind: str
    content: dict[str, Any]
    # Same provenance block TimelineRecord uses -- one custody story
    # platform-wide, not a bespoke shape per artifact kind.
    kronos: KronosProvenance
