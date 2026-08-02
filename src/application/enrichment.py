"""Enricher: extensible, additive per-source enrichment applied at ingest
(roadmap F1).

Mirrors this codebase's established ABC+registry extensibility idiom
(``FieldMapping``/``ECSFieldMappingRegistry``,
``StreamSourceNormalizer``/``StreamSourceNormalizerRegistry``): a new
enricher is a new registration, zero changes to existing enrichers or to
``EnrichmentPipeline`` itself.

**Why merged into ``TimelineRecord.extra``, not a new top-level domain
field.** ``extra: dict[str, Any]`` already exists precisely for
format-specific/derived data that doesn't earn a first-class ECS column
(every parser's own dotted-key convention, e.g. ``source.ip``,
``zeek.conn.*``) and ``ECSNormalizer`` already flattens it verbatim into
the indexed document. A new top-level ``TimelineRecord.enrichment`` field
would touch the normalizer, every construction site across six parsers,
and buy nothing ``extra`` doesn't already provide -- CLAUDE.md's own "don't
add abstractions beyond what's needed." The roadmap's actual requirement
-- "derived... goes in a separate namespace so the raw record stays
pristine" -- is satisfied by the ``enrichment.<source_name>.*`` key prefix
below, not by a new field.

**Why enrichment runs once, at ingest time, not as a live re-indexing
pass.** Once a ``TimelineRecord`` is indexed it is, by this platform's own
chain-of-custody principle, never mutated again (the same invariant WORM
evidence storage, the append-only audit log, and immutable sealed batches
already enforce elsewhere in this codebase) -- enrichment computed here
becomes part of that same immutable record, no different in kind from any
other derived field a parser or the ECS field-mapping registry (A2)
already attaches before indexing. If the underlying context source (e.g.
an asset inventory) changes later, the honest answer is NOT to reach back
and edit an already-indexed document -- it's to re-run enrichment against
the original record and index a fresh one. ``EnrichmentPipeline.enrich()``
is deliberately pure/stateless (record + org_id in, a new record out) so
that re-run is trivial to perform later (see
``poc/enrichment_pipeline/`` for a real demonstration of exactly that);
building the actual scheduled re-indexing job is an explicit, separate
follow-up (see this item's own roadmap STATUS note), not required to prove
the mechanism works.
"""

from __future__ import annotations

import logging
import uuid
from abc import ABC, abstractmethod
from typing import Any

from src.domain.timeline import TimelineRecord

logger = logging.getLogger(__name__)


class Enricher(ABC):
    """One real source of derived, additive enrichment data for a
    ``TimelineRecord``.

    ``org_id`` is always supplied by the caller (``EnrichmentPipeline``,
    itself only ever invoked from the authenticated request/task's own
    ``TenantContext``) -- never read from the record's own content. An
    enricher must never look up context for any org but the one it was
    explicitly given (roadmap invariant: tenant isolation is computed,
    never supplied).
    """

    @property
    @abstractmethod
    def source_name(self) -> str:
        """Namespace this enricher writes under -- e.g. ``"asset"`` produces
        keys prefixed ``"enrichment.asset."``. Must be stable across calls;
        used by ``EnrichmentPipeline`` to enforce the namespace contract."""

    @abstractmethod
    async def enrich(self, record: TimelineRecord, org_id: uuid.UUID) -> dict[str, Any] | None:
        """Return derived fields to merge, every key prefixed
        ``f"enrichment.{self.source_name}."``, or ``None`` if this source has
        nothing to add for this record (an honest "no match" -- never a
        fabricated/default result)."""


class EnrichmentPipeline:
    """Composes zero or more registered ``Enricher``s, merging their
    additive output into a ``TimelineRecord``'s own ``extra`` dict.

    A record with no configured enrichers is returned completely unchanged
    (the "honestly disabled" state this codebase uses everywhere an
    optional collaborator is unset, e.g. ``RFC3161TimestampService``).
    """

    def __init__(self, enrichers: list[Enricher] | None = None) -> None:
        self._enrichers = enrichers or []

    async def enrich(self, record: TimelineRecord, org_id: uuid.UUID) -> TimelineRecord:
        """Return a new ``TimelineRecord`` with every enricher's real,
        namespaced output merged into ``extra``. Never mutates the input
        record (frozen, per every other domain model in this codebase) and
        never overwrites an existing key -- a namespace violation or a real
        key collision is logged and the offending key is dropped, not
        silently applied over existing data.
        """
        if not self._enrichers:
            return record

        merged: dict[str, Any] = dict(record.extra)
        changed = False
        for enricher in self._enrichers:
            try:
                result = await enricher.enrich(record, org_id)
            except Exception as exc:  # noqa: BLE001 -- one source's failure must never sink ingest
                logger.warning(
                    "enrichment_source_failed",
                    extra={"source": enricher.source_name, "error": str(exc)},
                )
                continue
            if not result:
                continue

            prefix = f"enrichment.{enricher.source_name}."
            for key, value in result.items():
                if not key.startswith(prefix):
                    logger.warning(
                        "enrichment_key_namespace_violation",
                        extra={"source": enricher.source_name, "key": key},
                    )
                    continue
                if key in merged:
                    logger.warning(
                        "enrichment_key_collision_skipped",
                        extra={"source": enricher.source_name, "key": key},
                    )
                    continue
                merged[key] = value
                changed = True

        if not changed:
            return record
        return record.model_copy(update={"extra": merged})
