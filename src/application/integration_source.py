"""IntegrationSource: the foundation ABC for external EDR/XDR/IDS/SIEM tools
handing KronOS their own real alerts (roadmap Q1).

**Design decision, read before extending (mirrors H2/H3/D4's own honesty
precedent of arguing a design choice in the module it lands in).**
``docs/KAFKA_AND_INTEGRATIONS_ROADMAP.md``'s own §4 explicitly requires
justifying, per CLAUDE.md §G.1's standing rule against parallel class
hierarchies, whether a *new* ABC is warranted here rather than extending
``ForensicParser`` (``src/application/parsing.py``). Investigated seriously,
conclusion: **yes, a new ABC, for reasons that are structural, not
cosmetic:**

1. ``ForensicParser.parse()``/``extract_artifacts()`` both require an
   ``Evidence`` domain object (``evidence_id``, a case, a source-file
   ``sha256``) -- correct for a record parsed out of an uploaded, hashed
   file, structurally impossible for a live external alert, which has none
   of those (no owning file, nothing to hash per-event, no case at ingest
   time). This is the exact same argument ``StreamProvenance``'s own
   docstring (``src/domain/stream.py``) already made and won for continuous
   telemetry in general -- an ``IntegrationSource`` is a producer of exactly
   that provenance shape, not the file-shaped one.
2. ``ParserRegistry.get_parser()`` dispatches by sniffing
   ``(filename, content_type, header_bytes)`` -- meaningless for a live
   network source: there is no filename, and "sniff the first bytes" makes
   no sense for a scheduled outbound poll that hasn't happened yet.
   Dispatch here is always by an explicit, already-known ``source_type``
   (a URL path segment for push, an explicit per-connector config for
   poll) -- a completely different selection mechanism, not a variant of
   the same one.
3. Concretely new state/behavior ``ForensicParser`` has no notion of at
   all: a durable cursor/watermark for poll-based resumption
   (``SourceCursor``), and a live inbound webhook entry point with its own
   pluggable authentication (mTLS/API-key/OAuth2) instead of a single
   already-authenticated file upload.

Per §4's own constraint, this ABC's methods still only ever produce the
same two terminal domain types every other module produces
(``TimelineRecord``/``StructuredArtifact``) -- **but not directly**. See
"Why fetch is separate from mapping" below for why the two methods on this
ABC return raw bytes, not domain objects, and how ECS mapping still reuses
existing, proven infrastructure unchanged.

**Why fetch is separate from mapping (a second real finding, not assumed).**
``TimelineRecord.kronos`` for continuous telemetry is a ``StreamProvenance``
(``src/domain/stream.py``), whose ``batch_id`` field is **mandatory, with no
default** -- by design: "a stream record tagged with stream provenance
cannot be constructed until that event's batch has actually been sealed"
(``StreamNormalizationService``'s own docstring). No batch exists yet at the
moment an ``IntegrationSource`` fetches a raw external event, so this ABC's
methods cannot honestly construct a ``TimelineRecord`` at that point without
either violating that mandatory field (leaving it unset/fake, the exact
custody-impersonation bug ``StreamProvenance``'s docstring itself warns
against) or inventing a second, parallel provenance shape (a real "third
output shape" the roadmap's own §4 explicitly warns against). The correct,
minimal-new-surface answer, verified by reading the real existing pipeline
(``src/application/collector_ingest.py`` -> ``src/adapter/queue/
stream_ingest.py`` -> ``src/application/batch_sealing.py`` ->
``src/application/stream_normalization.py``): an ``IntegrationSource``'s job
is exactly the two genuinely new pieces (auth + fetch position/cursor); ECS
mapping to the real terminal ``TimelineRecord``/``StructuredArtifact`` types
is delegated to a ``StreamSourceNormalizer``
(``src/application/stream_source_registry.py``) registered under the same
``source_id``, run later by the existing, unmodified
``StreamNormalizationService`` once a real ``SealedBatch`` exists -- the
exact same real mechanism Zeek's own conn-log source already proves end to
end. This is not a shortcut: it is the only design that does not fake a
mandatory provenance field.

**Known, pre-existing gap this surfaces (reported, not silently fixed --
CLAUDE.md's own instruction for out-of-scope findings).** ``StreamSourceNormalizer.normalize()``
can only return a ``NormalizedStreamEvent`` (TimelineRecord-shaped) -- there
is no artifact-shaped equivalent today. A future poll source whose real
payload is artifact-shaped (Microsoft Defender's ``evidence[]`` entity list,
named explicitly in the roadmap) cannot be fully wired to durable storage
via this pipeline until that normalizer-side gap is closed (and
``StructuredArtifact.kronos`` -- still typed as the evidence-only
``KronosProvenance`` alias, unlike ``TimelineRecord.kronos``'s already-widened
discriminated union -- is widened to match, which itself requires touching
``ArtifactRepository.list_by_evidence``'s ``a.kronos.evidence_id`` access).
Out of Q1's scope (no concrete artifact-shaped source is being built yet);
flagged here for Q4's own dispatch brief.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from src.domain.integration_source import (
    IntegrationDeliveryMode,
    IntegrationSourceIdentity,
    SourceCursor,
)
from src.exceptions import KronOSException


class IntegrationSourceError(KronOSException):
    """Raised when an IntegrationSource cannot fetch/parse its real external
    dependency's data -- a real, observed failure (bad response code,
    malformed body, auth rejection), never silently swallowed into an empty
    result (CLAUDE.md §B.2/invariant #8)."""


@dataclass(frozen=True)
class PollFetchResult:
    """One poll cycle's real, raw output: zero or more raw event payloads
    plus the watermark to resume from next time.

    ``raw_events`` are opaque bytes, not yet ECS-mapped -- see this module's
    own docstring for why mapping is a separate, later step. ``next_cursor``
    is ``None`` only when the source has nothing new to report (an empty
    page) -- the orchestrator must not advance a real watermark based on no
    real progress; a non-``None`` value is persisted verbatim into the next
    ``SourceCursor``.
    """

    raw_events: list[bytes]
    next_cursor: str | None


class IntegrationSource(ABC):
    """A registered connector to one external tool's own alert/event feed.

    Every concrete source is either PUSH (implements
    :meth:`parse_push_event`) or POLL (implements :meth:`poll`) --
    :attr:`delivery_mode` declares which, and the *other* method's base
    implementation deliberately raises :class:`NotImplementedError` rather
    than silently returning an empty result. This differs from
    ``ForensicParser.extract_artifacts()``'s own "concrete default: yields
    nothing" idiom on purpose: "this module has no artifacts" is a
    legitimate real answer for a file-shaped parser, but calling the wrong
    delivery-mode method here always means an orchestration bug, not a
    legitimate empty result -- CLAUDE.md invariant #8 (fail loudly) applies.
    """

    @property
    @abstractmethod
    def source_type(self) -> str:
        """Stable identifier, e.g. 'generic-webhook', 'wazuh'. Exact-match
        dispatch key for IntegrationSourceRegistry -- never sniffed."""

    @property
    @abstractmethod
    def source_version(self) -> str:
        """Semver string, e.g. '1.0.0' -- mirrors ForensicParser.parser_version."""

    @property
    @abstractmethod
    def delivery_mode(self) -> IntegrationDeliveryMode:
        """PUSH or POLL -- declares which of the two methods below is real."""

    async def parse_push_event(self, raw_body: bytes) -> list[bytes]:
        """Split one inbound webhook POST body into individual raw event
        payloads (e.g. unwrap a vendor's own batch envelope).

        Concrete default: treat the whole body as a single event --
        correct for a vendor whose webhook POSTs exactly one event per
        call, an already-real, non-hypothetical simplification (mirrors
        this codebase's own "one real, minimal shape first" precedent).
        Only PUSH sources are ever called this way; a POLL-only source
        that does not override this will still get this same default,
        which is harmless (it is simply never invoked by the push
        ingest path for a POLL-mode source -- see
        ``IntegrationSourceRegistry``/``IntegrationPushIngestService``'s own
        delivery_mode check).
        """
        return [raw_body]

    async def poll(
        self, identity: IntegrationSourceIdentity, cursor: SourceCursor | None
    ) -> PollFetchResult:
        """Fetch new raw events from the real external API since *cursor*.

        Only POLL sources implement this. Raises
        :class:`IntegrationSourceError` on any real failure (auth rejected,
        non-2xx response, malformed body) -- never returns a fabricated
        empty result to paper over a real failure (CLAUDE.md invariant #8).
        """
        raise NotImplementedError(
            f"{type(self).__name__} is not a POLL-mode IntegrationSource "
            f"(delivery_mode={self.delivery_mode!r}) -- calling poll() on it is an "
            "orchestration bug, not a legitimate empty result."
        )


class IntegrationSourceRegistry:
    """Holds registered IntegrationSource instances, keyed by exact source_type.

    Mirrors ParserRegistry's registration idiom (adding a new source needs
    only a register() call, zero changes to orchestration code) but dispatch
    is exact-match on an already-known key, not content-sniffing -- see
    IntegrationSource's own module docstring for why that difference is
    real, not cosmetic.
    """

    def __init__(self) -> None:
        self._sources: dict[str, IntegrationSource] = {}

    def register(self, source: IntegrationSource) -> None:
        """Add a source. Raises ValueError on a duplicate source_type --
        unlike ParserRegistry's first-match-wins list, there is no
        meaningful "priority order" for an exact-match key, so a collision
        is always a real configuration mistake, not an intentional
        override."""
        if source.source_type in self._sources:
            raise ValueError(
                f"IntegrationSource already registered for source_type={source.source_type!r}"
            )
        self._sources[source.source_type] = source

    def get(self, source_type: str) -> IntegrationSource | None:
        """Return the registered source for source_type, or None."""
        return self._sources.get(source_type)

    def all_sources(self) -> list[IntegrationSource]:
        """Return a copy of all registered sources."""
        return list(self._sources.values())
