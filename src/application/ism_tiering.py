"""Per-source ISM tier resolution. Roadmap M1/B3.

A "tier" is just (policy_id, policy_body, index_pattern) -- ISM itself
already has the real, correct mechanism for routing an index to the right
policy (``ism_template`` + ``priority``, highest number wins when multiple
templates match, confirmed against the live 2.11.1 cluster in
poc/ism_tiering_legal_hold/). This resolver's only job is telling the
ingestion path which policy_id a given source maps to, so it can call
``IsmLifecycleManager.ensure_managed()`` with the right one -- ISM's own
priority ordering is what actually decides attachment at the cluster level;
this resolver just needs to agree with it, not duplicate it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path


class IsmTierResolver(ABC):
    """Maps a data source to the ISM policy_id it should be managed under."""

    @abstractmethod
    def policy_id_for_source(self, source_id: str | None) -> str:
        """The policy_id to attach for this source.

        ``source_id`` is ``None`` for case-scoped indices (mixed log types,
        evidentiary -- always the standard tier; see
        ``timeline_normalization.build_index_name``) and a real source name
        for stream-scoped indices (``build_stream_index_name``).
        """

    @abstractmethod
    def policy_body_for_id(self, policy_id: str) -> dict:
        """The real policy document for a policy_id, for ``ensure_policy()``."""


# Confirmed via poc/ism_tiering_legal_hold/: ISM applies the *highest*
# priority ism_template match when several templates could match the same
# index (see src/adapter/opensearch/ism_policy_stream_aggressive.json's
# priority: 200 vs. ism_policy.json's priority: 100). High-volume,
# lower-forensic-priority continuous telemetry sources get the aggressive
# tier; anything else (including any source not in this list) falls back to
# the standard case-grade tier -- a new high-volume source is registration
# here, not a new class, per CLAUDE.md's "no premature abstraction" guidance
# (get_default_log_types() in detector_provisioner.py is the same idiom).
_STANDARD_POLICY_ID = "kronos-rollover"
_AGGRESSIVE_POLICY_ID = "kronos-stream-aggressive"
_AGGRESSIVE_TIER_SOURCES: frozenset[str] = frozenset({"network", "firewall", "flow", "dns"})


class DefaultIsmTierResolver(IsmTierResolver):
    """The real, currently-deployed tier assignment."""

    def policy_id_for_source(self, source_id: str | None) -> str:
        if source_id is not None and source_id in _AGGRESSIVE_TIER_SOURCES:
            return _AGGRESSIVE_POLICY_ID
        return _STANDARD_POLICY_ID

    def policy_body_for_id(self, policy_id: str) -> dict:
        import json

        filename = "ism_policy.json" if policy_id == _STANDARD_POLICY_ID else "ism_policy_stream_aggressive.json"
        path = Path(__file__).parent.parent / "adapter" / "opensearch" / filename
        with path.open() as fh:
            return json.load(fh)
