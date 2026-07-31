"""Port for verifying a rule pack's supply-chain signature before acceptance.

Roadmap M2/C3. Reuses, UNCHANGED, the Cosign-based two-tier trust model
already designed in reviews/Extensibility_Architecture_Proposal.md SS4 for
third-party parser plugins -- CLAUDE.md SS G.3 explicitly mandates reusing
this exact model for other trust-boundary decisions in this codebase, not
redesigning it. A signed third-party rule pack is exactly that kind of
decision: "Cosign-verified signature ... gates before a plugin is
registrable" (SS4.1), applied here to a rule pack instead of a parser image.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class PackSignatureVerifier(ABC):
    """Verifies a detached signature over a rule pack's raw content bytes."""

    @abstractmethod
    def verify(self, content: bytes, signature: bytes, public_key_path: str) -> bool:
        """Return True iff *signature* is a valid signature of *content* under
        the key at *public_key_path*.

        Must fail closed: any tool error, timeout, or malformed input returns
        False, never raises past this boundary and never returns True on
        anything but a real, confirmed-valid signature.
        """
