"""Hash-chain and Merkle-tree verifiers for offline audit log attestation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

# Genesis hash: SHA-256("kronos-audit-genesis") — must match AuditLogService.
GENESIS_HASH = hashlib.sha256(b"kronos-audit-genesis").hexdigest()


def _canonical_json(ev: dict[str, Any]) -> bytes:
    """Reproduce the canonical JSON used by AuditLogService.hash_chain."""
    payload = {
        "event_id": ev.get("event_id", ""),
        "event_type": ev.get("event_type", ""),
        "actor_user_id": ev.get("actor_user_id"),
        "actor_username": ev.get("actor_username"),
        "org_id": ev.get("org_id"),
        "case_id": ev.get("case_id"),
        "evidence_id": ev.get("evidence_id"),
        "details": ev.get("details", {}),
        "occurred_at": ev.get("occurred_at", ""),
        "sequence_number": ev.get("sequence_number", 0),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_row_hash(prev_hash: str, ev: dict[str, Any]) -> str:
    """Recompute a row hash from previous hash and event dict."""
    digest = hashlib.sha256()
    digest.update(prev_hash.encode("utf-8"))
    digest.update(_canonical_json(ev))
    return digest.hexdigest()


def build_merkle_root(row_hashes: list[str]) -> str:
    """Compute Merkle root from a list of row_hash strings (sorted by sequence_number)."""
    if not row_hashes:
        return hashlib.sha256(b"empty").hexdigest()
    layer: list[bytes] = [hashlib.sha256(h.encode()).digest() for h in row_hashes]
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        layer = [hashlib.sha256(layer[i] + layer[i + 1]).digest() for i in range(0, len(layer), 2)]
    return layer[0].hex()


def merkle_proof(row_hashes: list[str], index: int) -> list[str]:
    """Return the sibling hashes needed to prove inclusion of row_hashes[index]."""
    if not row_hashes:
        return []
    proof: list[str] = []
    layer: list[bytes] = [hashlib.sha256(h.encode()).digest() for h in row_hashes]
    idx = index
    while len(layer) > 1:
        if len(layer) % 2 == 1:
            layer.append(layer[-1])
        sibling = idx ^ 1
        if sibling < len(layer):
            proof.append(layer[sibling].hex())
        next_layer = [
            hashlib.sha256(layer[i] + layer[i + 1]).digest() for i in range(0, len(layer), 2)
        ]
        idx //= 2
        layer = next_layer
    return proof


@dataclass
class ChainBreak:
    """Describes a single hash chain integrity failure."""

    sequence_number: int
    event_id: str
    stored_hash: str
    computed_hash: str


@dataclass
class ChainVerificationResult:
    """Result of verifying the full hash chain of an audit log export."""

    valid: bool
    event_count: int
    breaks: list[ChainBreak] = field(default_factory=list)
    merkle_root: str = ""


class ChainVerifier:
    """Verifies the SHA-256 hash chain of a KronOS audit log export (JSON format)."""

    def verify(self, events: list[dict[str, Any]]) -> ChainVerificationResult:
        """Verify hash chain integrity of an exported audit log.

        Events should be sorted by sequence_number (ascending).
        Returns a ChainVerificationResult with any detected breaks.

        SECURITY: We use the running tracked prev_hash, NOT the stored
        prev_row_hash field.  Using the stored field allows an attacker to
        forge a consistent chain by adjusting prev_row_hash on each event,
        bypassing the tamper-detection guarantee.

        For the Merkle root we always use the *stored* row_hash (even if
        tampered), so the computed root matches what the server anchored at the
        time of the anchor operation.  A mismatch between the computed root and
        the stored anchor root therefore indicates tampering.
        """
        sorted_events = sorted(events, key=lambda e: e.get("sequence_number", 0))
        prev_hash = GENESIS_HASH
        breaks: list[ChainBreak] = []
        row_hashes: list[str] = []

        for ev in sorted_events:
            # Recompute using the running tracked hash — not the stored field.
            computed = compute_row_hash(prev_hash, ev)
            stored = ev.get("row_hash", "")
            # Always include the stored hash in the Merkle layer so we can
            # compare against the server-anchored root.
            row_hashes.append(stored if stored else computed)

            if stored and stored != computed:
                breaks.append(
                    ChainBreak(
                        sequence_number=ev.get("sequence_number", -1),
                        event_id=ev.get("event_id", ""),
                        stored_hash=stored,
                        computed_hash=computed,
                    )
                )
            # Advance the running hash: use stored if valid, computed if missing.
            prev_hash = stored if stored else computed

        root = build_merkle_root(row_hashes)
        return ChainVerificationResult(
            valid=len(breaks) == 0,
            event_count=len(sorted_events),
            breaks=breaks,
            merkle_root=root,
        )


class MerkleVerifier:
    """Verifies Merkle inclusion proofs for individual audit events."""

    def verify_proof(
        self,
        leaf_hash: str,
        proof: list[str],
        root_hash: str,
        index: int,
    ) -> bool:
        """Verify that leaf_hash is included in the Merkle tree with the given root.

        proof is the list of sibling hashes from leaf to root (bottom-up).
        index is the 0-based position of the leaf in the original sorted list.
        """
        current = hashlib.sha256(leaf_hash.encode()).digest()
        idx = index
        for sibling_hex in proof:
            sibling = bytes.fromhex(sibling_hex)
            if idx % 2 == 0:
                current = hashlib.sha256(current + sibling).digest()
            else:
                current = hashlib.sha256(sibling + current).digest()
            idx //= 2
        return current.hex() == root_hash

    def compute_root_from_events(self, events: list[dict[str, Any]]) -> str:
        """Compute Merkle root from a list of event dicts (uses row_hash field)."""
        sorted_events = sorted(events, key=lambda e: e.get("sequence_number", 0))
        row_hashes = [e.get("row_hash") or compute_row_hash(GENESIS_HASH, e) for e in sorted_events]
        return build_merkle_root(row_hashes)
