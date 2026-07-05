# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Merkle Tree Audit Trail — Tamper-Evident Evidence Logging
──────────────────────────────────────────────────────────
Implements a Merkle hash tree for chaining audit evidence records,
providing tamper-evident integrity for the entire audit trail.

Each evidence record is hashed and combined with the previous record's
hash to form a chain. The Merkle root is periodically anchored
(conceptually to a trusted timestamp or blockchain).

Structure:
  - Each evidence record produces a SHA-256 leaf hash
  - Consecutive leaves are paired and hashed to form a binary Merkle tree
  - The Merkle root uniquely identifies the entire sequence of records
  - Tampering with any record changes the root, enabling detection

ISO/IEC 42001:2023 Clause 7.5 — Documented information integrity
is verified via the Merkle audit trail.
"""

from __future__ import annotations
import hashlib
import json
from typing import Any, Optional


def sha256(data: bytes) -> str:
    """SHA-256 hash as hex string."""
    return hashlib.sha256(data).hexdigest()


def hash_evidence(payload: dict[str, Any], previous_hash: str) -> str:
    """
    Generate a hash for a single evidence record that chains to
    the previous record.

    Format: SHA-256(previous_hash || canonical_json(payload))

    Args:
        payload: The evidence record content
        previous_hash: The hash of the preceding record (or 0x00 for genesis)

    Returns:
        Hex-encoded SHA-256 hash
    """
    canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    combined = previous_hash.encode("utf-8") + canonical
    return sha256(combined)


class MerkleTree:
    """
    Binary Merkle hash tree for audit trail integrity.

    Builds a tree from a list of leaf hashes, where each leaf
    corresponds to an evidence record. The root hash can be
    used to verify the integrity of the entire chain.

    Example (4 leaves):
            root
          /      \
        h01      h23
       /  \     /  \
      h0  h1   h2  h3
    """

    def __init__(self, leaves: list[str]):
        """
        Build a Merkle tree from leaf hashes.

        Args:
            leaves: List of hex-encoded SHA-256 hashes, one per evidence record
        """
        if not leaves:
            raise ValueError("MerkleTree requires at least one leaf")

        self.leaves = leaves[:]
        self.levels: list[list[str]] = [leaves[:]]
        self._build()

    def _build(self) -> None:
        """Build all levels of the Merkle tree bottom-up."""
        current_level = self.leaves[:]
        while len(current_level) > 1:
            next_level: list[str] = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                else:
                    # Duplicate last node for odd count
                    right = left
                combined = left + right
                next_level.append(sha256(combined.encode("utf-8")))
            self.levels.append(next_level)
            current_level = next_level

    @property
    def root(self) -> str:
        """Get the Merkle root hash."""
        return self.levels[-1][0] if self.levels else ""

    def get_proof(self, leaf_index: int) -> list[dict[str, str]]:
        """
        Generate a Merkle proof for a specific leaf.

        The proof is a list of sibling hashes and their positions
        (left/right) that can be used to verify the leaf is part
        of the tree without revealing other leaves.

        Args:
            leaf_index: Index of the leaf to generate proof for

        Returns:
            List of {'position': 'left'|'right', 'hash': str}
        """
        if leaf_index < 0 or leaf_index >= len(self.leaves):
            raise IndexError(f"Leaf index {leaf_index} out of range")

        proof: list[dict[str, str]] = []
        idx = leaf_index

        for level in self.levels[:-1]:  # Exclude root level
            sibling_idx = idx + 1 if idx % 2 == 0 else idx - 1
            if sibling_idx < len(level):
                position = "right" if idx % 2 == 0 else "left"
                proof.append({"position": position, "hash": level[sibling_idx]})
            idx //= 2

        return proof

    @staticmethod
    def verify_proof(
        leaf_hash: str,
        proof: list[dict[str, str]],
        root: str,
    ) -> bool:
        """
        Verify a Merkle proof for a leaf.

        Args:
            leaf_hash: The hash of the leaf to verify
            proof: The Merkle proof (list of sibling hashes)
            root: The expected Merkle root

        Returns:
            True if the proof is valid (leaf is in the tree)
        """
        current = leaf_hash
        for sibling in proof:
            if sibling["position"] == "left":
                combined = sibling["hash"] + current
            else:
                combined = current + sibling["hash"]
            current = sha256(combined.encode("utf-8"))
        return current == root


class AuditChain:
    """
    Chained audit trail with Merkle tree integrity verification.

    Each evidence record is hashed and linked to the previous record,
    forming a chain. Periodically, a Merkle tree is built from all
    leaf hashes to produce a single root that can be externally anchored.
    """

    def __init__(self):
        self.records: list[dict[str, Any]] = []
        self.hashes: list[str] = []
        self.previous_hash: str = "00" * 32  # Genesis hash

    def append(self, record: dict[str, Any]) -> str:
        """
        Append a record to the audit chain.

        Args:
            record: The evidence record to append

        Returns:
            The SHA-256 hash of this record (for Merkle tree building)
        """
        record_hash = hash_evidence(record, self.previous_hash)
        self.records.append(record)
        self.hashes.append(record_hash)
        self.previous_hash = record_hash
        return record_hash

    def build_merkle_tree(self) -> MerkleTree:
        """Build a Merkle tree from all record hashes."""
        return MerkleTree(self.hashes)

    @property
    def merkle_root(self) -> str:
        """Compute the Merkle root of all records."""
        if not self.hashes:
            return ""
        return self.build_merkle_tree().root
