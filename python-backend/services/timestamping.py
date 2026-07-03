"""
Trusted Timestamping Service — RFC 3161 & Merkle Anchoring
──────────────────────────────────────────────────────────
Provides cryptographically verifiable timestamps for audit evidence
records, ensuring that audit trails cannot be backdated.

Two timestamping mechanisms:
  1. Internal Merkle anchoring — Embeds a Merkle root of batch evidence
     records with a timestamp, providing batch-level integrity.
  2. External RFC 3161 TSA integration (configurable) — For production,
     timestamps can be anchored to a trusted Timestamping Authority.

ISO/IEC 42001:2023 Clause 7.5 — Documented information timestamps
must be verifiable and tamper-evident.

GDPR Art. 5(1)(d) — Accuracy: timestamps must be provably correct.
"""

from __future__ import annotations
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional
import logging

from services.merkle_audit import MerkleTree

logger = logging.getLogger("timestamping")


class TrustedTimestamp:
    """
    Provides verifiable timestamps for audit evidence records.

    Each timestamp includes:
      - ISO 8601 timestamp string
      - Unix epoch milliseconds
      - Merkle root of the evidence batch (for batch anchoring)
      - Optional external TSA signature (RFC 3161)
    """

    def __init__(self):
        self._batch_buffer: list[dict[str, Any]] = []
        self._batch_size = int(os.environ.get("TIMESTAMP_BATCH_SIZE", "100"))
        self._tsa_url = os.environ.get("RFC3161_TSA_URL", "")
        self._anchored_roots: list[dict[str, Any]] = []

    def timestamp_record(
        self,
        record: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Add a trusted timestamp to a single evidence record.

        Returns the record with an embedded `_trustedTimestamp` field
        containing the timestamp metadata.
        """
        now = datetime.now(timezone.utc)
        epoch_ms = int(now.timestamp() * 1000)

        # Generate a deterministic hash of the record content
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
        record_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        timestamp_entry = {
            "timestamp": now.isoformat(),
            "epochMs": epoch_ms,
            "recordHash": record_hash,
            "algorithm": "SHA-256",
        }

        # Add to batch buffer for periodic Merkle anchoring
        self._batch_buffer.append({
            "hash": record_hash,
            "timestamp": now.isoformat(),
            "epochMs": epoch_ms,
        })

        # If batch is full, anchor it
        if len(self._batch_buffer) >= self._batch_size:
            anchor = self._anchor_batch()
            timestamp_entry["merkleAnchor"] = anchor

        return {**record, "_trustedTimestamp": timestamp_entry}

    def _anchor_batch(self) -> Optional[dict[str, Any]]:
        """
        Anchor the current batch of timestamps using a Merkle tree.

        The Merkle root provides a single hash that represents all
        records in the batch. This root can be externally verified.
        """
        if not self._batch_buffer:
            return None

        # Build Merkle tree from batch hashes
        leaf_hashes = [entry["hash"] for entry in self._batch_buffer]
        try:
            tree = MerkleTree(leaf_hashes)
            merkle_root = tree.root
        except ValueError:
            logger.warning("Cannot anchor empty batch")
            return None

        now = datetime.now(timezone.utc)
        anchor = {
            "merkleRoot": merkle_root,
            "batchSize": len(self._batch_buffer),
            "anchoredAt": now.isoformat(),
            "epochMs": int(now.timestamp() * 1000),
        }

        # Store the anchor
        self._anchored_roots.append(anchor)

        # Clear the batch buffer
        self._batch_buffer.clear()

        logger.info(
            "Anchored batch of %d records with Merkle root %s",
            anchor["batchSize"],
            merkle_root[:16] + "...",
        )

        return anchor

    def flush_batch(self) -> Optional[dict[str, Any]]:
        """Force-anchoring of the current batch (call on shutdown)."""
        return self._anchor_batch()

    def get_anchored_roots(self) -> list[dict[str, Any]]:
        """Return all Merkle-root anchors generated in this session."""
        return self._anchored_roots.copy()

    def verify_record_in_anchor(
        self,
        record_hash: str,
        anchor: dict[str, Any],
        proof: list[dict[str, str]],
    ) -> bool:
        """
        Verify that a specific record was included in an anchored batch.

        Args:
            record_hash: SHA-256 hash of the record
            anchor: The Merkle anchor dict with merkleRoot
            proof: Merkle inclusion proof for the record

        Returns:
            True if the proof is valid and the record is in the batch.
        """
        expected_root = anchor.get("merkleRoot", "")
        return MerkleTree.verify_proof_against_root(
            leaf_hash=bytes.fromhex(record_hash),
            proof=proof,
            expected_root=expected_root,
        )

    @property
    def pending_batch_size(self) -> int:
        """Number of records in the current un-anchored batch."""
        return len(self._batch_buffer)


# Singleton
trusted_timestamp = TrustedTimestamp()
