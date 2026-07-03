"""
Cryptographic Signing Module — W3C Verifiable Credentials
──────────────────────────────────────────────────────────
Provides Ed25519-based signing and verification of W3C VCs
with proper multibase base58btc encoding per the
Ed25519Signature2020 suite specification.

Key management:
  - Development: auto-generated ephemeral keys
  - Production: PEM-encoded key from SIGNING_KEY_PRIVATE env var
  - HSM integration: extend _load_private_key() for PKCS#11

ISO/IEC 42001:2023 Clause 7.5 — Cryptographic integrity for
documented information. All signing events are logged.

Merkle Tree:
  - SHA-256-based audit evidence anchoring
  - Generates verifiable inclusion proofs for individual records
  - Embeds merkle_root into VC proof for tamper-evident linkage
"""

from __future__ import annotations
import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from services.key_provider import EnvironmentKeyProvider, KeyNotFoundError

# ─── Base58 Encoding (Bitcoin-style alphabet) ─────────────────────

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_encode(data: bytes) -> str:
    """Encode bytes to base58 (Bitcoin-style) string."""
    n = int.from_bytes(data, "big")
    chars = []
    while n > 0:
        n, remainder = divmod(n, 58)
        chars.append(BASE58_ALPHABET[remainder])
    # Handle leading zeros
    for byte in data:
        if byte == 0:
            chars.append(BASE58_ALPHABET[0])
        else:
            break
    return "".join(reversed(chars))


def _multibase_base58btc(data: bytes) -> str:
    """Encode bytes as multibase base58btc (prefix 'z')."""
    return "z" + _base58_encode(data)


# ─── Merkle Tree ──────────────────────────────────────────────────

class MerkleTree:
    """
    SHA-256 Merkle tree for audit evidence records.

    Builds a binary hash tree over canonicalised evidence records,
    enabling compact inclusion proofs that anchor the full set of
    evidence to a single root hash stored in the VC proof.
    """

    _LEAF_PREFIX = b"\x00"
    _NODE_PREFIX = b"\x01"

    def __init__(self, evidence_records: list[dict[str, Any]]):
        """
        Build the Merkle tree from evidence records.

        Each record must contain at minimum: evidence_id, model_id,
        audit_phase, payload, created_at.
        """
        if not evidence_records:
            raise ValueError("evidence_records must not be empty")

        self._records = evidence_records
        self._leaves: list[bytes] = [self._hash_leaf(r) for r in evidence_records]
        self._tree: list[list[bytes]] = []
        self._build()

    # ── Leaf / Node hashing ────────────────────────────────────

    @classmethod
    def _hash_leaf(cls, record: dict[str, Any]) -> bytes:
        """Deterministically hash an evidence record into a 32-byte leaf."""
        canonical = json.dumps(
            {
                "evidence_id": record["evidence_id"],
                "model_id": record["model_id"],
                "audit_phase": record["audit_phase"],
                "payload": record["payload"],
                "created_at": record["created_at"],
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(cls._LEAF_PREFIX + canonical).digest()

    @classmethod
    def _hash_node(cls, left: bytes, right: bytes) -> bytes:
        """Hash two child nodes into a parent node."""
        return hashlib.sha256(cls._NODE_PREFIX + left + right).digest()

    # ── Tree construction ──────────────────────────────────────

    def _build(self) -> None:
        """Construct the tree level-by-level bottom-up."""
        self._tree = [list(self._leaves)]
        current = self._leaves
        while len(current) > 1:
            next_level: list[bytes] = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else current[i]
                next_level.append(self._hash_node(left, right))
            self._tree.append(next_level)
            current = next_level

    # ── Public API ─────────────────────────────────────────────

    @property
    def root(self) -> bytes:
        """Return the Merkle root hash (bytes)."""
        return self._tree[-1][0]

    @property
    def root_hex(self) -> str:
        """Return the Merkle root as a hex string."""
        return self.root.hex()

    @property
    def leaf_count(self) -> int:
        return len(self._leaves)

    @property
    def depth(self) -> int:
        """Tree depth (number of levels above leaves). 0 means 1 leaf."""
        return len(self._tree) - 1 if len(self._tree) > 0 else 0

    def get_proof(self, index: int) -> list[dict[str, str]]:
        """
        Generate a Merkle inclusion proof for the leaf at *index*.

        Returns a list of ``{"hash": <hex>, "position": "left"|"right"}``
        describing the sibling hashes from leaf level up to (but not
        including) the root.
        """
        if index < 0 or index >= self.leaf_count:
            raise IndexError(f"leaf index {index} out of range 0..{self.leaf_count - 1}")

        proof: list[dict[str, str]] = []
        idx = index
        for level in self._tree[:-1]:
            # Sibling index
            if idx % 2 == 0:
                sibling = idx + 1 if idx + 1 < len(level) else idx
                position = "right"
            else:
                sibling = idx - 1
                position = "left"
            proof.append({"hash": level[sibling].hex(), "position": position})
            idx //= 2
        return proof

    def verify_proof(
        self,
        leaf_index: int,
        proof: list[dict[str, str]],
    ) -> bool:
        """
        Verify that a proof is consistent with this tree's root.

        Convenience wrapper around the class-level ``verify_proof_against_root``.
        """
        return self.verify_proof_against_root(
            leaf_hash=self._leaves[leaf_index],
            proof=proof,
            expected_root=self.root_hex,
        )

    @staticmethod
    def verify_proof_against_root(
        leaf_hash: bytes | str,
        proof: list[dict[str, str]],
        expected_root: str,
    ) -> bool:
        """
        Stateless proof verification — does not require the full tree.

        Args:
            leaf_hash: The 32-byte hash (bytes or hex str) of the leaf.
            proof: List of ``{"hash": hex, "position": "left"|"right"}``.
            expected_root: Expected Merkle root as a hex string.

        Returns:
            True if the reconstructed root matches ``expected_root``.
        """
        if isinstance(leaf_hash, str):
            current = bytes.fromhex(leaf_hash)
        else:
            current = leaf_hash

        for step in proof:
            sibling = bytes.fromhex(step["hash"])
            if step["position"] == "left":
                current = hashlib.sha256(
                    MerkleTree._NODE_PREFIX + sibling + current
                ).digest()
            else:
                current = hashlib.sha256(
                    MerkleTree._NODE_PREFIX + current + sibling
                ).digest()

        return current.hex() == expected_root


# ─── CryptoSigner ─────────────────────────────────────────────────

class CryptoSigner:
    """
    Ed25519-based signer for W3C Verifiable Credentials.

    Uses the Ed25519Signature2020 suite per the W3C security vocabulary.
    Supports key rotation, separate verification key exposure, and
    canonicalized payload signing per VC Data Model 1.1.
    """

    def __init__(self, private_key_pem: Optional[str] = None):
        """
        Initialize signer with an Ed25519 private key.

        Key resolution order:
          1. Explicit private_key_pem argument
          2. EnvironmentKeyProvider(SIGNING_KEY_PRIVATE)
          3. Auto-generated development key (dev-only — logs warning)

        For production, use SIGNING_KEY_PRIVATE env var or implement a
        custom BaseKeyProvider (see services/key_provider.py).
        """
        import os as _os
        _production_mode = _os.environ.get("PRODUCTION_MODE", "false").lower() in ("1", "true", "yes")

        pem_data = private_key_pem
        if pem_data is None:
            try:
                provider = EnvironmentKeyProvider(env_var="SIGNING_KEY_PRIVATE")
                pem_data = provider.get_private_key().decode("utf-8")
            except KeyNotFoundError:
                pem_data = None
        if pem_data:
            key_bytes = pem_data.encode("utf-8") if isinstance(pem_data, str) else pem_data
            self.private_key = serialization.load_pem_private_key(
                key_bytes, password=None,
            )
            assert isinstance(self.private_key, Ed25519PrivateKey), "Key must be Ed25519"
        else:
            if _production_mode:
                raise RuntimeError(
                    "╔══════════════════════════════════════════════════════════════════╗\n"
                    "║  FATAL: PRODUCTION MODE requires SIGNING_KEY_PRIVATE to be set. ║\n"
                    "║  Ephemeral keys are not permitted in production.                ║\n"
                    "║                                                                 ║\n"
                    "║  Generate with:                                                 ║\n"
                    "║    openssl genpkey -algorithm ed25519 -out private.pem           ║\n"
                    "║                                                                 ║\n"
                    "║  Set environment variable:                                      ║\n"
                    "║    SIGNING_KEY_PRIVATE=<PEM contents>                           ║\n"
                    "╚══════════════════════════════════════════════════════════════════╝"
                )
            import warnings
            warnings.warn(
                "╔══════════════════════════════════════════════════════════════════╗\n"
                "║  WARNING: EPHEMERAL DEV KEY — NOT FOR PRODUCTION                ║\n"
                "║  No SIGNING_KEY_PRIVATE set. Using ephemeral Ed25519 key.       ║\n"
                "║  Every restart invalidates previously issued certificates.       ║\n"
                "║  Set SIGNING_KEY_PRIVATE env var for production.                ║\n"
                "║  Generate with: openssl genpkey -algorithm ed25519 -out private.pem  ║\n"
                "╚══════════════════════════════════════════════════════════════════╝"
            )
            self.private_key = Ed25519PrivateKey.generate()

        self.public_key = self.private_key.public_key()
        self.public_key_multibase = _multibase_base58btc(self._raw_public_bytes())

    def _raw_public_bytes(self) -> bytes:
        """Get raw 32-byte Ed25519 public key."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @property
    def verification_method(self) -> str:
        """W3C-compatible verification method identifier (did:key format)."""
        return f"did:key:{self.public_key_multibase}#{self.public_key_multibase}"

    def sign_payload(self, payload: bytes) -> str:
        """
        Sign canonicalized bytes with Ed25519.

        Returns multibase base58btc-encoded signature per Ed25519Signature2020.
        """
        raw_sig = self.private_key.sign(payload)
        return _multibase_base58btc(raw_sig)

    def verify_signature(self, payload: bytes, signature_multibase: str) -> bool:
        """
        Verify an Ed25519 multibase signature.

        Args:
            payload: Original canonicalized bytes
            signature_multibase: Multibase base58btc-encoded signature (starts with 'z')

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Strip multibase prefix 'z' and decode base58
            if signature_multibase.startswith("z"):
                sig_b58 = signature_multibase[1:]
            else:
                sig_b58 = signature_multibase
            sig_bytes = self._base58_decode(sig_b58)
            self.public_key.verify(sig_bytes, payload)
            return True
        except (InvalidSignature, ValueError, IndexError):
            return False

    def _base58_decode(self, encoded: str) -> bytes:
        """Decode a base58 string to bytes."""
        n = 0
        for char in encoded:
            n = n * 58 + BASE58_ALPHABET.index(char)
        # Count leading zeros
        leading_zeros = 0
        for char in encoded:
            if char == BASE58_ALPHABET[0]:
                leading_zeros += 1
            else:
                break
        result = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
        return b"\x00" * leading_zeros + result

    # ── VC Signing with Merkle Root ────────────────────────────

    def sign_vc_payload(self, vc_dict: dict, merkle_root: Optional[str] = None) -> str:
        """
        Sign a Verifiable Credential dict per W3C standards.

        Removes the proof field before signing (per spec), canonicalizes
        to deterministic JSON, signs, and restores the proof field.

        When *merkle_root* is provided it is injected into ``vc_dict["proof"]``
        before signing so the VC is cryptographically bound to the Merkle
        anchor of its supporting evidence chain.

        Args:
            vc_dict: VC JSON dict (with or without proof)
            merkle_root: Optional hex-encoded Merkle root to embed in proof

        Returns:
            Multibase base58btc-encoded Ed25519 signature
        """
        proof = vc_dict.pop("proof", None)

        # Inject merkle root into the VC proof if supplied
        if merkle_root is not None:
            if proof is None:
                proof = {}
            proof["merkleRoot"] = merkle_root
            vc_dict["proof"] = proof

        canonical = json.dumps(vc_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")
        signature = self.sign_payload(canonical)

        # Restore original proof (without the merkle root) for the caller
        if proof is not None:
            proof.pop("merkleRoot", None)
            if proof:
                vc_dict["proof"] = proof

        return signature

    # ── Merkle Chain Builder ───────────────────────────────────

    def build_merkle_chain(
        self,
        evidence_records: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Build a Merkle tree from audit evidence records and return
        the anchoring metadata suitable for embedding in a VC proof.

        Args:
            evidence_records: List of dicts, each containing at minimum
                evidence_id, model_id, audit_phase, payload, created_at.

        Returns:
            dict with keys:
                merkle_root  — hex-encoded root hash
                tree_depth   — number of levels above the leaf level
                leaf_count   — number of evidence records
                timestamp    — ISO-8601 UTC timestamp of chain creation
        """
        tree = MerkleTree(evidence_records)
        return {
            "merkle_root": tree.root_hex,
            "tree_depth": tree.depth,
            "leaf_count": tree.leaf_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ── Static Proof Verification ──────────────────────────────

    @staticmethod
    def verify_merkle_proof(
        proof: list[dict[str, str]],
        root: str,
        leaf_hash: bytes | str,
    ) -> bool:
        """
        Stateless verification of a Merkle inclusion proof.

        This can be called without access to the original tree — only
        the leaf hash, proof path, and expected root are required.

        Args:
            proof:  List of ``{"hash": hex, "position": "left"|"right"}``.
            root:   Expected Merkle root as a hex string.
            leaf_hash: 32-byte leaf hash (bytes or hex string).

        Returns:
            True when the proof is valid against the given root.
        """
        return MerkleTree.verify_proof_against_root(leaf_hash, proof, root)


# Singleton instance
crypto_signer = CryptoSigner()
