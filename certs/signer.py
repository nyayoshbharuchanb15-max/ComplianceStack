# SPDX-License-Identifier: Apache-2.0
"""Ed25519 signer for W3C VC 2.0 DataIntegrityProof (cryptosuite eddsa-jcs-2022).

Signing procedure (verifiable offline by any independent party):
  proofOptions = proof object without proofValue
  toSign = sha256(JCS(proofOptions)) || sha256(JCS(document without proof))
  proofValue = 'z' + base58btc(Ed25519.sign(toSign))
verificationMethod = did:key derived from the public key (multicodec 0xed01).
Keys are generated inside the deployment boundary and never exported.
"""
from __future__ import annotations
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def b58encode(data: bytes) -> str:
    num = int.from_bytes(data, "big")
    encoded = ""
    while num > 0:
        num, rem = divmod(num, 58)
        encoded = B58_ALPHABET[rem] + encoded
    pad = 0
    for byte in data:
        if byte == 0:
            pad += 1
        else:
            break
    return "1" * pad + encoded


def b58decode(s: str) -> bytes:
    num = 0
    for char in s:
        num = num * 58 + B58_ALPHABET.index(char)
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


class Ed25519Signer:
    """Holds the deployment signing key; embedded or wrapped by certs/service.py."""

    def __init__(self, key_file: Optional[str] = None) -> None:
        self.key_file = key_file or os.environ.get("CERT_KEY_FILE", "/app/.governance/ed25519.seed")
        self._private_key = self._load_or_generate()
        self._public_key: Ed25519PublicKey = self._private_key.public_key()

    def _load_or_generate(self) -> Ed25519PrivateKey:
        path = Path(self.key_file)
        if path.exists():
            seed = bytes.fromhex(path.read_text().strip())
            return Ed25519PrivateKey.from_private_bytes(seed)
        key = Ed25519PrivateKey.generate()
        from cryptography.hazmat.primitives import serialization
        seed = key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(seed.hex())
        path.chmod(0o600)
        return key

    @property
    def public_key_multibase(self) -> str:
        from cryptography.hazmat.primitives import serialization
        raw = self._public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return "z" + b58encode(b"\xed\x01" + raw)

    @property
    def did(self) -> str:
        return f"did:key:{self.public_key_multibase}"

    @property
    def verification_method(self) -> str:
        return f"{self.did}#{self.public_key_multibase}"

    def _signing_input(self, document: dict, proof_options: dict) -> bytes:
        doc = {k: v for k, v in document.items() if k != "proof"}
        return (_sha256(canonical_json(proof_options).encode("utf-8"))
                + _sha256(canonical_json(doc).encode("utf-8")))

    def create_proof(self, document: dict, created: Optional[str] = None) -> dict:
        proof_options = {
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "created": created or datetime.now(timezone.utc).isoformat(),
            "verificationMethod": self.verification_method,
            "proofPurpose": "assertionMethod",
        }
        signature = self._private_key.sign(self._signing_input(document, proof_options))
        return {**proof_options, "proofValue": "z" + b58encode(signature)}

    def verify_proof(self, document: dict) -> bool:
        proof = document.get("proof")
        if not proof or proof.get("cryptosuite") != "eddsa-jcs-2022":
            return False
        # This is the LOCAL signer verifying its own credential — pin to self.
        return verify_with_method(
            document, proof.get("verificationMethod", ""), trusted_dids=[self.did])


def verify_with_method(document: dict, verification_method: str,
                       trusted_dids: Optional[list[str]] = None) -> bool:
    """Verify a VC 2.0 credential's DataIntegrityProof.

    Trust model: only accept `verificationMethod`s whose base did:key appears
    in the ``trusted_dids`` allow-list (defaults to the local signer's DID).
    Without this pin, ANY holder of an Ed25519 key can forge a syntactically
    valid credential — cf. SEC-002 in the 2026-02 security audit.
    """
    proof = document.get("proof") or {}
    try:
        base_did = verification_method.split("#")[0]
        allowed = list(trusted_dids or [])
        # Always trust the locally-embedded signer.
        allowed.append(get_signer().did)
        if base_did not in allowed:
            return False
        multibase = verification_method.split("#")[-1]
        if not multibase.startswith("z"):
            return False
        decoded = b58decode(multibase[1:])
        if decoded[:2] != b"\xed\x01":
            return False
        public_key = Ed25519PublicKey.from_public_bytes(decoded[2:])
        proof_options = {k: v for k, v in proof.items() if k != "proofValue"}
        doc = {k: v for k, v in document.items() if k != "proof"}
        signing_input = (_sha256(canonical_json(proof_options).encode("utf-8"))
                         + _sha256(canonical_json(doc).encode("utf-8")))
        proof_value = proof.get("proofValue", "")
        if not proof_value.startswith("z"):
            return False
        public_key.verify(b58decode(proof_value[1:]), signing_input)
        return True
    except Exception:
        return False


_signer: Optional[Ed25519Signer] = None


def get_signer() -> Ed25519Signer:
    global _signer
    if _signer is None:
        _signer = Ed25519Signer()
    return _signer
