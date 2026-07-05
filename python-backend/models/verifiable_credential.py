# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
W3C Verifiable Credential Data Model 1.1
─────────────────────────────────────────
Production-grade VC-JSON implementation for AI audit certificates.

Compliance mappings:
  - W3C VC Data Model 1.1 (https://www.w3.org/TR/vc-data-model/)
  - Ed25519Signature2020 (https://w3id.org/security/suites/ed25519-2020/v1)
  - ISO/IEC 42001:2023 Clause 7.5 — Documented Information retention

All audit certificates are self-contained, machine-readable, and
cryptographically verifiable without external dependencies.
"""

from __future__ import annotations
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional
from pydantic import BaseModel, Field


class VCProof(BaseModel):
    """Cryptographic proof attached to a Verifiable Credential."""
    type: str = "Ed25519Signature2020"
    created: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    verificationMethod: str
    proofPurpose: str = "assertionMethod"
    proofValue: str = ""


class VerifiableCredential(BaseModel):
    """
    W3C Verifiable Credential — AI Audit Certificate.

    JSON-LD compatible structure for decentralized verification.
    Each VC contains:
      - Context: JSON-LD contexts defining the data model
      - CredentialSubject: The audit results being attested
      - Proof: Cryptographic signature from the issuing authority
    """
    context: list[str] = Field(
        default_factory=lambda: [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1",
            "https://w3id.org/security/suites/ed25519-2020/v1",
        ],
        alias="@context",
    )
    id: str = Field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}")
    type: list[str] = Field(
        default_factory=lambda: ["VerifiableCredential", "AIAuditCertificate"]
    )
    issuer: dict[str, str]
    issuanceDate: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expirationDate: str = Field(
        default_factory=lambda: (
            datetime.now(timezone.utc) + timedelta(days=365)
        ).isoformat()
    )
    credentialSubject: dict[str, Any]
    proof: VCProof

    def to_jsonld(self) -> dict[str, Any]:
        """Serialize to JSON-LD format with @context at root."""
        data = self.model_dump(by_alias=True)
        return data

    def to_signing_payload(self) -> bytes:
        """
        Canonicalized payload for cryptographic signing.
        Uses deterministic JSON serialization per RFC 8785 guidelines.
        """
        payload = {
            "@context": self.context,
            "id": self.id,
            "type": self.type,
            "issuer": self.issuer,
            "issuanceDate": self.issuanceDate,
            "expirationDate": self.expirationDate,
            "credentialSubject": self.credentialSubject,
        }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


class VCIssuer:
    """
    Verifiable Credential Issuer.

    In production, the signing key should be loaded from a hardware
    security module (HSM) or key management service. The key material
    is NEVER logged or exposed in error messages.
    """

    def __init__(self, issuer_id: str, issuer_name: str):
        self.issuer_id = issuer_id
        self.issuer_name = issuer_name

    def issue(
        self,
        subject_data: dict[str, Any],
        valid_days: int = 365,
        proof_value: str = "",
        verification_method: str = "",
    ) -> VerifiableCredential:
        """Issue a new Verifiable Credential."""
        vc = VerifiableCredential(
            issuer={"id": self.issuer_id, "name": self.issuer_name},
            expirationDate=(
                datetime.now(timezone.utc) + timedelta(days=valid_days)
            ).isoformat(),
            credentialSubject=subject_data,
            proof=VCProof(verificationMethod=verification_method or self.issuer_id),
        )
        vc.proof.proofValue = proof_value
        vc.proof.created = datetime.now(timezone.utc).isoformat()
        return vc
