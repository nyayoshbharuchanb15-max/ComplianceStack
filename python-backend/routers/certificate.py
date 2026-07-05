# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Audit Certificate Router — W3C Verifiable Credential Issuance
───────────────────────────────────────────────────────────────
Issues cryptographically signed W3C Verifiable Credentials (VC-JSON)
for completed AI audits. Certificates are:

  1. Machine-readable (JSON-LD)
  2. Cryptographically signed (Ed25519Signature2020)
  3. Stored in PostgreSQL evidence store (ISO 42001 Clause 7.5)
  4. Self-verifiable without external dependencies (on-premise)

ISO/IEC 42001:2023 Clause 7.5 — Documented information must be
retained, protected, and retrievable.
W3C VC Data Model 1.1 — Standard for decentralized verifiable data.
"""

import json
import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Request
from models.schemas import GenerateCertificateRequest, AuditCertificate, VerifiableCredential
from models.verifiable_credential import VCIssuer, VerifiableCredential as VCModel
from services.auth import Scope, require_scope
from services.crypto_signer import crypto_signer
from services.evidence_store import record_audit_evidence, record_certificate, log_audit_event

router = APIRouter(prefix="/api/certificate", tags=["Certificate"])


@router.post("/generate", response_model=AuditCertificate)
@require_scope(Scope.audit_write)
async def generate_audit_certificate(request: GenerateCertificateRequest, request_obj: Request):
    """
    Generate a cryptographically signed W3C Verifiable Credential.

    The VC includes:
      - Issuer information (auditing authority)
      - Model audit results (score, tier, compliance)
      - Ed25519 cryptographic proof (signature)

    Steps:
      1. Build the VC credential subject from audit results
      2. Create the VCIssuer instance
      3. Generate the Ed25519 signature over the canonicalized payload
      4. Attach the proof to the VC
      5. Store in PostgreSQL evidence store
      6. Return the complete AuditCertificate with evidence ID
    """
    # ── Step 1: Build issuer ─────────────────────────────────────
    issuer_id = f"did:web:governance.internal:issuers:{uuid.uuid4().hex[:8]}"
    issuer = VCIssuer(issuer_id=issuer_id, issuer_name=request.issuerName)

    # ── Step 2: Build credential subject ─────────────────────────
    subject_data = {
        "id": f"did:model:{request.modelId}",
        "modelId": request.modelId,
        "auditScore": request.weightedScore,
        "tier": request.tier,
        "compliant": request.compliant,
        "auditDate": datetime.now(timezone.utc).isoformat(),
        "auditFramework": "AI Governance MCP Server v1.0",
        "regulatoryReferences": [
            "EU AI Act (Regulation 2024/1689)",
            "NIST AI RMF (NIST AI 100-1)",
            "ISO/IEC 42001:2023",
            "GDPR (Regulation 2016/679)",
            "DPDP Act 2023",
        ],
    }

    # ── Step 3: Issue the VC (without proof yet) ────────────────
    vc = issuer.issue(
        subject_data=subject_data,
        valid_days=request.validDays,
    )

    # ── Step 4: Generate cryptographic signature ─────────────────
    try:
        # Canonicalize and sign the payload per W3C standards
        canonical_payload = vc.to_signing_payload()
        signature = crypto_signer.sign_payload(canonical_payload)
        verification_method = crypto_signer.verification_method
    except Exception as crypto_err:
        await log_audit_event(
            model_id=request.modelId,
            phase="certificate_generation",
            action="certificate_generated",
            outcome="failure",
            details={"error": f"Crypto operation failed: {str(crypto_err)}"},
        )
        raise HTTPException(
            status_code=500,
            detail=f"Certificate signing failed: {str(crypto_err)}",
        )

    # ── Step 5: Attach proof ─────────────────────────────────────
    vc.proof.proofValue = signature
    vc.proof.verificationMethod = verification_method
    vc.proof.created = datetime.now(timezone.utc).isoformat()

    # ── Step 6: Serialize to VC-JSON ─────────────────────────────
    vc_json = vc.to_jsonld()

    # ── Step 7: Store in PostgreSQL evidence store ───────────────
    evidence_id = await record_audit_evidence(
        model_id=request.modelId,
        audit_phase="certificate_generation",
        payload={
            "vc": vc_json,
            "verificationMethod": verification_method,
            "issuer": request.issuerName,
            "score": request.weightedScore,
        },
        evidence_type="w3c_verifiable_credential",
    )

    # Also store in certificates table for dedicated VC access
    await record_certificate(
        model_id=request.modelId,
        vc_payload=vc_json,
        evidence_id=evidence_id,
    )

    # Log audit trail
    await log_audit_event(
        model_id=request.modelId,
        phase="certificate_generation",
        action="certificate_generated",
        outcome="success",
        details={"evidence_id": evidence_id, "score": request.weightedScore},
    )

    # ── Step 8: Build response ──────────────────────────────────
    # Convert the internal VC model to the response schema
    response_vc = VerifiableCredential(
        id=vc.id,
        issuer=vc.issuer,
        issuanceDate=vc.issuanceDate,
        expirationDate=vc.expirationDate,
        credentialSubject=vc.credentialSubject,
        proof={
            "type": vc.proof.type,
            "created": vc.proof.created,
            "verificationMethod": vc.proof.verificationMethod,
            "proofPurpose": vc.proof.proofPurpose,
            "proofValue": vc.proof.proofValue,
        },
    )

    return AuditCertificate(
        modelId=request.modelId,
        vc=response_vc,
        storedInPostgres=True,
        evidenceId=evidence_id,
    )
