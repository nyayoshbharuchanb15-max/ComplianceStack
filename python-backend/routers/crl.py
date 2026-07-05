# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Certificate Revocation Router — CRL & OCSP Endpoints
──────────────────────────────────────────────────────
Provides certificate revocation and status checking per X.509 standards:

  - CRL (Certificate Revocation List): Bulk list of all revoked certificates
  - OCSP-style check: Individual certificate status query
  - Revoke: Mark a certificate as revoked with reason

ISO/IEC 42001:2023 Clause 7.5 — Documented information integrity
requires verifiable certificate lifecycle management.

W3C VC Data Model 1.1 — Verifiable Credentials may be revoked by
the issuer. Verifiers must be able to check revocation status.
"""

import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from typing import Optional

from services.auth import Scope, require_scope
from services.evidence_store import record_audit_evidence
from db.postgres import pg_client

router = APIRouter(prefix="/api/certificate", tags=["Certificate Revocation"])


# ─── Request/Response Schemas ─────────────────────────────────────

class RevokeCertificateRequest(BaseModel):
    certificateId: str = Field(..., description="UUID of the certificate to revoke")
    reason: str = Field(
        default="unspecified",
        description="Revocation reason: unspecified, key_compromise, affiliation_changed, "
                    "superseded, cessation_of_operation, privilege_withdrawn",
    )


class RevocationStatusResponse(BaseModel):
    certificateId: str
    revoked: bool
    revokedAt: Optional[str] = None
    revocationReason: Optional[str] = None
    expiresAt: Optional[str] = None
    valid: bool  # True if not revoked AND not expired


class CRLResponse(BaseModel):
    revokedCertificates: list[dict]
    totalRevoked: int
    generatedAt: str
    issuer: str = "AI Governance MCP Server — Certificate Authority"
    crlNumber: int = 1


# ─── Endpoints ────────────────────────────────────────────────────

@router.post("/revoke", response_model=dict)
@require_scope(Scope.audit_write)
async def revoke_certificate(request: RevokeCertificateRequest, request_obj: Request):
    """
    Revoke a W3C Verifiable Credential certificate.

    Marks the certificate as revoked in the database. The revocation
    is immediately effective and reflected in CRL and status queries.
    """
    success = await pg_client.revoke_certificate(
        certificate_id=request.certificateId,
        reason=request.reason,
    )
    if not success:
        raise HTTPException(
            status_code=404,
            detail=f"Certificate {request.certificateId} not found or already revoked",
        )

    await record_audit_evidence(
        model_id="system",
        audit_phase="certificate_revocation",
        payload={
            "certificateId": request.certificateId,
            "reason": request.reason,
            "revokedBy": getattr(request_obj.state, "user", "unknown"),
        },
        evidence_type="certificate_revocation",
    )

    return {
        "certificateId": request.certificateId,
        "revoked": True,
        "reason": request.reason,
        "revokedAt": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/status/{certificate_id}", response_model=RevocationStatusResponse)
@require_scope(Scope.audit_read)
async def check_certificate_status(certificate_id: str, request_obj: Request):
    """
    Check the revocation and expiration status of a certificate (OCSP-style).

    Returns whether the certificate is revoked, expired, or still valid.
    Verifiers should call this endpoint before trusting a VC.
    """
    status = await pg_client.check_certificate_revocation(certificate_id)

    is_expired = False
    if status.get("expires_at"):
        try:
            expires = datetime.fromisoformat(status["expires_at"])
            is_expired = datetime.now(timezone.utc) > expires
        except (ValueError, TypeError):
            pass

    return RevocationStatusResponse(
        certificateId=certificate_id,
        revoked=status["revoked"],
        revokedAt=status["revoked_at"],
        revocationReason=status["revocation_reason"],
        expiresAt=status.get("expires_at"),
        valid=not status["revoked"] and not is_expired,
    )


@router.get("/crl", response_model=CRLResponse)
@require_scope(Scope.audit_read)
async def get_certificate_revocation_list(request_obj: Request):
    """
    Retrieve the Certificate Revocation List (CRL).

    Returns all revoked certificates with their revocation details.
    External verifiers can fetch this list to check certificate status
    without querying individual certificates.
    """
    revoked = await pg_client.get_revoked_certificates()

    return CRLResponse(
        revokedCertificates=[
            {
                "certificateId": str(r["certificate_id"]),
                "modelId": r["model_id"],
                "revokedAt": r["revoked_at"].isoformat() if r["revoked_at"] else None,
                "revocationReason": r["revocation_reason"],
                "expiresAt": r["expires_at"].isoformat() if r["expires_at"] else None,
            }
            for r in revoked
        ],
        totalRevoked=len(revoked),
        generatedAt=datetime.now(timezone.utc).isoformat(),
    )
