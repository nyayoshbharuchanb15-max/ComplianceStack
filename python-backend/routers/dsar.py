# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
DSAR Router — GDPR Art. 15–17 Data Subject Rights
───────────────────────────────────────────────────
Implements:
  - Art. 15: Right of access — retrieve all records for a data subject
  - Art. 17: Right to erasure — cascade deletion across all data stores
             with Merkle proof audit and W3C VC erasure certificate

GDPR Art. 15 — The data subject shall have the right to obtain
confirmation as to whether personal data concerning him or her
are being processed.
GDPR Art. 17 — The data subject shall have the right to obtain
the erasure of personal data without undue delay.
ISO/IEC 42001:2023 Clause 7.5 — Erasure is documented as
evidence of conformity with data protection obligations.
"""

import uuid

from fastapi import APIRouter, HTTPException, Request
from models.schemas import DSARRequest, DSARResponse, ErasureStoreStatus
from services.auth import Scope, require_scope
from services.evidence_store import record_audit_evidence
from services.erasure_chain import ErasureChain, access_data_subject_records

router = APIRouter(prefix="/api/dsar", tags=["DSAR"])


@router.post("/access", response_model=dict)
@require_scope(Scope.audit_read)
async def data_subject_access_request(
    request: DSARRequest,
    request_obj: Request,
):
    """
    Fulfill a GDPR Art. 15 Data Subject Access Request.

    Retrieves all records relating to the data subject across
    PostgreSQL, Neo4j, and Redis stores. Returns a consolidated
    access report.
    """
    try:
        request_id = str(uuid.uuid4())
        records = await access_data_subject_records(
            model_id=request.modelId,
            data_subject_id=request.dataSubjectId,
            dsar_request_id=request_id,
        )

        await record_audit_evidence(
            model_id=request.modelId,
            audit_phase="dsar_access_request",
            payload=records,
        )

        return records

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"DSAR access request failed: {str(e)}",
        )


@router.post("/erasure", response_model=DSARResponse)
@require_scope(Scope.audit_write)
async def right_to_erasure(
    request: DSARRequest,
    request_obj: Request,
):
    """
    Fulfill a GDPR Art. 17 Right to Erasure request.

    Cascades deletion across all registered data stores:
      1. PostgreSQL — Clears evidence, certificates, alerts, PII logs
      2. Neo4j      — Removes model nodes and provenance edges
      3. Redis      — Deletes cached keys and stream entries

    Each erasure step is recorded in a Merkle audit chain.
    A W3C Verifiable Credential is issued as the erasure certificate.

    Returns per-store erasure status, Merkle proof, and the VC.
    """
    try:
        request_id = str(uuid.uuid4())
        chain = ErasureChain(
            model_id=request.modelId,
            data_subject_id=request.dataSubjectId,
            request_id=request_id,
        )

        store_statuses, audit_chain = await chain.run()

        all_completed = all(
            s.status == "completed" or s.status == "skipped"
            for s in store_statuses
        )

        erasure_proof = chain.build_erasure_proof() if audit_chain and audit_chain.hashes else None

        erasure_vc = chain.build_erasure_certificate() if audit_chain and audit_chain.hashes else None

        response = DSARResponse(
            modelId=request.modelId,
            dataSubjectId=request.dataSubjectId,
            requestType="erasure",
            requestId=request_id,
            compliant=all_completed,
            stores=store_statuses,
            erasureProof=erasure_proof,
            erasureCertificate=erasure_vc,
        )

        await record_audit_evidence(
            model_id=request.modelId,
            audit_phase="dsar_erasure",
            payload=response.model_dump(),
        )

        return response

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Right to erasure failed: {str(e)}",
        )
