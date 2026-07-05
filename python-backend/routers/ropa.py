# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
ROPA Generation Router — GDPR Art. 30
───────────────────────────────────────
Generates a Record of Processing Activities report, documenting all
7 mandatory fields required by GDPR Art. 30(1) for data controllers.

GDPR Art. 30(1) — Each controller and, where applicable, the
controller's representative, shall maintain a record of processing
activities under its responsibility.
GDPR Art. 5(2) — Accountability: the controller is responsible for,
and shall be able to demonstrate compliance with data protection
principles.
ISO/IEC 42001:2023 Clause 7.5 — Documented information shall be
retained as evidence of conformity.
"""

import uuid

from fastapi import APIRouter, HTTPException, Request
from models.schemas import GenerateROPARequest, ROPAReport
from services.auth import Scope, require_scope
from services.evidence_store import record_audit_evidence

router = APIRouter(prefix="/api/ropa", tags=["ROPA"])


@router.post("/generate", response_model=ROPAReport)
@require_scope(Scope.audit_write)
async def generate_ropa(request: GenerateROPARequest, request_obj: Request):
    """
    Generate a GDPR Art. 30 Record of Processing Activities.

    Builds a structured ROPA covering all 7 fields from Art. 30(1):
    (a) Controller identity and contact details
    (b) Processing purposes
    (c) Data subject and personal data categories
    (d) Recipient categories
    (e) Cross-border transfers with safeguards
    (f) Retention and erasure schedules
    (g) Technical and organisational security measures
    """
    has_special_categories = any(c.specialCategory for c in request.dataCategories)
    cross_border_transfer_assessed = (
        not request.crossBorderTransfer or len(request.transferSafeguards) > 0
    )
    all_retentions_defined = all(
        c.retentionPeriod.strip() for c in request.dataCategories
    ) if request.dataCategories else False

    compliant = (
        all_retentions_defined
        and cross_border_transfer_assessed
        and bool(request.controllerName)
        and bool(request.processingPurposes)
    )

    report = ROPAReport(
        modelId=request.modelId,
        controllerName=request.controllerName,
        controllerRepresentative=request.controllerRepresentative,
        dpoName=request.dpoName,
        controllerAddress=request.controllerAddress,
        controllerEmail=request.controllerEmail,
        jointControllers=request.jointControllers,
        processingPurposes=request.processingPurposes,
        dataSubjectCategories=request.dataSubjectCategories,
        dataCategories=request.dataCategories,
        recipientCategories=request.recipientCategories,
        crossBorderTransfer=request.crossBorderTransfer,
        thirdCountries=request.thirdCountries,
        transferSafeguards=request.transferSafeguards,
        retentionScheduleDescription=request.retentionScheduleDescription or
            "Retention periods are defined per data category above.",
        securityMeasures=request.securityMeasures,
        ropaId=str(uuid.uuid4()),
        compliant=compliant,
    )

    await record_audit_evidence(
        model_id=request.modelId,
        audit_phase="ropa_generation",
        payload=report.model_dump(),
    )

    return report
