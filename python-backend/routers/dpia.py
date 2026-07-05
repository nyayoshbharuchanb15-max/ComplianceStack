# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
DPIA Generation Router — GDPR Art. 35
───────────────────────────────────────
Generates a Data Protection Impact Assessment report, evaluating
the necessity, proportionality, and risk of AI data processing.

GDPR Art. 35(1) — A DPIA is required when processing is likely to
result in high risk to natural persons' rights and freedoms.
GDPR Art. 35(7) — Mandatory content: systematic description,
necessity assessment, risk analysis, and mitigation measures.
GDPR Art. 44–49 — Cross-border transfer mechanisms must be assessed
with adequacy decisions or Standard Contractual Clauses (SCCs).
ISO/IEC 42001:2023 Clause 6.2 — Data protection impact assessment.
"""

from fastapi import APIRouter, HTTPException, Request
from models.schemas import GenerateDPIAARequest, DPIAReport, DPIASection, RiskLevel
from services.auth import Scope, require_scope
from services.evidence_store import record_audit_evidence, log_audit_event

router = APIRouter(prefix="/api/dpia", tags=["DPIA"])


@router.post("/generate", response_model=DPIAReport)
@require_scope(Scope.audit_write)
async def generate_dpia(request: GenerateDPIAARequest, request_obj: Request):
    """
    Generate a comprehensive DPIA report.

    Evaluates:
      1. Necessity and proportionality (GDPR Art. 5(1)(c))
      2. Data category risk (GDPR Art. 9 — special categories)
      3. Cross-border transfer mechanisms (GDPR Art. 44–49)
      4. Mitigation measures

    Returns structured sections with per-section risk ratings
    and actionable mitigation recommendations.
    """
    sections = _build_dpia_sections(request)
    has_high_risk = any(s.risk == RiskLevel.high for s in sections)
    dpia_required = _is_dpia_required(request)

    cross_border_risk = RiskLevel.high
    adequacy = None
    if request.crossBorderTransfer and request.thirdCountries:
        adequacy = _evaluate_adequacy(request.thirdCountries)
        if adequacy == "ADEQUATE":
            cross_border_risk = RiskLevel.low
        elif adequacy == "SCCs":
            cross_border_risk = RiskLevel.medium

    # A DPIA is required if there's any high risk section
    compliant = not (has_high_risk and dpia_required)

    report = DPIAReport(
        modelId=request.modelId,
        dpiaRequired=dpia_required,
        dataController=request.dataController,
        dataProtectionOfficer=request.dpoName,
        sections=sections,
        crossBorderTransfer=request.crossBorderTransfer,
        adequacyDecision=adequacy,
        compliant=compliant,
    )

    # Persist to evidence store
    await record_audit_evidence(
        model_id=request.modelId,
        audit_phase="dpia_generation",
        payload=report.model_dump(),
    )

    # Log audit trail
    await log_audit_event(
        model_id=request.modelId,
        phase="dpia_generation",
        action="dpia_generated",
        outcome="success",
        details={"dpia_required": dpia_required, "compliant": compliant},
    )

    return report


def _is_dpia_required(request: GenerateDPIAARequest) -> bool:
    """Determine if a DPIA is legally required (GDPR Art. 35(1)–(4))."""
    high_risk_indicators = [
        "biometric" in [c.lower() for c in request.dataCategories],
        "health" in [c.lower() for c in request.dataCategories],
        "genetic" in [c.lower() for c in request.dataCategories],
        "location" in [c.lower() for c in request.dataCategories],
        request.crossBorderTransfer,
        any("vulnerable" in cat.lower() for cat in request.dataCategories),
    ]
    return any(high_risk_indicators)


def _build_dpia_sections(request: GenerateDPIAARequest) -> list[DPIASection]:
    """Build structured DPIA sections per GDPR Art. 35(7)."""
    return [
        DPIASection(
            section="1. Systematic Description of Processing",
            finding=f"Processing purpose: {request.processingPurpose}. "
                    f"Data categories: {', '.join(request.dataCategories)}. "
                    f"Data controller: {request.dataController}.",
            risk=RiskLevel.medium,
            mitigation="Maintain a record of processing activities per GDPR Art. 30.",
        ),
        DPIASection(
            section="2. Necessity and Proportionality Assessment",
            finding=f"Processing is {'necessary' if request.dataCategories else 'potentially excessive'} "
                    f"for the stated purpose. Review data minimization per GDPR Art. 5(1)(c).",
            risk=RiskLevel.medium if len(request.dataCategories) > 3 else RiskLevel.low,
            mitigation="Implement data minimization controls and retention schedules.",
        ),
        DPIASection(
            section="3. Risk Assessment to Rights and Freedoms",
            finding=f"Processing involves {len(request.dataCategories)} data categories. "
                    f"Risk of discrimination, profiling, or data breach.",
            risk=RiskLevel.high if "biometric" in request.dataCategories or "health" in request.dataCategories
            else RiskLevel.medium,
            mitigation="Implement pseudonymization, encryption, and access controls. "
                       "Conduct regular security testing.",
        ),
        DPIASection(
            section="4. Mitigation Measures",
            finding="Proposed mitigations: technical and organizational measures "
                    "including pseudonymization, encryption, access controls, "
                    "and regular audits.",
            risk=RiskLevel.low,
            mitigation="Document all technical and organizational measures (TOMs) "
                       "and review quarterly.",
        ),
        DPIASection(
            section="5. Cross-Border Data Transfer Assessment",
            finding=f"Cross-border transfer: {request.crossBorderTransfer}. "
                    f"Third countries: {', '.join(request.thirdCountries) if request.thirdCountries else 'N/A'}.",
            risk=RiskLevel.high if request.crossBorderTransfer else RiskLevel.low,
            mitigation="Implement SCCs or Binding Corporate Rules per GDPR Art. 46. "
                       "Verify adequacy decisions per Art. 45.",
        ),
    ]


def _evaluate_adequacy(third_countries: list[str]) -> str:
    """Evaluate cross-border adequacy decisions (GDPR Art. 45)."""
    adequate_countries = {
        "japan", "united kingdom", "canada", "switzerland",
        "new zealand", "south korea", "argentina", "uruguay",
        "israel", "united states",  # EU-US Data Privacy Framework
    }
    for country in third_countries:
        if country.lower() in adequate_countries:
            return "ADEQUATE"
    return "SCCs REQUIRED"
