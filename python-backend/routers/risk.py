# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Risk Classification Router — EU AI Act Art. 6
───────────────────────────────────────────────
Classifies AI systems into risk tiers (Prohibited, High, Limited, Minimal)
based on the system's intended purpose, sector, and capabilities.

EU AI Act Art. 6(2) — High-risk classification criteria are defined
in Annex III of the Regulation.
NIST AI RMF MAP 1.1 — Risk mapping identifies potential harms.
ISO/IEC 42001:2023 Clause 6.1 — Risk assessment planning.
"""

from fastapi import APIRouter, Depends, HTTPException, Request
from models.schemas import ClassifyRiskRequest, RiskTierResult, RiskTier
from services.auth import Scope, require_scope
from services.evidence_store import record_audit_evidence, log_audit_event

router = APIRouter(prefix="/api/risk", tags=["Risk Classification"])

# ── High-risk categories per EU AI Act Annex III ──────────────────
HIGH_RISK_SECTORS = {
    "biometric": "Remote biometric identification systems (Annex III, Art. 6(2))",
    "critical_infrastructure": "Safety components of critical digital infrastructure (Annex III, Art. 6(2))",
    "educational": "Determining access or assigning grades in education (Annex III, Art. 6(2))",
    "employment": "Recruitment, promotion, and performance evaluation (Annex III, Art. 6(2))",
    "credit": "Creditworthiness assessment (Annex III, Art. 6(2))",
    "law_enforcement": "Law enforcement risk assessment (Annex III, Art. 6(2))",
}

PROHIBITED_PRACTICES = {
    "subliminal_manipulation": "Art. 5(1)(a): Subliminal techniques causing harm",
    "social_scoring": "Art. 5(1)(c): Social scoring by public authorities",
    "real_time_biometric": "Art. 5(1)(d): Real-time biometric surveillance in public spaces",
}


@router.post("/classify", response_model=RiskTierResult)
@require_scope(Scope.audit_write)
async def classify_ai_risk(request: ClassifyRiskRequest, request_obj: Request):
    """
    Classify an AI system into an EU AI Act risk tier.

    Evaluation logic (per EU AI Act Art. 6 and Annex III):
      1. Prohibited: Practices banned under Art. 5
      2. High-Risk: Systems in Annex III categories
      3. Limited: Systems with specific transparency obligations
      4. Minimal: All other systems

    Returns a RiskTierResult with plain-language rationale mapped
    to specific regulatory articles.
    """
    tier = _evaluate_risk_tier(request)
    rationale = _build_rationale(tier, request)
    compliant = tier != RiskTier.prohibited

    result = RiskTierResult(
        modelId=request.modelId,
        tier=tier,
        rationale=rationale,
        mappedArticles=_get_articles(tier),
        compliant=compliant,
    )

    # Persist to evidence store (ISO 42001 Clause 7.5)
    await record_audit_evidence(
        model_id=request.modelId,
        audit_phase="risk_classification",
        payload=result.model_dump(),
    )

    # Log audit trail mutation
    await log_audit_event(
        model_id=request.modelId,
        phase="risk_classification",
        action="risk_classified",
        outcome="success",
        details={"tier": tier.value, "compliant": compliant},
    )

    return result


def _evaluate_risk_tier(request: ClassifyRiskRequest) -> RiskTier:
    """Determine the risk tier based on regulatory criteria."""
    # Prohibited: Check for Art. 5 banned practices
    if request.modelType == "real_time_biometric":
        return RiskTier.prohibited

    # High-Risk: Check Annex III categories
    if request.sector in HIGH_RISK_SECTORS:
        return RiskTier.high

    # High-Risk: General-purpose AI with profiling capabilities
    if request.modelType == "general_purpose_ai" and request.usesProfiling:
        return RiskTier.high

    # Limited: Systems with specific transparency obligations
    if request.modelType == "general_purpose_ai":
        return RiskTier.limited

    # Minimal: Default for all other systems
    return RiskTier.minimal


def _build_rationale(tier: RiskTier, request: ClassifyRiskRequest) -> str:
    """Build a plain-language explanation of the risk classification."""
    if tier == RiskTier.prohibited:
        return (
            f"Model '{request.modelId}' is classified as PROHIBITED under EU AI Act Art. 5. "
            f"Sector '{request.sector}' with type '{request.modelType}' falls under "
            f"banned AI practices. Deployment is not permitted within the EU."
        )
    elif tier == RiskTier.high:
        sector_reason = HIGH_RISK_SECTORS.get(
            request.sector,
            "General-purpose AI with profiling capabilities"
        )
        return (
            f"Model '{request.modelId}' is classified as HIGH-RISK under EU AI Act Art. 6(2) "
            f"and Annex III. Reason: {sector_reason}. "
            f"Full Conformity assessment is required before deployment."
        )
    elif tier == RiskTier.limited:
        return (
            f"Model '{request.modelId}' is classified as LIMITED RISK under EU AI Act. "
            f"As a general-purpose AI system, transparency obligations under Art. 50 apply. "
            f"Users must be informed they are interacting with an AI system."
        )
    else:
        return (
            f"Model '{request.modelId}' is classified as MINIMAL RISK under EU AI Act. "
            f"No specific regulatory obligations apply beyond voluntary codes of conduct."
        )


def _get_articles(tier: RiskTier) -> list[str]:
    base = [
        "EU AI Act Art. 6 (Risk Classification)",
        "NIST AI RMF MAP 1.1 (Risk Mapping)",
        "ISO/IEC 42001:2023 Clause 6.1 (Risk Assessment)",
        "GDPR Art. 35 (Data Protection Impact Assessment)",
        "DPDP Act 2023 Sec. 7 (Duties of Data Fiduciary)",
    ]
    if tier == RiskTier.prohibited:
        base.insert(0, "EU AI Act Art. 5 (Prohibited Practices)")
    return base
