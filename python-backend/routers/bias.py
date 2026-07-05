# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Bias Assessment Router — Multidimensional Fairness Scan
─────────────────────────────────────────────────────────
Executes the Bias Engine (Fairlearn + AIF360) for comprehensive
fairness evaluation across protected attributes.

EU AI Act Art. 10 — Data governance: training data must be examined
for biases that could lead to discriminatory outcomes.
GDPR Art. 9 — Processing of special category data requires
additional safeguards against discrimination.
GDPR Art. 35 — DPIA must include bias assessment for high-risk
processing.
ISO/IEC 42001:2023 Clause 8.1.2 — Bias and fairness controls.
"""

from fastapi import APIRouter, HTTPException, Request
from models.schemas import RunBiasAssessmentRequest, BiasReport
from services.auth import Scope, require_scope
from services.bias_engine import run_bias_assessment
from services.evidence_store import record_audit_evidence, log_audit_event

router = APIRouter(prefix="/api/bias", tags=["Bias Assessment"])


@router.post("/assess", response_model=BiasReport)
@require_scope(Scope.audit_write)
async def assess_bias(request: RunBiasAssessmentRequest, request_obj: Request):
    """
    Run a multidimensional bias assessment across protected attributes.

    Evaluates:
      1. Demographic Parity Difference
      2. Equal Opportunity Difference
      3. Disparate Impact Ratio (80% rule)

    Each metric is compared against a configurable threshold and
    reported with pass/fail status and plain-language explanation.
    """
    try:
        report = await run_bias_assessment(
            model_id=request.modelId,
            dataset_sample=request.datasetSample,
            sensitive_features=request.sensitiveFeatures,
            fairness_threshold=request.fairnessThreshold,
        )

        # Persist to evidence store
        await record_audit_evidence(
            model_id=request.modelId,
            audit_phase="bias_assessment",
            payload=report.model_dump(),
        )

        # Log audit trail
        await log_audit_event(
            model_id=request.modelId,
            phase="bias_assessment",
            action="bias_assessed",
            outcome="success",
            details={"bias_risk": report.overallBiasRisk.value},
        )

        return report

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Bias assessment failed: {str(e)}")
