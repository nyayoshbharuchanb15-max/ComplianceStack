# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Prompt Template Audit Router — Injection Surface & Fairness Analysis
──────────────────────────────────────────────────────────────────────
Audits prompt engineering templates for injection surface area,
few-shot bias, instruction safety, and transparency compliance.

EU AI Act Art. 10 — Data quality for training and prompt data.
EU AI Act Art. 13 — Transparency obligations for AI systems.
NIST AI RMF GOVERN 1.2 — Supply chain and prompt engineering governance.
ISO/IEC 42001:2023 Clause 8.1.3 — Adversarial resilience of prompts.
"""

from fastapi import APIRouter, HTTPException, Request
from models.schemas import (
    AuditPromptTemplatesRequest,
    PromptAuditReport,
)
from services.auth import Scope, require_scope
from services.prompt_template_auditor import audit_prompt_templates
from services.evidence_store import record_audit_evidence, log_audit_event

router = APIRouter(prefix="/api/prompt-audit", tags=["Prompt Template Audit"])


@router.post("/evaluate", response_model=PromptAuditReport)
@require_scope(Scope.audit_write)
async def evaluate_prompts(request: AuditPromptTemplatesRequest, request_obj: Request):
    """
    Audit prompt templates for:
      - Injection surface area
      - Few-shot representation and label bias
      - Instruction safety
      - Tone/persona consistency
      - Output constraint adequacy
      - Transparency markers
      - Role boundary clarity
    """
    try:
        report = await audit_prompt_templates(
            model_id=request.modelId,
            prompt_templates=request.promptTemplates,
            few_shot_examples=request.fewShotExamples,
            system_prompt=request.systemPrompt,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prompt audit failed: {str(e)}")

    await record_audit_evidence(
        model_id=request.modelId,
        audit_phase="prompt_template_audit",
        payload=report.model_dump(),
    )

    # Log audit trail
    await log_audit_event(
        model_id=request.modelId,
        phase="prompt_template_audit",
        action="prompt_templates_audited",
        outcome="success",
        details={"overall_risk": report.overallRisk.value},
    )

    return report
