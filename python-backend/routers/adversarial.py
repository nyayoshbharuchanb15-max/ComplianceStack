# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Adversarial Testing Router — Real Model API Robustness Verification
────────────────────────────────────────────────────────────────────
Executes adversarial robustness test suites against a target LLM via
configurable OpenAI-compatible API endpoints (vLLM, Ollama, OpenAI).

Each test suite sends real HarmBench-inspired prompts to the target
model and scores responses using an LLM-as-judge evaluator.

EU AI Act Art. 15 — High-risk systems must achieve appropriate
levels of accuracy, robustness, and cybersecurity.
ISO/IEC 42001:2023 Clause 8.1.3 — Security and robustness controls.
"""

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from models.schemas import (
    RunAdversarialTestsRequest,
    AdversarialReport,
    AdversarialTestResult,
    RiskLevel,
)
from services.auth import Scope, require_scope
from services.evidence_store import record_audit_evidence, log_audit_event
from services.adversarial_tester import create_tester

router = APIRouter(prefix="/api/adversarial", tags=["Adversarial Testing"])


@router.post("/run", response_model=AdversarialReport)
@require_scope(Scope.audit_write)
async def run_adversarial_tests(request: RunAdversarialTestsRequest, request_obj: Request):
    """
    Execute selected adversarial test suites against the target model.

    Connects to a configurable OpenAI-compatible model endpoint and runs
    real adversarial prompts. Each prompt is scored using an LLM-as-judge
    evaluator that determines whether the response violates safety guidelines.

    Test suites:
      - prompt_injection:     Prompts designed to override system instructions
      - jailbreak:            Known jailbreak techniques (DAN, roleplay, etc.)
      - ood_detection:        Embedding-similarity OOD via sentence-transformers
      - model_inversion:      Training-data extraction attempts
      - membership_inference: Canary-based membership inference attacks

    Configuration (in order of precedence: request body > env var):
      - endpoint_url:  Base URL of an OpenAI-compatible API (env: ADV_ENDPOINT_URL)
      - api_key:       API key (env: ADV_API_KEY)
      - target_model:  Model to test (env: ADV_TARGET_MODEL)
      - judge_model:   Model used for LLM-as-judge scoring (env: ADV_JUDGE_MODEL)
      - embedding_model: Sentence-transformers model for OOD (env: ADV_EMBEDDING_MODEL)
    """
    try:
        tester = create_tester(
            endpoint_url=request.endpoint_url or "",
            api_key=request.api_key or "",
            target_model=request.target_model or "",
            judge_model=request.judge_model or "",
            embedding_model=request.embedding_model or "",
        )

        suite_names = request.testSuites
        results = await tester.run_all(suite_names)

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Adversarial testing failed: {str(e)}",
        )

    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    threshold_level = severity_order.get(request.severityThreshold, 1)

    overall_risk = RiskLevel.low
    for r in results:
        if not r.passed and severity_order.get(r.severity.value, 0) > severity_order.get(overall_risk.value, 0):
            overall_risk = r.severity

    high_or_critical_failures = [
        r for r in results
        if not r.passed and severity_order.get(r.severity.value, 0) >= threshold_level
    ]
    compliant = len(high_or_critical_failures) == 0

    report = AdversarialReport(
        modelId=request.modelId,
        tests=results,
        overallRisk=overall_risk,
        compliant=compliant,
    )

    await record_audit_evidence(
        model_id=request.modelId,
        audit_phase="adversarial_testing",
        payload=report.model_dump(),
    )

    # Log audit trail
    await log_audit_event(
        model_id=request.modelId,
        phase="adversarial_testing",
        action="adversarial_tests_run",
        outcome="success",
        details={"overall_risk": overall_risk.value, "compliant": compliant},
    )

    return report
