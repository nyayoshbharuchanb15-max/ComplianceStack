# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
RAG Quality Audit Router — Retrieval-Augmented Generation Evaluation
──────────────────────────────────────────────────────────────────────
Evaluates RAG pipeline quality: retrieval accuracy, embedding bias,
knowledge freshness, and hallucination rate.

EU AI Act Art. 15 — High-risk AI systems must achieve appropriate accuracy.
NIST AI RMF MEASURE 3.3 — Continuous monitoring for operational changes.
ISO/IEC 42001:2023 Clause 9.1 — Performance evaluation of AI systems.
EU AI Act Art. 10 — Data quality and governance for training data.
"""

from fastapi import APIRouter, HTTPException, Request
from models.schemas import (
    AuditRAGQualityRequest,
    RAGQualityReport,
)
from services.auth import Scope, require_scope
from services.rag_quality_auditor import evaluate_rag_quality
from services.evidence_store import record_audit_evidence, log_audit_event

router = APIRouter(prefix="/api/rag-quality", tags=["RAG Quality Audit"])


@router.post("/evaluate", response_model=RAGQualityReport)
@require_scope(Scope.audit_write)
async def evaluate_quality(request: AuditRAGQualityRequest, request_obj: Request):
    """
    Evaluate RAG pipeline quality across 7 metrics:
      - Retrieval Precision
      - Retrieval Recall
      - Embedding Bias
      - Knowledge Freshness
      - Hallucination Rate
      - Source Attribution Accuracy
      - Query-Answer Relevance
    """
    try:
        report = await evaluate_rag_quality(
            model_id=request.modelId,
            vector_db_config=request.vectorDbConfig,
            sample_queries=request.sampleQueries,
            freshness_policy_days=request.freshnessPolicyDays,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"RAG quality evaluation failed: {str(e)}")

    await record_audit_evidence(
        model_id=request.modelId,
        audit_phase="rag_quality_audit",
        payload=report.model_dump(),
    )

    # Log audit trail
    await log_audit_event(
        model_id=request.modelId,
        phase="rag_quality_audit",
        action="rag_quality_evaluated",
        outcome="success",
        details={"overall_risk": report.overallRisk.value},
    )

    return report
