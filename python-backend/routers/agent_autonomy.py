"""
Agent Autonomy Classification Router — Risk Tier Mapping
──────────────────────────────────────────────────────────────────────
Classifies AI agent autonomy level (assistive/supervised/autonomous/fully_autonomous)
and maps to EU AI Act risk tiers. Determines required human oversight controls.

EU AI Act Art. 6 — Risk tiering based on autonomy level.
EU AI Act Art. 14 — Human oversight requirements by autonomy.
NIST AI RMF GOVERN 3.2 — Oversight governance.
ISO/IEC 42001:2023 Clause 6.1 — Risk assessment for autonomous agents.
"""

from __future__ import annotations
from fastapi import APIRouter, HTTPException, Request
from models.schemas import (
    ClassifyAgentAutonomyRequest,
    AgentAutonomyResult,
)
from services.auth import Scope, require_scope
from services.agent_autonomy_classifier import classify_autonomy
from services.evidence_store import record_audit_evidence, log_audit_event

router = APIRouter(prefix="/api/agent-autonomy", tags=["Agent Autonomy Classification"])


@router.post("/classify", response_model=AgentAutonomyResult)
@require_scope(Scope.audit_write)
async def classify_level(request: ClassifyAgentAutonomyRequest, request_obj: Request):
    """
    Classify agent autonomy level based on capabilities:
      - assistive: agent suggests, human decides
      - supervised: agent acts, human reviews
      - autonomous: agent acts, human monitors
      - fully_autonomous: agent acts without human oversight (BLOCKER)
    """
    try:
        result = await classify_autonomy(
            model_id=request.modelId,
            agent_type=request.agentType,
            has_human_oversight=request.hasHumanOversight,
            can_make_decisions=request.canMakeDecisions,
            can_modify_environment=request.canModifyEnvironment,
            can_delegate_tasks=request.canDelegateTasks,
            can_access_external_apis=request.canAccessExternalAPIs,
            can_self_modify=request.canSelfModify,
            deployment_context=request.deploymentContext,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Autonomy classification failed: {str(e)}")

    await record_audit_evidence(
        model_id=request.modelId,
        audit_phase="agent_autonomy_classification",
        payload=result.model_dump(),
    )

    # Log audit trail
    await log_audit_event(
        model_id=request.modelId,
        phase="agent_autonomy_classification",
        action="autonomy_classified",
        outcome="success",
        details={"autonomy_level": result.autonomyLevel.value},
    )

    return result
