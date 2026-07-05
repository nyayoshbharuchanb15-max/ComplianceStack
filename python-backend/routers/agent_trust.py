# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Agent Trust & Identity Audit Router — Multi-Agent Trust Verification
──────────────────────────────────────────────────────────────────────
Audits agent identity verification, capability claims validation,
P2P message integrity, collusion detection, and cross-agent data leakage.

EU AI Act Art. 14 — Human oversight for high-risk AI systems.
EU AI Act Art. 11 — Technical documentation requirements.
NIST AI RMF GOVERN 1.2 — Supply chain and multi-agent governance.
DPDP Act 2023 Sec. 8 — Data processor duties.
ISO/IEC 42001:2023 Clause 7.4.3 — Supply chain trust controls.
"""

from fastapi import APIRouter, HTTPException, Request
from models.schemas import (
    AuditAgentTrustRequest,
    AgentTrustReport,
)
from services.auth import Scope, require_scope
from services.agent_trust_auditor import audit_agent_trust
from services.evidence_store import record_audit_evidence, log_audit_event

router = APIRouter(prefix="/api/agent-trust", tags=["Agent Trust Audit"])


@router.post("/evaluate", response_model=AgentTrustReport)
@require_scope(Scope.audit_write)
async def evaluate_trust(request: AuditAgentTrustRequest, request_obj: Request):
    """
    Evaluate multi-agent trust:
      - Agent identity verification
      - Capability claims vs actual tools
      - Message integrity on pub/sub bus
      - P2P channel security
      - Cross-agent data leakage risk
      - Collusion detection
      - Agent registry completeness
    """
    try:
        report = await audit_agent_trust(
            model_id=request.modelId,
            agents=request.agents,
            message_bus_config=request.messageBusConfig,
            p2p_enabled=request.p2pEnabled,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Agent trust audit failed: {str(e)}")

    await record_audit_evidence(
        model_id=request.modelId,
        audit_phase="agent_trust_audit",
        payload=report.model_dump(),
    )

    # Log audit trail
    await log_audit_event(
        model_id=request.modelId,
        phase="agent_trust_audit",
        action="agent_trust_evaluated",
        outcome="success",
        details={"overall_risk": report.overallRisk.value},
    )

    return report
