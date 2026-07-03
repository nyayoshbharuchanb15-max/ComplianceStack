"""
Tool Permission Boundary Audit Router — Privilege Escalation Detection
──────────────────────────────────────────────────────────────────────
Audits tool permission boundaries: verifies agents only access authorized tools,
detects privilege escalation, unauthorized access, and permission drift.

DPDP Act 2023 Sec. 8 — Data processor duties.
EU AI Act Art. 14 — Human oversight for tool access.
GDPR Art. 25 — Data protection by design and by default.
ISO/IEC 42001:2023 Clause 7.4.3 — Supply chain permission controls.
NIST AI RMF GOVERN 1.2 — Tool access governance.
"""

from __future__ import annotations
from fastapi import APIRouter, HTTPException, Request
from models.schemas import (
    AuditToolPermissionsRequest,
    ToolPermissionReport,
)
from services.auth import Scope, require_scope
from services.tool_permission_auditor import audit_tool_permissions
from services.evidence_store import record_audit_evidence, log_audit_event

router = APIRouter(prefix="/api/tool-permissions", tags=["Tool Permission Audit"])


@router.post("/evaluate", response_model=ToolPermissionReport)
@require_scope(Scope.audit_write)
async def evaluate_permissions(request: AuditToolPermissionsRequest, request_obj: Request):
    """
    Evaluate tool permission boundaries:
      - Privilege escalation detection
      - Unauthorized access patterns
      - Permission drift from last audit
      - Scope violations
      - Least privilege compliance
      - Access log completeness
    """
    try:
        report = await audit_tool_permissions(
            model_id=request.modelId,
            tool_registry=request.toolRegistry,
            access_logs=request.accessLogs,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Tool permission audit failed: {str(e)}")

    await record_audit_evidence(
        model_id=request.modelId,
        audit_phase="tool_permission_audit",
        payload=report.model_dump(),
    )

    # Log audit trail
    await log_audit_event(
        model_id=request.modelId,
        phase="tool_permission_audit",
        action="tool_permissions_evaluated",
        outcome="success",
        details={"overall_risk": report.overallRisk.value},
    )

    return report
