"""
Session Memory Audit Router — Short-Term / Long-Term Memory Isolation
──────────────────────────────────────────────────────────────────────
Verifies STM isolation, context window limits, session data wipe-on-expiry,
and cross-session data leakage prevention for AI agents.

GDPR Art. 5(1)(f) — Integrity and confidentiality of personal data.
GDPR Art. 25 — Data protection by design and by default.
DPDP Act 2023 Sec. 8 — Data processor duties.
EU AI Act Art. 15 — Accuracy and monitoring.
ISO/IEC 42001:2023 Clause 8.2 — Controls for AI system memory management.
"""

from __future__ import annotations
from fastapi import APIRouter, HTTPException, Request
from models.schemas import (
    AuditSessionMemoryRequest,
    SessionMemoryReport,
)
from services.auth import Scope, require_scope
from services.session_memory_auditor import audit_session_memory
from services.evidence_store import record_audit_evidence, log_audit_event

router = APIRouter(prefix="/api/session-memory", tags=["Session Memory Audit"])


@router.post("/audit", response_model=SessionMemoryReport)
@require_scope(Scope.audit_write)
async def audit_memory(request: AuditSessionMemoryRequest, request_obj: Request):
    """
    Audit short-term and long-term memory isolation for an AI agent session.

    Verifies:
      - STM isolation per user/session
      - Context window limits and truncation safety
      - Session buffer wipe on timeout/logout
      - LTM access control and embedding isolation
      - Vector DB row-level security
      - Session token binding
      - Data retention compliance
      - Audit trail for memory access
    """
    try:
        report = await audit_session_memory(
            model_id=request.modelId,
            session_id=request.sessionId,
            stm_config=request.stmConfig,
            ltm_config=request.ltmConfig,
            session_timeout_minutes=request.sessionTimeoutMinutes,
            isolation_level=request.isolationLevel,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Session memory audit failed: {str(e)}")

    await record_audit_evidence(
        model_id=request.modelId,
        audit_phase="session_memory_audit",
        payload=report.model_dump(),
    )

    # Log audit trail
    await log_audit_event(
        model_id=request.modelId,
        phase="session_memory_audit",
        action="session_memory_audited",
        outcome="success",
        details={"compliant": report.compliant},
    )

    return report
