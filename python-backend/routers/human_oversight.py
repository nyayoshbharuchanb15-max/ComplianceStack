"""
Human Oversight Verification Router — EU AI Act Art. 14
─────────────────────────────────────────────────────────
Verifies that high-risk AI systems have adequate human oversight
mechanisms, including human-in-the-loop (HITL) and kill-switch
controls.

EU AI Act Art. 14(1) — High-risk systems must allow natural persons
to override or interrupt system output.
EU AI Act Art. 14(3) — Oversight measures must be proportionate
to the risk and autonomy level.
GDPR Art. 22 — Automated individual decision-making requires
meaningful human intervention.
ISO/IEC 42001:2023 Clause 8.2 — Controls must be implemented
and verified.

BLOCKER FAIL: If no kill-switch is present for real-time or
autonomous deployment contexts, certification is halted immediately.
"""

from fastapi import APIRouter, HTTPException, Request
from models.schemas import (
    VerifyHumanOversightRequest,
    OversightCertificate,
    OversightLevel,
)
from services.auth import Scope, require_scope
from services.evidence_store import record_audit_evidence, log_audit_event

router = APIRouter(prefix="/api/human-oversight", tags=["Human Oversight"])


@router.post("/verify", response_model=OversightCertificate)
@require_scope(Scope.audit_write)
async def verify_human_oversight(request: VerifyHumanOversightRequest, request_obj: Request):
    """
    Verify human oversight mechanisms for an AI system.

    Evaluation criteria:
      1. Human-in-the-loop (HITL): Can a human review and override decisions?
      2. Kill-switch: Is there a mechanism to immediately halt the system?
      3. Deployment context: Real-time and autonomous systems require
         stricter oversight per EU AI Act Art. 14(3).

    Returns:
      - OversightCertificate with compliance status
      - `blocker: true` if oversight is insufficient (halts certification)
      - `remediation` with specific guidance on failures
    """
    blocker = False
    remediation_parts = []
    oversight_level = OversightLevel.full

    # ── Check 1: Human-in-the-Loop ───────────────────────────────
    if not request.hasHumanInTheLoop:
        oversight_level = OversightLevel.partial
        remediation_parts.append(
            "Implement human-in-the-loop (HITL) review process: "
            "all high-risk decisions must be reviewable by a qualified human operator "
            "before execution (EU AI Act Art. 14(3))."
        )

    # ── Check 2: Kill-Switch ─────────────────────────────────────
    if not request.hasKillSwitch:
        remediation_parts.append(
            "Deploy a physical or software-based kill-switch capable of "
            "immediately halting AI system output. This is MANDATORY for "
            "real-time and autonomous deployment contexts (EU AI Act Art. 14(1))."
        )

        # BLOCKER FAIL: No kill-switch for high-risk deployment contexts
        if request.deploymentContext in ("real_time", "autonomous"):
            blocker = True
            oversight_level = OversightLevel.none_
            remediation_parts.append(
                "❌ BLOCKER: Real-time/autonomous deployment without kill-switch "
                "violates EU AI Act Art. 14(1). Certification cannot proceed."
            )

    # ── Check 3: Process Documentation ───────────────────────────
    if not request.oversightProcess:
        remediation_parts.append(
            "Document the formal human oversight process including escalation "
            "paths, review frequency, and operator training requirements "
            "(ISO/IEC 42001:2023 Clause 8.2)."
        )

    compliant = not blocker and (
        request.hasHumanInTheLoop or request.deploymentContext == "assistive"
    )

    report = OversightCertificate(
        modelId=request.modelId,
        humanInTheLoop=request.hasHumanInTheLoop,
        killSwitchPresent=request.hasKillSwitch,
        oversightLevel=oversight_level,
        blocker=blocker,
        remediation="; ".join(remediation_parts) if remediation_parts else None,
        compliant=compliant,
    )

    # Persist to evidence store (ISO 42001 Clause 7.5)
    await record_audit_evidence(
        model_id=request.modelId,
        audit_phase="human_oversight_verification",
        payload=report.model_dump(),
    )

    # Log audit trail
    await log_audit_event(
        model_id=request.modelId,
        phase="human_oversight_verification",
        action="oversight_verified",
        outcome="success",
        details={"blocker": blocker, "compliant": compliant},
    )

    return report
