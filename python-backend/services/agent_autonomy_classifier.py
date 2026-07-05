# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Agent Autonomy Classifier — Risk Tier Mapping
──────────────────────────────────────────────────────────
Classifies AI agent autonomy level and maps to EU AI Act risk tiers.
Determines required human oversight controls based on agent capabilities.

EU AI Act Art. 6 — Risk tiering.
EU AI Act Art. 14 — Human oversight requirements.
NIST AI RMF GOVERN 3.2 — Oversight governance.
ISO/IEC 42001:2023 Clause 6.1 — Risk assessment.
"""

from __future__ import annotations
from models.schemas import (
    AutonomyLevel,
    AgentAutonomyResult,
    RiskTier,
)


# Autonomy classification matrix:
# (canMakeDecisions, canModifyEnv, canDelegate, canSelfModify, hasOversight) → level
CLASSIFICATION_MATRIX = {
    (False, False, False, False, False): AutonomyLevel.assistive,
    (False, False, False, False, True):  AutonomyLevel.assistive,
    (True,  False, False, False, True):  AutonomyLevel.supervised,
    (True,  True,  False, False, True):  AutonomyLevel.supervised,
    (True,  True,  True,  False, True):  AutonomyLevel.autonomous,
    (True,  True,  True,  False, False): AutonomyLevel.fully_autonomous,
    (True,  True,  True,  True,  True):  AutonomyLevel.fully_autonomous,
    (True,  True,  True,  True,  False): AutonomyLevel.fully_autonomous,
    (True,  False, True,  False, True):  AutonomyLevel.autonomous,
    (True,  False, True,  False, False): AutonomyLevel.fully_autonomous,
    (True,  False, False, False, False): AutonomyLevel.autonomous,
    (True,  True,  False, False, False): AutonomyLevel.autonomous,
    (False, True,  False, False, True):  AutonomyLevel.supervised,
    (False, True,  True,  False, True):  AutonomyLevel.autonomous,
    (False, True,  True,  False, False): AutonomyLevel.fully_autonomous,
}

# Controls required by autonomy level
CONTROLS_BY_LEVEL = {
    AutonomyLevel.assistive: [
        "No special controls required for assistive agents.",
        "Recommend logging of all suggestions for audit trail.",
    ],
    AutonomyLevel.supervised: [
        "Human review required before action execution.",
        "Implement approval workflow for high-impact decisions.",
        "Log all agent actions for post-hoc review.",
    ],
    AutonomyLevel.autonomous: [
        "Real-time monitoring dashboard required.",
        "Kill-switch must be accessible within 2 clicks.",
        "Automated alerts for anomalous behavior patterns.",
        "Weekly human review of agent decision logs.",
        "Implement rate limiting on tool access.",
    ],
    AutonomyLevel.fully_autonomous: [
        "BLOCKER: Fully autonomous agents require explicit regulatory approval.",
        "Implement comprehensive kill-switch with <1s response time.",
        "All decisions must be logged with full reasoning chain.",
        "Deploy anomaly detection with automatic shutdown.",
        "Require human-in-the-loop for any action affecting natural persons.",
        "Conduct quarterly adversarial testing.",
    ],
}


async def classify_autonomy(
    model_id: str,
    agent_type: str,
    has_human_oversight: bool,
    can_make_decisions: bool,
    can_modify_environment: bool,
    can_delegate_tasks: bool,
    can_access_external_apis: bool,
    can_self_modify: bool,
    deployment_context: str,
) -> AgentAutonomyResult:
    """Classify agent autonomy and map to risk tier."""
    key = (can_make_decisions, can_modify_environment, can_delegate_tasks, can_self_modify, has_human_oversight)
    autonomy_level = CLASSIFICATION_MATRIX.get(key, _fallback_classify(key))

    risk_tier = _map_to_risk_tier(autonomy_level, agent_type, deployment_context)
    rationale = _build_rationale(autonomy_level, can_make_decisions, can_modify_environment, can_delegate_tasks, can_self_modify, has_human_oversight)
    controls = CONTROLS_BY_LEVEL.get(autonomy_level, [])
    human_oversight_required = autonomy_level in (AutonomyLevel.supervised, AutonomyLevel.autonomous, AutonomyLevel.fully_autonomous)

    return AgentAutonomyResult(
        modelId=model_id,
        autonomyLevel=autonomy_level,
        agentType=agent_type,
        riskTier=risk_tier,
        rationale=rationale,
        humanOversightRequired=human_oversight_required,
        recommendedControls=controls,
        compliant=autonomy_level != AutonomyLevel.fully_autonomous,
    )


def _fallback_classify(key: tuple[bool, ...]) -> AutonomyLevel:
    """Fallback classification for unrecognized combinations."""
    can_decide, can_modify, can_delegate, can_self, has_oversight = key
    if can_self:
        return AutonomyLevel.fully_autonomous
    if not has_oversight and (can_decide or can_modify):
        return AutonomyLevel.autonomous
    if can_decide:
        return AutonomyLevel.supervised
    return AutonomyLevel.assistive


def _map_to_risk_tier(level: AutonomyLevel, agent_type: str, deployment_context: str) -> RiskTier:
    """Map autonomy level to EU AI Act risk tier."""
    if level == AutonomyLevel.fully_autonomous:
        return RiskTier.high
    if level == AutonomyLevel.autonomous:
        if agent_type in ("multi_agent", "hierarchical", "swarm"):
            return RiskTier.high
        return RiskTier.limited
    if level == AutonomyLevel.supervised:
        return RiskTier.limited
    return RiskTier.minimal


def _build_rationale(
    level: AutonomyLevel,
    can_decide: bool,
    can_modify: bool,
    can_delegate: bool,
    can_self: bool,
    has_oversight: bool,
) -> str:
    """Build human-readable rationale for classification."""
    parts = []
    if can_decide:
        parts.append("agent can make decisions")
    if can_modify:
        parts.append("agent can modify environment")
    if can_delegate:
        parts.append("agent can delegate tasks to other agents")
    if can_self:
        parts.append("agent can modify its own configuration")
    if has_oversight:
        parts.append("human oversight is present")
    else:
        parts.append("no human oversight")

    capability_desc = "; ".join(parts) if parts else "no significant capabilities"
    return f"Classified as {level.value}: {capability_desc}."
