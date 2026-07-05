# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Agent Trust Auditor — Multi-Agent Identity & Trust Verification
──────────────────────────────────────────────────────────────────
Evaluates agent identity verification, capability claims validation,
P2P message integrity, collusion detection, and cross-agent data leakage.

EU AI Act Art. 14 — Human oversight requirements.
EU AI Act Art. 11 — Technical documentation.
NIST AI RMF GOVERN 1.2 — Supply chain governance.
DPDP Act 2023 Sec. 8 — Processor duties.
ISO/IEC 42001:2023 Clause 7.4.3 — Supply chain trust.
"""

from __future__ import annotations
from typing import Any
from models.schemas import (
    AgentTrustRecord,
    AgentTrustReport,
    RiskLevel,
)


async def audit_agent_trust(
    model_id: str,
    agents: list[dict[str, Any]],
    message_bus_config: dict[str, Any] | None,
    p2p_enabled: bool,
) -> AgentTrustReport:
    """Run full agent trust audit across 7 checks."""
    records = [_evaluate_agent(a, p2p_enabled) for a in agents]
    bus_integrity = _check_message_bus_integrity(message_bus_config)
    leakage_risk = _compute_leakage_risk(records, p2p_enabled)
    collusion_risk = _detect_collusion(records, agents)

    failed_agents = [r for r in records if r.trustScore < 0.6 or len(r.issues) > 1]
    overall_risk = _derive_risk(failed_agents, leakage_risk, collusion_risk, bus_integrity)

    return AgentTrustReport(
        modelId=model_id,
        agents=records,
        overallRisk=overall_risk,
        crossAgentLeakageRisk=round(leakage_risk, 3),
        messageBusIntegrity=bus_integrity,
        collusionRisk=collusion_risk,
        compliant=overall_risk in (RiskLevel.low, RiskLevel.medium),
    )


def _evaluate_agent(agent: dict[str, Any], p2p_enabled: bool) -> AgentTrustRecord:
    """Evaluate a single agent's trust properties."""
    agent_id = agent.get("agentId", agent.get("agent_id", "unknown"))
    role = agent.get("role", "unknown")
    capabilities = agent.get("capabilities", [])
    tools = agent.get("tools", agent.get("authorizedTools", []))
    endpoints = agent.get("endpoints", [])
    has_identity = agent.get("hasIdentity", agent.get("has_identity", False))
    has_signature = agent.get("hasSignature", agent.get("has_signature", False))
    has_encryption = agent.get("hasEncryption", agent.get("has_encryption", False))

    issues = []

    # 1. Identity Verification
    identity_verified = bool(has_identity and has_signature)

    # 2. Capability Claims vs Actual
    capability_valid = _validate_capabilities(capabilities, tools)
    if not capability_valid:
        issues.append("Agent claims capabilities it does not have tools for.")

    # 3. Message Integrity
    message_integrity = bool(has_signature and has_encryption)

    # Trust score computation
    score_parts = [
        0.3 if identity_verified else 0.0,
        0.25 if capability_valid else 0.0,
        0.2 if message_integrity else 0.0,
        0.15 if len(endpoints) > 0 else 0.0,
        0.1 if not p2p_enabled or has_encryption else 0.0,
    ]
    trust_score = round(sum(score_parts), 2)

    if not identity_verified:
        issues.append("Agent identity is not verified (missing identity or signature).")
    if not message_integrity:
        issues.append("Agent messages lack cryptographic integrity (no signature/encryption).")
    if p2p_enabled and not has_encryption:
        issues.append("P2P communication enabled but agent lacks encryption.")

    return AgentTrustRecord(
        agentId=agent_id,
        role=role,
        identityVerified=identity_verified,
        capabilityClaimsValid=capability_valid,
        messageIntegritySupported=message_integrity,
        trustScore=trust_score,
        issues=issues,
    )


def _validate_capabilities(capabilities: list, tools: list) -> bool:
    """Check if agent's claimed capabilities match its authorized tools."""
    if not capabilities:
        return True
    if not tools:
        return False
    tool_names = {str(t).lower() for t in tools}
    for cap in capabilities:
        cap_lower = str(cap).lower()
        if not any(cap_lower in t or t in cap_lower for t in tool_names):
            return False
    return True


def _check_message_bus_integrity(config: dict[str, Any] | None) -> bool:
    """Check if message bus has integrity controls."""
    if not config:
        return False
    has_hmac = config.get("hmac", config.get("hmacEnabled", False))
    has_signing = config.get("signing", config.get("messageSigning", False))
    has_auth = config.get("authentication", config.get("authEnabled", False))
    return bool(has_hmac or has_signing or has_auth)


def _compute_leakage_risk(records: list[AgentTrustRecord], p2p_enabled: bool) -> float:
    """Compute cross-agent data leakage risk (0.0–1.0)."""
    if not records:
        return 0.0
    unverified = sum(1 for r in records if not r.identityVerified)
    no_integrity = sum(1 for r in records if not r.messageIntegritySupported)
    base = (unverified + no_integrity) / max(len(records) * 2, 1)
    if p2p_enabled:
        base = min(base + 0.15, 1.0)
    return round(base, 3)


def _detect_collusion(records: list[AgentTrustRecord], agents: list[dict[str, Any]]) -> RiskLevel:
    """Detect potential collusion between agents."""
    if len(records) < 2:
        return RiskLevel.low
    unverified_count = sum(1 for r in records if not r.identityVerified)
    no_integrity_count = sum(1 for r in records if not r.messageIntegritySupported)
    if unverified_count >= 2 or no_integrity_count >= 2:
        return RiskLevel.high
    if unverified_count == 1 or no_integrity_count == 1:
        return RiskLevel.medium
    return RiskLevel.low


def _derive_risk(
    failed_agents: list[AgentTrustRecord],
    leakage_risk: float,
    collusion_risk: RiskLevel,
    bus_integrity: bool,
) -> RiskLevel:
    """Derive overall risk from individual findings."""
    if collusion_risk == RiskLevel.high or leakage_risk > 0.6:
        return RiskLevel.critical
    if len(failed_agents) > 0 or leakage_risk > 0.3 or not bus_integrity:
        return RiskLevel.high
    if collusion_risk == RiskLevel.medium or leakage_risk > 0.1:
        return RiskLevel.medium
    return RiskLevel.low
