# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Tool Permission Auditor — Privilege Escalation Detection
──────────────────────────────────────────────────────────
Evaluates tool permission boundaries: verifies agents only access
authorized tools, detects privilege escalation, unauthorized access,
and permission drift from last audit state.

DPDP Act 2023 Sec. 8 — Processor duties.
EU AI Act Art. 14 — Human oversight for tool access.
GDPR Art. 25 — Data protection by design.
ISO/IEC 42001:2023 Clause 7.4.3 — Supply chain controls.
NIST AI RMF GOVERN 1.2 — Tool access governance.
"""

from __future__ import annotations
from typing import Any
from models.schemas import (
    ToolPermissionIssue,
    ToolPermissionReport,
    RiskLevel,
)


async def audit_tool_permissions(
    model_id: str,
    tool_registry: list[dict[str, Any]],
    access_logs: list[dict[str, Any]],
) -> ToolPermissionReport:
    """Run full tool permission boundary audit across 6 checks."""
    issues: list[ToolPermissionIssue] = []

    # Build lookup structures
    registry_map = _build_registry(tool_registry)
    agent_tools = _build_agent_tool_map(tool_registry)
    log_entries = _normalize_logs(access_logs)

    # 1. Privilege Escalation
    escalation_issues = _detect_privilege_escalation(registry_map, log_entries, agent_tools)
    issues.extend(escalation_issues)

    # 2. Unauthorized Access
    unauthorized_issues = _detect_unauthorized_access(agent_tools, log_entries)
    issues.extend(unauthorized_issues)

    # 3. Permission Drift
    drift_issues = _detect_permission_drift(tool_registry)
    issues.extend(drift_issues)

    # 4. Scope Violations
    scope_issues = _detect_scope_violations(registry_map, log_entries)
    issues.extend(scope_issues)

    # 5. Least Privilege Compliance
    privilege_issues = _check_least_privilege(tool_registry, agent_tools)
    issues.extend(privilege_issues)

    # 6. Access Log Completeness
    log_issues = _check_log_completeness(access_logs, log_entries)
    issues.extend(log_issues)

    # Compute aggregates
    privilege_escalation = any(i.issueType == "privilege_escalation" for i in issues)
    unauthorized_count = sum(1 for i in issues if i.issueType == "unauthorized_access")
    drift_count = sum(1 for i in issues if i.issueType == "permission_drift")
    least_priv = not any(i.issueType == "scope_violation" for i in issues)

    overall_risk = _derive_risk(issues)

    return ToolPermissionReport(
        modelId=model_id,
        issues=issues,
        overallRisk=overall_risk,
        privilegeEscalationDetected=privilege_escalation,
        unauthorizedAccessCount=unauthorized_count,
        permissionDriftCount=drift_count,
        principleOfLeastPrivilege=least_priv,
        compliant=overall_risk in (RiskLevel.low, RiskLevel.medium),
    )


def _build_registry(tool_registry: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Build tool name -> config lookup."""
    registry = {}
    for tool in tool_registry:
        name = tool.get("toolName", tool.get("tool_name", ""))
        if name:
            registry[name] = tool
    return registry


def _build_agent_tool_map(tool_registry: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Build agent_id -> list of authorized tool names."""
    agent_tools: dict[str, list[str]] = {}
    for tool in tool_registry:
        tool_name = tool.get("toolName", tool.get("tool_name", ""))
        agents = tool.get("agents", [])
        for agent_id in agents:
            agent_tools.setdefault(agent_id, []).append(tool_name)
    return agent_tools


def _normalize_logs(access_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize access log entries."""
    normalized = []
    for log in access_logs:
        normalized.append({
            "agentId": log.get("agentId", log.get("agent_id", "")),
            "toolName": log.get("toolName", log.get("tool_name", "")),
            "action": log.get("action", ""),
            "result": log.get("result", ""),
            "timestamp": log.get("timestamp", ""),
            "scope": log.get("scope", log.get("scopeUsed", "")),
        })
    return normalized


def _detect_privilege_escalation(
    registry: dict[str, dict[str, Any]],
    logs: list[dict[str, Any]],
    agent_tools: dict[str, list[str]],
) -> list[ToolPermissionIssue]:
    """Detect agents accessing tools beyond their assigned permissions."""
    issues = []
    for log in logs:
        agent_id = log["agentId"]
        tool_name = log["toolName"]
        if not agent_id or not tool_name:
            continue
        authorized = agent_tools.get(agent_id, [])
        if authorized and tool_name not in authorized:
            issues.append(ToolPermissionIssue(
                toolName=tool_name,
                issueType="privilege_escalation",
                severity=RiskLevel.critical,
                finding=f"Agent '{agent_id}' accessed tool '{tool_name}' which is not in its authorized tool list.",
                remediation=f"Remove '{tool_name}' from agent '{agent_id}' access or update authorization.",
            ))
    return issues


def _detect_unauthorized_access(
    agent_tools: dict[str, list[str]],
    logs: list[dict[str, Any]],
) -> list[ToolPermissionIssue]:
    """Detect tools called by agents not in their authorized list."""
    issues = []
    seen = set()
    for log in logs:
        agent_id = log["agentId"]
        tool_name = log["toolName"]
        key = f"{agent_id}:{tool_name}"
        if key in seen:
            continue
        seen.add(key)
        authorized = agent_tools.get(agent_id, [])
        if authorized and tool_name not in authorized:
            issues.append(ToolPermissionIssue(
                toolName=tool_name,
                issueType="unauthorized_access",
                severity=RiskLevel.high,
                finding=f"Agent '{agent_id}' accessed unauthorized tool '{tool_name}'.",
                remediation=f"Revoke access to '{tool_name}' for agent '{agent_id}'.",
            ))
    return issues


def _detect_permission_drift(tool_registry: list[dict[str, Any]]) -> list[ToolPermissionIssue]:
    """Detect permission drift from last audited state."""
    issues = []
    for tool in tool_registry:
        tool_name = tool.get("toolName", tool.get("tool_name", ""))
        last_audited = tool.get("lastAuditedPermissions", tool.get("last_audited_permissions"))
        current_agents = set(tool.get("agents", []))
        if last_audited is not None:
            previous_agents = set(last_audited) if isinstance(last_audited, list) else set()
            added = current_agents - previous_agents
            removed = previous_agents - current_agents
            if added or removed:
                drift_detail = []
                if added:
                    drift_detail.append(f"added agents: {added}")
                if removed:
                    drift_detail.append(f"removed agents: {removed}")
                issues.append(ToolPermissionIssue(
                    toolName=tool_name,
                    issueType="permission_drift",
                    severity=RiskLevel.medium,
                    finding=f"Permission drift detected for tool '{tool_name}': {'; '.join(drift_detail)}.",
                    remediation=f"Review and re-audit permissions for tool '{tool_name}'.",
                ))
    return issues


def _detect_scope_violations(
    registry: dict[str, dict[str, Any]],
    logs: list[dict[str, Any]],
) -> list[ToolPermissionIssue]:
    """Detect tools invoked with broader scope than declared."""
    issues = []
    for log in logs:
        tool_name = log["toolName"]
        scope_used = log.get("scope", "")
        tool_config = registry.get(tool_name, {})
        allowed_scopes = tool_config.get("scopes", tool_config.get("permissions", []))
        if allowed_scopes and scope_used and scope_used not in allowed_scopes:
            issues.append(ToolPermissionIssue(
                toolName=tool_name,
                issueType="scope_violation",
                severity=RiskLevel.high,
                finding=f"Tool '{tool_name}' invoked with scope '{scope_used}' which exceeds declared scope {allowed_scopes}.",
                remediation=f"Restrict scope for tool '{tool_name}' to declared permissions.",
            ))
    return issues


def _check_least_privilege(
    tool_registry: list[dict[str, Any]],
    agent_tools: dict[str, list[str]],
) -> list[ToolPermissionIssue]:
    """Check if agents have more permissions than needed for their role."""
    issues = []
    for tool in tool_registry:
        tool_name = tool.get("toolName", tool.get("tool_name", ""))
        agents = tool.get("agents", [])
        required_role = tool.get("requiredRole", tool.get("required_role", ""))
        if len(agents) > 5 and required_role:
            issues.append(ToolPermissionIssue(
                toolName=tool_name,
                issueType="scope_violation",
                severity=RiskLevel.medium,
                finding=f"Tool '{tool_name}' is accessible to {len(agents)} agents — violates least privilege principle.",
                remediation=f"Reduce agent access for '{tool_name}' to only those requiring '{required_role}' role.",
            ))
    return issues


def _check_log_completeness(
    raw_logs: list[dict[str, Any]],
    normalized_logs: list[dict[str, Any]],
) -> list[ToolPermissionIssue]:
    """Check for missing or incomplete access log entries."""
    issues = []
    missing_fields = 0
    for log in raw_logs:
        if not log.get("agentId") and not log.get("agent_id"):
            missing_fields += 1
        if not log.get("toolName") and not log.get("tool_name"):
            missing_fields += 1
        if not log.get("timestamp"):
            missing_fields += 1
    if missing_fields > 0:
        issues.append(ToolPermissionIssue(
            toolName="__access_logs__",
            issueType="log_incomplete",
            severity=RiskLevel.medium,
            finding=f"{missing_fields} access log entries are missing required fields (agentId, toolName, timestamp).",
            remediation="Ensure all access log entries include agentId, toolName, action, and timestamp.",
        ))
    return issues


def _derive_risk(issues: list[ToolPermissionIssue]) -> RiskLevel:
    """Derive overall risk from issues."""
    if not issues:
        return RiskLevel.low
    severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    max_severity = max(severity_order.get(i.severity.value, 0) for i in issues)
    if max_severity >= 3:
        return RiskLevel.critical
    if max_severity >= 2:
        return RiskLevel.high
    if len(issues) >= 3:
        return RiskLevel.medium
    return RiskLevel.medium if issues else RiskLevel.low
