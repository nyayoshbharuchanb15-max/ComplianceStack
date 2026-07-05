# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Tests: Tool Permission Audit (Phase E) — Privilege Escalation Detection
"""

from __future__ import annotations
import pytest

from services.tool_permission_auditor import (
    audit_tool_permissions,
    _build_registry,
    _build_agent_tool_map,
    _detect_privilege_escalation,
    _detect_unauthorized_access,
    _detect_permission_drift,
    _check_log_completeness,
    _derive_risk,
)
from models.schemas import ToolPermissionIssue, RiskLevel


class TestBuildRegistry:
    def test_basic_registry(self):
        tools = [
            {"toolName": "read_file", "agents": ["a1"], "scopes": ["read"]},
            {"toolName": "write_file", "agents": ["a2"], "scopes": ["write"]},
        ]
        registry = _build_registry(tools)
        assert "read_file" in registry
        assert "write_file" in registry

    def test_empty_registry(self):
        assert _build_registry([]) == {}


class TestAgentToolMap:
    def test_basic_map(self):
        tools = [
            {"toolName": "read_file", "agents": ["a1", "a2"]},
            {"toolName": "write_file", "agents": ["a2"]},
        ]
        agent_tools = _build_agent_tool_map(tools)
        assert "read_file" in agent_tools["a1"]
        assert "write_file" in agent_tools["a2"]
        assert "read_file" in agent_tools["a2"]


class TestPrivilegeEscalation:
    def test_no_escalation(self):
        agent_tools = {"a1": ["read_file"]}
        logs = [{"agentId": "a1", "toolName": "read_file", "action": "read", "result": "ok", "timestamp": "t", "scope": "read"}]
        issues = _detect_privilege_escalation({}, logs, agent_tools)
        assert len(issues) == 0

    def test_escalation_detected(self):
        agent_tools = {"a1": ["read_file"]}
        logs = [{"agentId": "a1", "toolName": "admin_delete", "action": "delete", "result": "ok", "timestamp": "t", "scope": "admin"}]
        issues = _detect_privilege_escalation({}, logs, agent_tools)
        assert len(issues) == 1
        assert issues[0].issueType == "privilege_escalation"
        assert issues[0].severity == RiskLevel.critical


class TestUnauthorizedAccess:
    def test_no_unauthorized(self):
        agent_tools = {"a1": ["read_file"]}
        logs = [{"agentId": "a1", "toolName": "read_file", "action": "read", "result": "ok", "timestamp": "t", "scope": ""}]
        issues = _detect_unauthorized_access(agent_tools, logs)
        assert len(issues) == 0

    def test_unauthorized_detected(self):
        agent_tools = {"a1": ["read_file"]}
        logs = [{"agentId": "a1", "toolName": "write_file", "action": "write", "result": "ok", "timestamp": "t", "scope": ""}]
        issues = _detect_unauthorized_access(agent_tools, logs)
        assert len(issues) == 1
        assert issues[0].issueType == "unauthorized_access"


class TestPermissionDrift:
    def test_no_drift(self):
        tools = [{"toolName": "read_file", "agents": ["a1"], "lastAuditedPermissions": ["a1"]}]
        issues = _detect_permission_drift(tools)
        assert len(issues) == 0

    def test_drift_detected(self):
        tools = [{"toolName": "read_file", "agents": ["a1", "a2"], "lastAuditedPermissions": ["a1"]}]
        issues = _detect_permission_drift(tools)
        assert len(issues) == 1
        assert issues[0].issueType == "permission_drift"


class TestLogCompleteness:
    def test_complete_logs(self):
        logs = [{"agentId": "a1", "toolName": "read_file", "timestamp": "t"}]
        issues = _check_log_completeness(logs, logs)
        assert len(issues) == 0

    def test_incomplete_logs(self):
        logs = [{"agentId": "a1"}]
        issues = _check_log_completeness(logs, logs)
        assert len(issues) == 1


class TestDeriveRisk:
    def test_no_issues_low(self):
        assert _derive_risk([]) == RiskLevel.low

    def test_critical_issue(self):
        issues = [ToolPermissionIssue(toolName="t", issueType="privilege_escalation", severity=RiskLevel.critical, finding="", remediation="")]
        assert _derive_risk(issues) == RiskLevel.critical

    def test_multiple_medium(self):
        issues = [
            ToolPermissionIssue(toolName="t", issueType="drift", severity=RiskLevel.medium, finding="", remediation=""),
            ToolPermissionIssue(toolName="t2", issueType="drift", severity=RiskLevel.medium, finding="", remediation=""),
            ToolPermissionIssue(toolName="t3", issueType="drift", severity=RiskLevel.medium, finding="", remediation=""),
        ]
        assert _derive_risk(issues) == RiskLevel.medium


class TestAuditToolPermissions:
    @pytest.mark.asyncio
    async def test_clean_audit(self):
        registry = [
            {"toolName": "read_file", "agents": ["a1"], "scopes": ["read"]},
        ]
        logs = [
            {"agentId": "a1", "toolName": "read_file", "action": "read", "result": "ok", "timestamp": "t"},
        ]
        report = await audit_tool_permissions("test-model", registry, logs)
        assert report.modelId == "test-model"
        assert report.privilegeEscalationDetected is False
        assert report.unauthorizedAccessCount == 0

    @pytest.mark.asyncio
    async def test_escalation_detected(self):
        registry = [
            {"toolName": "read_file", "agents": ["a1"], "scopes": ["read"]},
        ]
        logs = [
            {"agentId": "a1", "toolName": "admin_delete", "action": "delete", "result": "ok", "timestamp": "t"},
        ]
        report = await audit_tool_permissions("test-model", registry, logs)
        assert report.privilegeEscalationDetected is True

    @pytest.mark.asyncio
    async def test_regulatory_mappings(self):
        report = await audit_tool_permissions("test-model", [], [])
        assert any("DPDP Act" in a for a in report.mappedArticles)
        assert "ISO/IEC 42001:2023" in report.iso42001Clause
