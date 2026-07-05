# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Tests: Agent Trust Audit (Phase D) — Identity & Trust Verification
"""

from __future__ import annotations
import pytest

from services.agent_trust_auditor import (
    audit_agent_trust,
    _evaluate_agent,
    _check_message_bus_integrity,
    _compute_leakage_risk,
    _detect_collusion,
)
from models.schemas import AgentTrustRecord, RiskLevel


class TestEvaluateAgent:
    def test_verified_agent(self):
        agent = {
            "agentId": "agent-1",
            "role": "analyst",
            "capabilities": ["read_data"],
            "tools": ["read_data"],
            "endpoints": ["http://localhost:8001"],
            "hasIdentity": True,
            "hasSignature": True,
            "hasEncryption": True,
        }
        record = _evaluate_agent(agent, p2p_enabled=False)
        assert record.identityVerified is True
        assert record.trustScore >= 0.8
        assert len(record.issues) == 0

    def test_unverified_agent(self):
        agent = {
            "agentId": "agent-2",
            "role": "unknown",
            "capabilities": [],
            "tools": [],
            "endpoints": [],
            "hasIdentity": False,
            "hasSignature": False,
            "hasEncryption": False,
        }
        record = _evaluate_agent(agent, p2p_enabled=False)
        assert record.identityVerified is False
        assert record.trustScore < 0.5

    def test_capability_mismatch(self):
        agent = {
            "agentId": "agent-3",
            "role": "writer",
            "capabilities": ["execute_code", "read_data"],
            "tools": ["read_data"],
            "endpoints": [],
            "hasIdentity": True,
            "hasSignature": True,
            "hasEncryption": False,
        }
        record = _evaluate_agent(agent, p2p_enabled=False)
        assert record.capabilityClaimsValid is False
        assert any("capabilities" in i.lower() for i in record.issues)

    def test_p2p_without_encryption(self):
        agent = {
            "agentId": "agent-4",
            "role": "worker",
            "capabilities": [],
            "tools": [],
            "endpoints": [],
            "hasIdentity": True,
            "hasSignature": True,
            "hasEncryption": False,
        }
        record = _evaluate_agent(agent, p2p_enabled=True)
        assert any("P2P" in i or "encryption" in i for i in record.issues)


class TestMessageBusIntegrity:
    def test_no_config(self):
        assert _check_message_bus_integrity(None) is False

    def test_with_hmac(self):
        assert _check_message_bus_integrity({"hmac": True}) is True

    def test_with_signing(self):
        assert _check_message_bus_integrity({"messageSigning": True}) is True

    def test_with_auth(self):
        assert _check_message_bus_integrity({"authentication": True}) is True

    def test_empty_config(self):
        assert _check_message_bus_integrity({}) is False


class TestLeakageRisk:
    def test_no_agents(self):
        assert _compute_leakage_risk([], False) == 0.0

    def test_all_verified(self):
        records = [
            AgentTrustRecord(agentId="a", role="r", identityVerified=True, capabilityClaimsValid=True, messageIntegritySupported=True, trustScore=0.9, issues=[]),
        ]
        assert _compute_leakage_risk(records, False) == 0.0

    def test_unverified_increases_risk(self):
        records = [
            AgentTrustRecord(agentId="a", role="r", identityVerified=False, capabilityClaimsValid=True, messageIntegritySupported=False, trustScore=0.3, issues=[]),
        ]
        assert _compute_leakage_risk(records, False) > 0.0

    def test_p2p_increases_risk(self):
        records = [
            AgentTrustRecord(agentId="a", role="r", identityVerified=True, capabilityClaimsValid=True, messageIntegritySupported=False, trustScore=0.6, issues=[]),
        ]
        assert _compute_leakage_risk(records, True) > _compute_leakage_risk(records, False)


class TestCollusionDetection:
    def test_single_agent_no_collusion(self):
        records = [
            AgentTrustRecord(agentId="a", role="r", identityVerified=True, capabilityClaimsValid=True, messageIntegritySupported=True, trustScore=0.9, issues=[]),
        ]
        assert _detect_collusion(records, []) == RiskLevel.low

    def test_multiple_unverified_high_risk(self):
        records = [
            AgentTrustRecord(agentId="a", role="r", identityVerified=False, capabilityClaimsValid=True, messageIntegritySupported=False, trustScore=0.2, issues=[]),
            AgentTrustRecord(agentId="b", role="r", identityVerified=False, capabilityClaimsValid=True, messageIntegritySupported=False, trustScore=0.2, issues=[]),
        ]
        assert _detect_collusion(records, []) == RiskLevel.high


class TestAuditAgentTrust:
    @pytest.mark.asyncio
    async def test_basic_audit(self):
        agents = [
            {"agentId": "a1", "role": "analyst", "hasIdentity": True, "hasSignature": True, "hasEncryption": True, "capabilities": ["read"], "tools": ["read"], "endpoints": ["http://x"]},
            {"agentId": "a2", "role": "writer", "hasIdentity": True, "hasSignature": True, "hasEncryption": False, "capabilities": ["write"], "tools": ["write"], "endpoints": ["http://y"]},
        ]
        report = await audit_agent_trust(
            model_id="test-model",
            agents=agents,
            message_bus_config={"hmac": True},
            p2p_enabled=False,
        )
        assert report.modelId == "test-model"
        assert len(report.agents) == 2
        assert report.collusionRisk in (RiskLevel.low, RiskLevel.medium)

    @pytest.mark.asyncio
    async def test_regulatory_mappings(self):
        report = await audit_agent_trust(
            model_id="test-model",
            agents=[],
            message_bus_config=None,
            p2p_enabled=False,
        )
        assert any("EU AI Act" in a for a in report.mappedArticles)
        assert "ISO/IEC 42001:2023" in report.iso42001Clause
