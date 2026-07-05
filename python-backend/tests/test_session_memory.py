# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Nyayosh Bharuchanb15-Max

"""
Tests: Session Memory Audit (Phase A) — STM/LTM Isolation
"""

from __future__ import annotations
import pytest

from services.session_memory_auditor import (
    audit_session_memory,
    _compute_isolation_score,
    _derive_risk,
)
from models.schemas import SessionMemorySection, RiskLevel


class TestIsolationScore:
    def test_empty_sections_returns_zero(self):
        assert _compute_isolation_score([]) == 0.0

    def test_all_compliant_high_score(self):
        sections = [
            SessionMemorySection(section="Session Isolation", requirement="", status="compliant", finding="", remediation=""),
            SessionMemorySection(section="Embedding Isolation", requirement="", status="compliant", finding="", remediation=""),
            SessionMemorySection(section="Vector DB Row-Level Security", requirement="", status="compliant", finding="", remediation=""),
        ]
        score = _compute_isolation_score(sections)
        assert score >= 0.9

    def test_non_compliant_low_score(self):
        sections = [
            SessionMemorySection(section="Session Isolation", requirement="", status="non_compliant", finding="", remediation=""),
            SessionMemorySection(section="Embedding Isolation", requirement="", status="non_compliant", finding="", remediation=""),
            SessionMemorySection(section="Vector DB Row-Level Security", requirement="", status="non_compliant", finding="", remediation=""),
        ]
        score = _compute_isolation_score(sections)
        assert score == 0.0

    def test_partial_compliance_mixed_score(self):
        sections = [
            SessionMemorySection(section="Session Isolation", requirement="", status="compliant", finding="", remediation=""),
            SessionMemorySection(section="Embedding Isolation", requirement="", status="non_compliant", finding="", remediation=""),
        ]
        score = _compute_isolation_score(sections)
        assert 0.0 < score < 1.0


class TestDeriveRisk:
    def test_high_ratio_high_isolation_is_low(self):
        assert _derive_risk(0.9, 0.9) == RiskLevel.low

    def test_medium_ratio_medium_isolation_is_medium(self):
        assert _derive_risk(0.6, 0.6) == RiskLevel.medium

    def test_low_ratio_low_isolation_is_critical(self):
        assert _derive_risk(0.2, 0.2) == RiskLevel.critical

    def test_mixed_is_high(self):
        assert _derive_risk(0.3, 0.5) == RiskLevel.high


class TestAuditSessionMemory:
    @pytest.mark.asyncio
    async def test_per_user_isolation_compliant(self):
        report = await audit_session_memory(
            model_id="test-model",
            session_id="sess-001",
            stm_config={
                "maxTokens": 4096,
                "maxHistory": 100,
                "wipeOnExpiry": True,
                "embeddingIsolation": True,
                "rowLevelSecurity": True,
                "tokenBinding": True,
                "retentionDays": 30,
                "auditTrail": True,
            },
            ltm_config={"accessControl": "tenant_id"},
            session_timeout_minutes=30,
            isolation_level="per_user",
        )
        assert report.modelId == "test-model"
        assert report.sessionId == "sess-001"
        assert report.wipeOnExpiryVerified is True
        assert report.contextIsolationScore >= 0.8
        assert len(report.sections) == 10

    @pytest.mark.asyncio
    async def test_shared_isolation_non_compliant(self):
        report = await audit_session_memory(
            model_id="test-model",
            session_id="sess-002",
            stm_config={},
            ltm_config=None,
            session_timeout_minutes=30,
            isolation_level="shared",
        )
        assert report.overallRisk in (RiskLevel.high, RiskLevel.critical)
        isolated_section = next(s for s in report.sections if s.section == "Session Isolation")
        assert isolated_section.status == "non_compliant"

    @pytest.mark.asyncio
    async def test_regulatory_mappings_present(self):
        report = await audit_session_memory(
            model_id="test-model",
            session_id="sess-003",
            stm_config={"maxTokens": 2048},
            ltm_config=None,
            session_timeout_minutes=15,
            isolation_level="per_session",
        )
        assert "GDPR Art. 5(1)(f)" in report.mappedArticles[0]
        assert "ISO/IEC 42001:2023" in report.iso42001Clause

    @pytest.mark.asyncio
    async def test_empty_config_detects_gaps(self):
        report = await audit_session_memory(
            model_id="test-model",
            session_id="sess-004",
            stm_config={},
            ltm_config=None,
            session_timeout_minutes=30,
            isolation_level="per_user",
        )
        non_compliant = [s for s in report.sections if s.status == "non_compliant"]
        assert len(non_compliant) >= 3
